"""
BrainWiz Relay Server

A lightweight WebSocket-based tunnel relay. AI clients connect via HTTPS;
the relay forwards traffic to user apps over persistent WebSocket tunnels.

Routes:
  POST /register                              — App registers, gets a token
  POST /admin/tokens                          — Add tokens to whitelist (private mode only)
  DELETE /admin/tokens                        — Remove tokens from whitelist (private mode only)
  GET  /admin/stats                           — Per-token request stats (private mode only)
  WS   /tunnel/{token}                        — App opens WebSocket tunnel
  GET  /.well-known/oauth-authorization-server — OAuth 2.1 metadata
  GET  /.well-known/oauth-protected-resource   — Resource metadata
  GET  /authorize                             — OAuth approval page
  POST /authorize                             — Process approval, redirect with code
  POST /token                                 — Exchange code for bearer token
  *    /{token}/mcp[/...]                     — AI clients hit MCP via relay

Modes:
  Public (default): any well-formed token is accepted on /register.
  Private: set TOKENS_FILE=/path/to/tokens.txt and ADMIN_SECRET=<secret>.
           Only tokens listed in the file are accepted. New tokens can be
           added at runtime via POST /admin/tokens without a restart.

The relay is stateless (in-memory token→tunnel map). It holds no user data.
Deploy on Fly.io or any platform that terminates TLS upstream.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Union
from urllib.parse import parse_qs, urlparse

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect
import uvicorn

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("relay")

AUTH_CODE_TTL = 300       # 5 minutes

# Pending slots are either a Future (regular request) or Queue (SSE stream)
Pending = Union[asyncio.Future, asyncio.Queue]


@dataclass
class Tunnel:
    token: str
    ws: WebSocket | None = None
    pending: dict[str, Pending] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


tunnels: dict[str, Tunnel] = {}

# Short-lived auth codes: code → {token, code_challenge, redirect_uri, state, expires_at}
auth_codes: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Private mode — token whitelist
# ---------------------------------------------------------------------------

_TOKENS_FILE = os.getenv("TOKENS_FILE", "")
_ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")
_valid_tokens: set[str] | None = None  # None = public mode


def _load_whitelist() -> None:
    global _valid_tokens
    if not _TOKENS_FILE:
        return  # public mode
    _valid_tokens = set()
    try:
        with open(_TOKENS_FILE) as f:
            for line in f:
                t = line.strip()
                if t:
                    _valid_tokens.add(t)
        log.info(f"Private mode: {len(_valid_tokens)} tokens loaded from {_TOKENS_FILE}")
    except FileNotFoundError:
        log.info(f"Private mode: {_TOKENS_FILE} not found, starting with empty whitelist")


_load_whitelist()

# ---------------------------------------------------------------------------
# Per-token stats and rate limiting
# ---------------------------------------------------------------------------

RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "30"))
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(1024 * 1024)))  # 1MB default
STATS_TOP_N = int(os.getenv("STATS_TOP_N", "100"))

# token → {"requests": int, "last_seen": float, "issued_at": float, "total_bytes": int}
_token_stats: dict[str, dict] = {}

# Token bucket rate limiter — O(1) memory per token regardless of request rate.
# Each entry is [allowance: float, last_refill: float].
# Refill rate: RATE_LIMIT_RPM tokens per 60s. Bucket capacity = RATE_LIMIT_RPM.
_rate_buckets: dict[str, list[float]] = {}


def _record_request(token: str, body_bytes: int = 0) -> None:
    now = time.time()
    stats = _token_stats.setdefault(token, {"requests": 0, "last_seen": 0.0, "issued_at": now, "total_bytes": 0})
    stats["requests"] += 1
    stats["last_seen"] = now
    stats["total_bytes"] += body_bytes


def _check_rate_limit(token: str) -> bool:
    """Return True if the request is allowed, False if rate limit exceeded."""
    now = time.time()
    if token not in _rate_buckets:
        _rate_buckets[token] = [float(RATE_LIMIT_RPM), now]
    bucket = _rate_buckets[token]
    elapsed = now - bucket[1]
    bucket[1] = now
    bucket[0] = min(RATE_LIMIT_RPM, bucket[0] + elapsed * (RATE_LIMIT_RPM / 60.0))
    if bucket[0] < 1.0:
        return False
    bucket[0] -= 1.0
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _relay_base(request: Request) -> str:
    """Return the relay's public base URL, respecting X-Forwarded-Proto."""
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return str(request.base_url).rstrip("/").replace(
        f"{request.url.scheme}://", f"{proto}://", 1
    )


def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return computed == challenge


def _token_from_resource(resource: str) -> str | None:
    """Extract tunnel token from a resource URL like https://relay.../TOKEN/mcp."""
    path = urlparse(resource).path          # e.g. /TOKEN/mcp
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else None


def _check_bearer(request: Request, token: str) -> bool:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth[7:] == token and token in tunnels


def _unauthorized(request: Request, token: str = "") -> JSONResponse:
    base = _relay_base(request)
    # Include the token in the resource_metadata URL so the OAuth client
    # discovers per-token resource metadata (resource = {base}/{token}/mcp),
    # which it then passes back to /authorize as the resource parameter.
    metadata_url = (
        f"{base}/{token}/.well-known/oauth-protected-resource"
        if token else
        f"{base}/.well-known/oauth-protected-resource"
    )
    return JSONResponse(
        {"error": "unauthorized"},
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Bearer realm="BrainWiz",'
                f' resource_metadata="{metadata_url}"'
            )
        },
    )


def _purge_expired_codes() -> None:
    now = time.time()
    expired = [c for c, v in auth_codes.items() if v["expires_at"] < now]
    for c in expired:
        del auth_codes[c]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

async def register(request: Request) -> JSONResponse:
    body = await request.json()
    token = body.get("token")

    # Private mode: validate token against whitelist before doing anything else.
    if _valid_tokens is not None:
        if not token or token not in _valid_tokens:
            return JSONResponse({"error": "Invalid or missing license key"}, status_code=403)
        if token not in tunnels:
            tunnels[token] = Tunnel(token=token)
            log.info(f"New tunnel registered (private): {token[:8]}...")
        else:
            tunnels[token].last_seen = time.time()
            log.info(f"Re-registered tunnel (private): {token[:8]}...")
        base = _relay_base(request)
        return JSONResponse({"token": token, "mcp_url": f"{base}/{token}/mcp"})

    # Public mode: accept any well-formed token or generate a new one.
    if token and len(token) >= 16:
        # Accept any well-formed token, even after a relay restart.
        # Tokens have 192 bits of entropy — guessing one is not feasible.
        if token not in tunnels:
            tunnels[token] = Tunnel(token=token)
            log.info(f"Reclaimed token after restart: {token[:8]}...")
        else:
            tunnels[token].last_seen = time.time()
            log.info(f"Re-registered tunnel: {token[:8]}...")
    else:
        token = secrets.token_urlsafe(24)
        tunnels[token] = Tunnel(token=token)
        log.info(f"New tunnel registered: {token[:8]}...")

    base = _relay_base(request)
    return JSONResponse({
        "token": token,
        "mcp_url": f"{base}/{token}/mcp",
    })


async def admin_add_tokens(request: Request) -> JSONResponse:
    if _valid_tokens is None:
        return JSONResponse({"error": "Not in private mode"}, status_code=404)
    auth = request.headers.get("authorization", "")
    if not _ADMIN_SECRET or auth != f"Bearer {_ADMIN_SECRET}":
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    new_tokens = body.get("tokens", [])
    if not isinstance(new_tokens, list):
        return JSONResponse({"error": "tokens must be a list"}, status_code=400)
    added = []
    now = time.time()
    for t in new_tokens:
        t = str(t).strip()
        if t and t not in _valid_tokens:
            _valid_tokens.add(t)
            _token_stats.setdefault(t, {"requests": 0, "last_seen": 0.0, "issued_at": now, "total_bytes": 0})
            added.append(t)
    if added and _TOKENS_FILE:
        os.makedirs(os.path.dirname(_TOKENS_FILE) or ".", exist_ok=True)
        with open(_TOKENS_FILE, "a") as f:
            for t in added:
                f.write(t + "\n")
    log.info(f"Admin: added {len(added)} tokens ({len(_valid_tokens)} total)")
    return JSONResponse({"added": len(added), "total": len(_valid_tokens)})


async def admin_remove_tokens(request: Request) -> JSONResponse:
    if _valid_tokens is None:
        return JSONResponse({"error": "Not in private mode"}, status_code=404)
    auth = request.headers.get("authorization", "")
    if not _ADMIN_SECRET or auth != f"Bearer {_ADMIN_SECRET}":
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    remove = body.get("tokens", [])
    if not isinstance(remove, list):
        return JSONResponse({"error": "tokens must be a list"}, status_code=400)
    removed = [t for t in (str(t).strip() for t in remove) if t and t in _valid_tokens]
    for t in removed:
        _valid_tokens.discard(t)
        tunnels.pop(t, None)
        _token_stats.pop(t, None)
        _rate_buckets.pop(t, None)
    if removed and _TOKENS_FILE:
        try:
            with open(_TOKENS_FILE) as f:
                lines = f.readlines()
            with open(_TOKENS_FILE, "w") as f:
                for line in lines:
                    if line.strip() not in removed:
                        f.write(line)
        except FileNotFoundError:
            pass
    log.info(f"Admin: removed {len(removed)} tokens ({len(_valid_tokens)} total)")
    return JSONResponse({"removed": len(removed), "total": len(_valid_tokens)})


async def admin_stats(request: Request) -> JSONResponse:
    if _valid_tokens is None:
        return JSONResponse({"error": "Not in private mode"}, status_code=404)
    auth = request.headers.get("authorization", "")
    if not _ADMIN_SECRET or auth != f"Bearer {_ADMIN_SECRET}":
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    now = time.time()
    rows = []
    for token in _valid_tokens:
        stats = _token_stats.get(token, {})
        requests = stats.get("requests", 0)
        total_bytes = stats.get("total_bytes", 0)
        issued_at = stats.get("issued_at") or now
        days_active = max((now - issued_at) / 86400.0, 1 / 1440.0)
        rows.append({
            "token": token,
            "connected": token in tunnels and tunnels[token].ws is not None,
            "requests": requests,
            "requests_per_day": round(requests / days_active, 2),
            "avg_bytes_per_request": round(total_bytes / requests, 1) if requests else 0,
            "last_seen": stats.get("last_seen") or None,
            "issued_at": issued_at,
        })
    return JSONResponse({
        "total_tokens": len(_valid_tokens),
        "active_tunnels": sum(1 for t in tunnels.values() if t.ws is not None),
        "top_by_requests_per_day": sorted(rows, key=lambda r: r["requests_per_day"], reverse=True)[:STATS_TOP_N],
        "top_by_avg_bytes": sorted(rows, key=lambda r: r["avg_bytes_per_request"], reverse=True)[:STATS_TOP_N],
    })


# ---------------------------------------------------------------------------
# WebSocket tunnel endpoint
# ---------------------------------------------------------------------------

async def tunnel_endpoint(ws: WebSocket) -> None:
    token = ws.path_params["token"]
    if token not in tunnels:
        await ws.close(code=4001, reason="Unknown token")
        return

    await ws.accept()
    tunnel = tunnels[token]
    tunnel.ws = ws
    tunnel.last_seen = time.time()
    log.info(f"Tunnel connected: {token[:8]}...")

    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            req_id = msg.get("id")
            if req_id and req_id in tunnel.pending:
                slot = tunnel.pending[req_id]
                if isinstance(slot, asyncio.Queue):
                    # SSE stream: enqueue each event chunk
                    await slot.put(msg)
                elif not slot.done():
                    slot.set_result(msg)
    except WebSocketDisconnect:
        log.info(f"Tunnel disconnected: {token[:8]}...")
    finally:
        # Only clear tunnel.ws if this connection is still the active one.
        # A newer connection may have already replaced it.
        if tunnel.ws is ws:
            tunnel.ws = None
            for slot in list(tunnel.pending.values()):
                if isinstance(slot, asyncio.Queue):
                    await slot.put({"type": "sse_end"})
                elif not slot.done():
                    slot.set_exception(ConnectionError("Tunnel disconnected"))
            tunnel.pending.clear()


# ---------------------------------------------------------------------------
# OAuth 2.1 (PKCE) — discovery, authorization, token exchange
# ---------------------------------------------------------------------------

async def oauth_server_metadata(request: Request) -> JSONResponse:
    base = _relay_base(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register/client",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


async def oauth_protected_resource(request: Request) -> JSONResponse:
    base = _relay_base(request)
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
    })


async def oauth_protected_resource_token(request: Request) -> JSONResponse:
    """Per-token resource metadata — resource identifies the specific MCP URL.

    Points authorization_servers at the per-token issuer ({base}/{token}) so
    clients follow RFC 8414 path-based discovery to /{token}/authorize instead
    of falling back to the root /authorize (which doesn't know the token).
    """
    base = _relay_base(request)
    token = request.path_params["token"]
    return JSONResponse({
        "resource": f"{base}/{token}/mcp",
        "authorization_servers": [f"{base}/{token}"],
        "bearer_methods_supported": ["header"],
    })


_APPROVE_PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect to BrainWiz</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f0f0f; color: #e5e5e5;
          display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
  .card {{ background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
           padding: 2rem 2.5rem; max-width: 420px; width: 100%; text-align: center; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 0.5rem; color: #fff; }}
  p  {{ color: #999; font-size: 0.9rem; margin: 0 0 1.5rem; line-height: 1.5; }}
  .token {{ background: #111; border: 1px solid #333; border-radius: 6px;
            padding: 0.4rem 0.8rem; font-family: monospace; font-size: 0.85rem;
            color: #7dd3fc; margin-bottom: 1.5rem; display: inline-block; }}
  button {{ background: #2563eb; color: #fff; border: none; border-radius: 8px;
            padding: 0.7rem 2rem; font-size: 1rem; cursor: pointer; width: 100%; }}
  button:hover {{ background: #1d4ed8; }}
  .error {{ color: #f87171; }}
</style>
</head>
<body>
<div class="card">
  <h1>Connect to BrainWiz</h1>
  <p>Claude Desktop wants to access your personal BrainWiz memory.<br>
     Approving lets it capture, search, and browse your stored thoughts.</p>
  <div class="token">{token_display}</div>
  <form method="POST" action="{form_action}">
    <input type="hidden" name="token" value="{token}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="state" value="{state}">
    <button type="submit">Approve</button>
  </form>
</div>
</body>
</html>
"""

_ERROR_PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BrainWiz — Error</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f0f0f; color: #e5e5e5;
          display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
  .card {{ background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
           padding: 2rem 2.5rem; max-width: 420px; width: 100%; text-align: center; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 1rem; color: #f87171; }}
  p  {{ color: #999; font-size: 0.9rem; margin: 0; line-height: 1.5; }}
</style>
</head>
<body>
<div class="card">
  <h1>{title}</h1>
  <p>{message}</p>
</div>
</body>
</html>
"""


async def client_registration(request: Request) -> JSONResponse:
    """RFC 7591 dynamic client registration — required by Claude Desktop."""
    # We don't track clients; client_id is not validated at the token endpoint.
    # This endpoint exists solely to satisfy Claude Desktop's discovery requirement.
    try:
        body = await request.json()
    except Exception:
        body = {}
    log.info(f"Client registration request: {json.dumps(body)}")

    redirect_uris = body.get("redirect_uris", [])
    client_id = secrets.token_urlsafe(16)
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", ""),
        "scope": body.get("scope", ""),
    }, status_code=201)


async def client_registration_token(request: Request) -> JSONResponse:
    """Per-token client registration — returns a client_id that encodes the token.

    Because this endpoint URL differs from the root /register/client, clients
    that properly use per-token discovery will register here fresh and receive
    a token-encoded client_id. The authorize endpoint decodes the token from it.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    token = request.path_params["token"]
    log.info(f"Per-token client registration for tunnel: {token[:8]}...")
    redirect_uris = body.get("redirect_uris", [])
    client_id = f"bwz.{token}"
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", ""),
        "scope": body.get("scope", ""),
    }, status_code=201)


async def authorize_get(request: Request) -> HTMLResponse:
    """Show the OAuth approval page."""
    params = dict(request.query_params)
    log.info(f"GET /authorize params: {json.dumps(params)}")
    redirect_uri    = params.get("redirect_uri", "")
    code_challenge  = params.get("code_challenge", "")
    state           = params.get("state", "")
    resource        = params.get("resource", "")

    # Extract token from the resource URL (e.g. https://relay.../TOKEN/mcp)
    token = _token_from_resource(resource) if resource else None

    if not token:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="Missing Token",
                message=(
                    "Could not identify your BrainWiz instance. "
                    "Make sure you copied the full URL from the BrainWiz app."
                ),
            ),
            status_code=400,
        )

    if token not in tunnels:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="Unknown Instance",
                message="This BrainWiz token is not registered with the relay. "
                        "Start the BrainWiz app and try again.",
            ),
            status_code=404,
        )

    tunnel = tunnels[token]
    if not tunnel.ws:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="BrainWiz is Offline",
                message="Your BrainWiz app is not currently connected to the relay. "
                        "Make sure the app is running, then try again.",
            ),
            status_code=503,
        )

    token_display = token[:8] + "…"
    return HTMLResponse(
        _APPROVE_PAGE.format(
            token=token,
            token_display=token_display,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            state=state,
            form_action="/authorize",
        )
    )


async def authorize_post(request: Request) -> RedirectResponse:
    """Process approval: generate auth code and redirect back to client."""
    _purge_expired_codes()
    form = await request.form()
    token          = str(form.get("token", ""))
    redirect_uri   = str(form.get("redirect_uri", ""))
    code_challenge = str(form.get("code_challenge", ""))
    state          = str(form.get("state", ""))

    if not token or token not in tunnels:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="Invalid Token",
                message="The BrainWiz token is no longer valid. Please try again.",
            ),
            status_code=400,
        )

    code = secrets.token_urlsafe(16)
    auth_codes[code] = {
        "token": token,
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + AUTH_CODE_TTL,
    }
    log.info(f"Auth code issued for tunnel: {token[:8]}...")

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}&state={state}"
    return RedirectResponse(location, status_code=302)


async def token_exchange(request: Request) -> JSONResponse:
    """Exchange an auth code + PKCE verifier for a bearer token."""
    _purge_expired_codes()

    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await request.form()
        params = {k: str(v) for k, v in form.items()}
    else:
        # Fallback: parse raw body as url-encoded
        body = (await request.body()).decode()
        params = {k: v[0] for k, v in parse_qs(body).items()}

    grant_type    = params.get("grant_type", "")
    code          = params.get("code", "")
    code_verifier = params.get("code_verifier", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    entry = auth_codes.pop(code, None)
    if not entry:
        return JSONResponse({"error": "invalid_grant", "error_description": "Unknown or expired code"}, status_code=400)

    if entry["expires_at"] < time.time():
        return JSONResponse({"error": "invalid_grant", "error_description": "Code expired"}, status_code=400)

    if not _verify_pkce(code_verifier, entry["code_challenge"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    token = entry["token"]
    log.info(f"Bearer token issued for tunnel: {token[:8]}...")
    return JSONResponse({
        "access_token": token,
        "token_type": "bearer",
        "scope": "mcp",
    })


# ---------------------------------------------------------------------------
# Per-token OAuth endpoints (for clients that do path-based discovery)
# ---------------------------------------------------------------------------

async def oauth_server_metadata_token(request: Request) -> JSONResponse:
    """Per-token OAuth authorization server metadata.

    Points authorization_endpoint at /{token}/authorize so clients that do
    path-based discovery (RFC 8414 §3) learn the token without needing a
    resource parameter in the /authorize request.

    Handles multiple discovery URL patterns that different clients try:
      /.well-known/oauth-authorization-server/{token}
      /.well-known/oauth-authorization-server/{token}/mcp   (Codex appends full path)
      /{token}/mcp/.well-known/oauth-authorization-server   (Codex also tries this)
      /{token}/.well-known/oauth-authorization-server
    """
    base = _relay_base(request)
    # Compute the issuer as the URL with the .well-known segment removed.
    # RFC 8414 requires the returned issuer to exactly match the issuer URL
    # that was used to construct the discovery URL — clients validate this.
    #
    # Patterns handled:
    #   /.well-known/oauth-authorization-server/{token}/mcp  → issuer = {base}/{token}/mcp
    #   /{token}/mcp/.well-known/oauth-authorization-server  → issuer = {base}/{token}/mcp
    #   /{token}/.well-known/oauth-authorization-server      → issuer = {base}/{token}
    path = request.url.path
    wk = "/.well-known/oauth-authorization-server"
    if path.startswith(wk):
        issuer_path = path[len(wk):]          # e.g. "/{token}/mcp"
    elif wk in path:
        issuer_path = path[:path.index(wk)]   # e.g. "/{token}/mcp"
    else:
        issuer_path = ""
    issuer_path = issuer_path.rstrip("/")
    issuer = f"{base}{issuer_path}" if issuer_path else base

    # Extract the tunnel token (first path component of issuer_path)
    token = next((p for p in issuer_path.split("/") if p), "")
    return JSONResponse({
        "issuer": issuer,
        # Use the token-specific authorize endpoint so Codex (which caches by
        # authorization_endpoint) treats this as a new server and re-registers
        # via /register/client/{token}, giving it a token-encoded client_id.
        "authorization_endpoint": f"{base}/{token}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register/client/{token}",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


async def authorize_token_get(request: Request) -> HTMLResponse:
    """Show OAuth approval page — token is already known from the URL path."""
    token = request.path_params["token"]
    params = dict(request.query_params)
    redirect_uri   = params.get("redirect_uri", "")
    code_challenge = params.get("code_challenge", "")
    state          = params.get("state", "")

    if token not in tunnels:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="Unknown Instance",
                message="This BrainWiz token is not registered with the relay. "
                        "Start the BrainWiz app and try again.",
            ),
            status_code=404,
        )

    tunnel = tunnels[token]
    if not tunnel.ws:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="BrainWiz is Offline",
                message="Your BrainWiz app is not currently connected to the relay. "
                        "Make sure the app is running, then try again.",
            ),
            status_code=503,
        )

    token_display = token[:8] + "…"
    return HTMLResponse(
        _APPROVE_PAGE.format(
            token=token,
            token_display=token_display,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            state=state,
            form_action=f"/{token}/authorize",
        )
    )


async def authorize_token_post(request: Request) -> RedirectResponse:
    """Process approval for per-token authorize endpoint."""
    _purge_expired_codes()
    token = request.path_params["token"]
    form = await request.form()
    redirect_uri   = str(form.get("redirect_uri", ""))
    code_challenge = str(form.get("code_challenge", ""))
    state          = str(form.get("state", ""))

    if not token or token not in tunnels:
        return HTMLResponse(
            _ERROR_PAGE.format(
                title="Invalid Token",
                message="The BrainWiz token is no longer valid. Please try again.",
            ),
            status_code=400,
        )

    code = secrets.token_urlsafe(16)
    auth_codes[code] = {
        "token": token,
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + AUTH_CODE_TTL,
    }
    log.info(f"Auth code issued for tunnel (token path): {token[:8]}...")

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}&state={state}"
    return RedirectResponse(location, status_code=302)


# ---------------------------------------------------------------------------
# Regular HTTP proxy
# ---------------------------------------------------------------------------

async def proxy_request(request: Request) -> Response | JSONResponse:
    token = request.path_params["token"]

    if not _check_bearer(request, token):
        return _unauthorized(request, token)

    if not _check_rate_limit(token):
        return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)

    body_raw = await request.body()
    if len(body_raw) > MAX_BODY_BYTES:
        return JSONResponse({"error": "Payload too large."}, status_code=413)

    _record_request(token, body_bytes=len(body_raw))

    tunnel = tunnels.get(token)
    if not tunnel:
        return JSONResponse({"error": "Unknown brain. Check your relay URL."}, status_code=404)
    if not tunnel.ws:
        return JSONResponse(
            {"error": "This brain is currently offline. The user's computer may be asleep or the app is closed."},
            status_code=503,
        )

    sub_path = request.url.path
    prefix = f"/{token}"
    if sub_path.startswith(prefix):
        sub_path = sub_path[len(prefix):] or "/"

    body = body_raw.decode("utf-8", errors="replace")
    req_id = str(uuid.uuid4())

    envelope = {
        "id": req_id,
        "type": "request",
        "method": request.method,
        "path": sub_path,
        "query": str(request.url.query),
        "headers": dict(request.headers),
        "body": body,
    }

    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    tunnel.pending[req_id] = future

    try:
        await tunnel.ws.send_text(json.dumps(envelope))
        response_msg = await asyncio.wait_for(future, timeout=30.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": "Brain did not respond in time."}, status_code=504)
    except ConnectionError:
        return JSONResponse({"error": "Brain went offline during request."}, status_code=503)
    finally:
        tunnel.pending.pop(req_id, None)

    backend_headers = response_msg.get("headers", {})
    content_type = backend_headers.get("content-type", "text/plain")
    return Response(
        content=response_msg.get("body", ""),
        status_code=response_msg.get("status", 200),
        media_type=content_type,
        headers={k: v for k, v in backend_headers.items() if k.lower() != "content-type"},
    )


# ---------------------------------------------------------------------------
# SSE proxy (MCP GET /mcp)
# ---------------------------------------------------------------------------

async def proxy_sse(request: Request):
    token = request.path_params["token"]

    if not _check_bearer(request, token):
        return _unauthorized(request, token)

    if not _check_rate_limit(token):
        return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)

    _record_request(token)

    tunnel = tunnels.get(token)
    if not tunnel:
        return JSONResponse({"error": "Unknown brain."}, status_code=404)
    if not tunnel.ws:
        return JSONResponse({"error": "Brain is offline."}, status_code=503)

    sub_path = request.url.path
    prefix = f"/{token}"
    if sub_path.startswith(prefix):
        sub_path = sub_path[len(prefix):] or "/"

    req_id = str(uuid.uuid4())
    envelope = {
        "id": req_id,
        "type": "sse_request",
        "method": "GET",
        "path": sub_path,
        "query": str(request.url.query),
        "headers": dict(request.headers),
    }

    queue: asyncio.Queue = asyncio.Queue()
    tunnel.pending[req_id] = queue

    try:
        await tunnel.ws.send_text(json.dumps(envelope))
    except Exception:
        tunnel.pending.pop(req_id, None)
        return JSONResponse({"error": "Failed to reach brain."}, status_code=503)

    async def event_stream():
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=300)
                if msg.get("type") == "sse_end":
                    break
                if msg.get("type") == "sse_event":
                    line = msg["data"]
                    # Rewrite the MCP messages path to include the token prefix
                    # so AI clients POST back to the relay rather than the bare path.
                    if line.startswith("data: /"):
                        line = f"data: /{token}" + line[len("data: "):]
                    yield line
        except asyncio.TimeoutError:
            pass
        finally:
            tunnel.pending.pop(req_id, None)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

async def health(request: Request) -> JSONResponse:
    active = sum(1 for t in tunnels.values() if t.ws is not None)
    return JSONResponse({
        "status": "ok",
        "tunnels_registered": len(tunnels),
        "tunnels_active": active,
    })


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

routes = [
    Route("/health", health, methods=["GET"]),
    Route("/register", register, methods=["POST"]),
    Route("/admin/tokens", admin_add_tokens, methods=["POST"]),
    Route("/admin/tokens", admin_remove_tokens, methods=["DELETE"]),
    Route("/admin/stats", admin_stats, methods=["GET"]),
    # OAuth 2.1 discovery + flow (must come before /{token}/... catch-alls)
    Route("/.well-known/oauth-authorization-server", oauth_server_metadata, methods=["GET"]),
    # RFC 8414 path-based discovery: Codex appends the full MCP path (e.g. /{token}/mcp)
    Route("/.well-known/oauth-authorization-server/{path:path}", oauth_server_metadata_token, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
    Route("/authorize", authorize_get, methods=["GET"]),
    Route("/authorize", authorize_post, methods=["POST"]),
    Route("/token", token_exchange, methods=["POST"]),
    Route("/register/client", client_registration, methods=["POST"]),
    Route("/register/client/{token}", client_registration_token, methods=["POST"]),
    # Tunnel WebSocket
    WebSocketRoute("/tunnel/{token}", tunnel_endpoint),
    # Per-token OAuth metadata (must be before catch-all)
    Route("/{token}/.well-known/oauth-authorization-server", oauth_server_metadata_token, methods=["GET"]),
    Route("/{token}/mcp/.well-known/oauth-authorization-server", oauth_server_metadata_token, methods=["GET"]),
    Route("/{token}/.well-known/oauth-protected-resource", oauth_protected_resource_token, methods=["GET"]),
    # Per-token authorize endpoints (for clients that do path-based discovery)
    Route("/{token}/authorize", authorize_token_get, methods=["GET"]),
    Route("/{token}/authorize", authorize_token_post, methods=["POST"]),
    # MCP proxy routes
    Route("/{token}/mcp", proxy_sse, methods=["GET"]),
    Route("/{token}/mcp", proxy_request, methods=["POST", "DELETE"]),
    Route("/{token}/{path:path}", proxy_request, methods=["GET", "POST", "PUT", "DELETE"]),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BrainWiz Relay Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)
