# BrainWiz Relay

A lightweight WebSocket tunnel relay that lets AI clients reach MCP servers running on users' local machines. It includes an OAuth 2.1 (PKCE) flow so clients like Claude Desktop can connect through a browser approval page rather than requiring manual config file editing.

## Privacy

**Your memories never leave your machine.** All BrainWiz data (memories, the database, the embedding model) is stored locally on your computer or self-hosted server. The relay never stores, logs, or has persistent access to memory content.

What the relay does handle:

- **Desktop/relay mode:** MCP requests from AI clients are proxied through this server to reach your local app. Request content passes through in transit but is never logged or stored. Only aggregate request counts and payload sizes are tracked per license key for abuse detection.
- **Docker/self-hosted mode:** Nothing passes through the relay except a license registration call at startup and a daily heartbeat (license key + instance ID only). All MCP traffic goes directly between AI clients and your server.

In both modes, the relay holds only an in-memory map of active connections that is cleared on every restart.

Your email address is stored by our payment processor (not this server) in association with your license key. It may be used to contact you if abuse is detected.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Desktop app registers and receives a tunnel token |
| `POST` | `/license/activate` | Docker startup registration (kicks previous instance) |
| `POST` | `/license/heartbeat` | Docker daily liveness check |
| `WS` | `/tunnel/{token}` | App opens persistent WebSocket tunnel |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth 2.1 server metadata |
| `GET` | `/.well-known/oauth-protected-resource` | OAuth resource metadata |
| `GET` | `/authorize` | OAuth approval page (shown in browser) |
| `POST` | `/authorize` | Process approval, redirect with auth code |
| `POST` | `/token` | Exchange auth code + PKCE verifier for bearer token |
| `*` | `/{token}/mcp[/...]` | Proxy AI client requests to the user's local app |

## Deploy on Fly.io

1. Edit `fly.toml` and set your own `app` name.
2. From this directory:
   ```bash
   flyctl launch --no-deploy
   flyctl deploy
   ```

The included `fly.toml` configures `auto_stop_machines = 'off'` — this is required to keep WebSocket tunnels alive across all connected users.

## Run locally

```bash
pip install -r requirements.txt
python server.py --host 0.0.0.0 --port 8080
```

## How it works

1. The local app calls `POST /register` to get a token, then opens `WS /tunnel/{token}`.
2. The AI client is pointed at `https://relay.example.com/{token}/mcp`.
3. On first connection the relay returns a 401 that triggers the OAuth flow; the user approves in a browser and the client receives a bearer token (equal to the tunnel token).
4. Subsequent requests arrive at the relay with `Authorization: Bearer {token}`, get forwarded over the WebSocket tunnel, and the response is streamed back.
