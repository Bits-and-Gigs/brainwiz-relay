# BrainWiz MCP Relay — Client Compatibility

## Confirmed Working

| Client | Notes |
|--------|-------|
| Claude Code | CLI-based; uses MCP over OAuth 2.1 |
| Claude Desktop | Desktop app; full OAuth PKCE flow |
| Claude.ai | Web-based; MCP remote connection |
| OpenAI Codex | Requires per-token OAuth discovery (RFC 8414 path-based) |

## Needs Testing

| Client | Notes |
|--------|-------|
| Cursor | Popular AI code editor with MCP support |
| Windsurf (Codeium) | AI code editor; MCP support added recently |
| GitHub Copilot | VS Code / JetBrains extension; MCP support varies by version |
| Continue.dev | Open-source AI coding assistant; MCP compatible |
| Cline | VS Code extension; MCP-native |
| Zed | AI-native editor with MCP support |
| Sourcegraph Cody | AI coding assistant; MCP integration |
| Amazon Q Developer | AWS AI coding assistant |
| JetBrains AI Assistant | Built-in JetBrains IDE assistant |
| Gemini CLI | Google's CLI tool; MCP support in progress |
