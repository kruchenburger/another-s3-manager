# MCP Setup Guide

This guide explains how to configure AI agents (Claude Desktop, Cursor,
Codex, custom SDK agents) to access your another-s3-manager instance via
the MCP (Model Context Protocol) server.

## Concepts

### Tokens

API tokens authenticate AI agents the same way session cookies authenticate
the web UI — they grant the same permissions (roles, allowed buckets,
admin flags) as the user who created them. Each token:

- Has a per-token cap on `read_file` size (`max_read_bytes`, default 1 MB,
  hard ceiling 10 MB)
- Can be marked **read-only** (allows list/read tools, blocks upload/delete)
- Is shown as plaintext only once — at creation. Lose it = revoke + recreate.
- Can be revoked at any time without affecting your web sessions.

Per-user limit: 10 active tokens. Revoked tokens don't count toward the limit.

### Read-only knobs

There are two layers:

- **Per-token `is_read_only`** flag (set when you create the token)
- **Server-level `mcp_disable_writes`** config (admin-only, kill-switch
  for all writes regardless of per-token settings)

Either being on blocks all write operations.

### Tools (v1)

| Tool                                              | Purpose                                  |
| ------------------------------------------------- | ---------------------------------------- |
| `list_roles`                                      | List role names accessible to your token |
| `list_buckets(role)`                              | List buckets in a given role             |
| `list_files(role, bucket, path)`                  | List files at a path in a bucket         |
| `read_file(role, bucket, path, force_text=false)` | Read a text file                         |
| `upload_file(role, bucket, path, content_base64)` | Upload (write tool)                      |
| `delete_file(role, bucket, path)`                 | Delete (write tool)                      |

`read_file` returns text content. Binary files error with `BINARY_CONTENT`
unless `force_text=true` is passed (in which case undecoded bytes become
`�` replacement chars).

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "another-s3-manager": {
      "type": "http",
      "url": "https://your-app.example.com/mcp/",
      "headers": {
        "Authorization": "Bearer as3m_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

Note: the URL must end with a trailing slash (`/mcp/`), and `"type": "http"`
is required by clients that don't auto-detect Streamable HTTP transport
(VS Code MCP, some SDK builds).

Restart Claude Desktop. The tools should appear under the MCP icon.

## Cursor

Edit `~/.cursor/mcp.json` (or via Cursor settings → Extensions → MCP):

```json
{
  "mcpServers": {
    "another-s3-manager": {
      "type": "http",
      "url": "https://your-app.example.com/mcp/",
      "headers": {
        "Authorization": "Bearer as3m_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

## Codex / generic SDK

For the Anthropic Agent SDK or other custom clients:

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client(
    "https://your-app.example.com/mcp",
    headers={"Authorization": "Bearer as3m_YOUR_TOKEN_HERE"},
) as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
```

## Troubleshooting

### `INVALID_TOKEN` error

- Token may have been revoked. Check the `/v2/api-tokens` page.
- Copied with extra whitespace or truncated? Tokens are exactly 48 chars
  including the `as3m_` prefix.
- The user account that created the token may have been deleted.

### `BINARY_CONTENT` error

The file's extension or content sniff suggests it's binary. Either:

- Confirm the file really is text and pass `force_text=true`
- Add the extension to `mcp_text_extensions` in admin Settings
- Skip the file

### `READ_ONLY_TOKEN` / `READ_ONLY_SERVER`

- `READ_ONLY_TOKEN`: your token was created with read-only flag set. Make
  a new token with read-only off.
- `READ_ONLY_SERVER`: server config has `mcp_disable_writes=true`. An
  admin must change it in Settings.

### `FILE_TOO_LARGE`

The file exceeds the smaller of (per-token cap, server-level
`mcp_global_max_read_bytes`). Either:

- Make a new token with a higher `max_read_bytes` (admin can raise the
  per-token cap up to 10 MB)
- Use a non-MCP download path (web UI, direct S3 client) for large files

## Security best practices

- **Never commit tokens to source control.** Treat them like passwords.
- **Use read-only tokens** unless write access is explicitly needed. The
  default in the create modal is read-only for this reason.
- **Rotate periodically.** Revoke + create a new token every few months,
  especially after personnel changes or device migrations.
- **One token per agent.** Don't share tokens across multiple AI clients
  — if one is compromised, you can revoke without affecting others.
- **Use HTTPS only.** The token is passed in a header; without TLS, it's
  visible in transit.

## Self-host configuration reference

Set in `data/config.json` or via the admin Settings page:

| Field                       | Default            | Purpose                                                                            |
| --------------------------- | ------------------ | ---------------------------------------------------------------------------------- |
| `mcp_enabled`               | `true`             | Global kill-switch. When `false`, `/mcp/*` returns 503. Hot-reload.                |
| `mcp_disable_writes`        | `false`            | Server-level read-only. Forces all tokens to read-only. Hot-reload.                |
| `mcp_text_extensions`       | `[]`               | Per-deployment extension to the built-in text-extension whitelist for `read_file`. |
| `mcp_global_max_read_bytes` | `10485760` (10 MB) | Server-level cap on `read_file` size. Cannot exceed 10 MB hard ceiling.            |

Env vars:

| Variable           | Default | Purpose                                                                                                            |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------ |
| `LOG_FORMAT`       | `text`  | `text` or `json`. JSON is structured for log aggregators.                                                          |
| `METRICS_PASSWORD` | unset   | Optional basic-auth for `/metrics` (username `metrics`, password `$METRICS_PASSWORD`). If unset, endpoint is open. |

## Prometheus scrape

Example scrape config:

```yaml
scrape_configs:
  - job_name: another-s3-manager
    metrics_path: /metrics
    basic_auth:
      username: metrics
      password: ${METRICS_PASSWORD}
    static_configs:
      - targets: ["your-app.example.com:443"]
```

A Grafana dashboard JSON is on the roadmap (see backlog).
