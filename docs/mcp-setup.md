# MCP Setup Guide

This guide explains how to configure AI agents (Claude Desktop, Cursor,
Codex, custom SDK agents) to access your another-s3-manager instance via
the MCP (Model Context Protocol) server.

## Concepts

### Tokens

MCP tokens authenticate AI agents the same way session cookies authenticate
the web UI — they grant the same permissions (roles, allowed buckets,
admin flags) as the user who created them. They are MCP-only and cannot be
used as Bearer tokens against the regular `/api/*` web endpoints, which
require the cookie + CSRF flow. Each token:

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

### Tools

| Tool                                                                                         | Purpose                                                                                                                                   |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `list_roles`                                                                                 | List role names accessible to your token                                                                                                  |
| `list_buckets(role)`                                                                         | List buckets in a given role                                                                                                              |
| `list_files(role, bucket, path)`                                                             | List files at a path in a bucket                                                                                                          |
| `bucket_summary(role, bucket, path="")`                                                      | One-call compact digest: counts, sizes, per-prefix breakdown, extension histogram, top-10 largest. Use FIRST for "what's in this bucket?" |
| `get_object_metadata(role, bucket, path)`                                                    | Size, last-modified, content-type, etag — no download                                                                                     |
| `read_file(role, bucket, path, force_text=false)`                                            | Read a text file                                                                                                                          |
| `presigned_url(role, bucket, path, expires_in=3600)`                                         | Time-limited download URL (works for binary too)                                                                                          |
| `upload_file(role, bucket, path, content_base64)`                                            | Upload (write tool)                                                                                                                       |
| `copy_object(role, source_bucket, source_path, dest_bucket, dest_path, delete_source=false)` | Server-side copy within a role; `delete_source=true` moves/renames (write tool)                                                           |
| `delete_file(role, bucket, path)`                                                            | Delete (write tool)                                                                                                                       |

`list_files` is bounded in BOTH modes by `mcp_list_page_size` /
`mcp_list_max_page_size` — a listing longer than the effective cap is cut,
with `is_truncated: true` and a `hint` added to the response. In recursive
mode, page through with `next_continuation_token`. In non-recursive mode
there is no continuation token (S3's delimiter listing doesn't offer one at
the granularity this tool needs) — the hint instead points at `bucket_summary`
or `list_files(..., recursive=True)` to see the rest.

### The `bucket_summary` honesty contract

`bucket_summary` never guesses. When the bucket (or the scanned prefix) is
larger than `mcp_summary_max_keys`, the response says so explicitly instead
of silently reporting incomplete numbers as if they were the whole picture:

| Field                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `complete`             | `false` once the walk hits `mcp_summary_max_keys`. When `false`, `total_objects`/`total_bytes` are `null` — they are NEVER reported as a guess.                                                                                                                                                                                                                                                                            |
| `note`                 | Present (non-null) only when `complete` is `false`. Plain-language warning that `root_objects`, `extensions`, `largest_objects`, and `oldest_modified`/`newest_modified` were computed from the scanned range only and can under-report — S3 returns keys lexicographically, so a single oversized prefix can hide a loose root object, or the bucket's actual largest file, if either sorts after where the scan stopped. |
| per-prefix `coverage`  | `"complete"` (every object under that prefix was scanned), `"partial"` (the scan stopped partway through it), or `"not_scanned"` (the scan never reached it) — the only per-prefix numbers safe to trust as exact are `"complete"` ones.                                                                                                                                                                                   |
| `prefix_list_complete` | Whether Step 1 (the cheap `Delimiter="/"` enumeration of _which_ prefixes exist) finished within its own `mcp_summary_prefix_scan_pages` budget. Can be `false` even when `prefixes_truncated` is also relevant — they answer different questions.                                                                                                                                                                         |
| `prefixes_truncated`   | Whether more than the top-20 rendered prefixes exist (`prefix_count` says how many). Independent of `prefix_list_complete` — all prefixes can be known (`prefix_list_complete: true`) while only the top 20 are shown (`prefixes_truncated: true`).                                                                                                                                                                        |

Rule of thumb for an agent: if `complete` is `false`, treat every number
outside `total_objects`/`total_bytes` (null) and `"complete"`-coverage
prefixes as a lower bound, not a total — read `note` for specifics, then
narrow with `path` or ask an admin to raise `mcp_summary_max_keys`.

`read_file` returns text content. Binary files error with `BINARY_CONTENT`
unless `force_text=true` is passed (in which case undecoded bytes become
`�` replacement chars) — for binary files, prefer `presigned_url` to hand out
a download link instead.

Write tools (`upload_file`, `copy_object`, `delete_file`) are blocked for
read-only tokens and when `mcp_disable_writes` is set; `delete_file` and
`copy_object` with `delete_source=true` are additionally blocked when
`disable_deletion` is set. `copy_object` copies within one role's credentials
only (both buckets must be in the role's allowed_buckets) — cross-role /
cross-provider copy is not supported.

### Tool annotations (auto-approval hints)

All ten tools advertise MCP `readOnlyHint`/`destructiveHint`/`idempotentHint`
annotations so a client (e.g. Claude Desktop) can auto-approve reads while
still gating writes — the 7 read tools (`list_roles`, `list_buckets`,
`list_files`, `bucket_summary`, `read_file`, `get_object_metadata`,
`presigned_url`) are `readOnlyHint: true`; the 3 write tools
(`upload_file`, `copy_object`, `delete_file`) are not, and all three are
additionally flagged `destructiveHint: true` — none of them checks whether
something already exists at the destination before overwriting it (S3
`PutObject`/`CopyObject` semantics), and `delete_file` removes an object
outright. `upload_file` is also `idempotentHint: true` (same bytes to the
same key always end in the same state) — destructive and idempotent are
independent hints, a tool can be both.

**One caveat if your client auto-approves read-only tools:** `presigned_url`
is annotated `readOnlyHint: true` because it never modifies the bucket — but
unlike the other read tools, it doesn't just describe state, it *mints* a
live, shareable, credential-bearing download URL that anyone holding it can
use until it expires. Annotations are hints, not a security boundary — treat
`presigned_url` as worth a manual look before auto-approving it, not
something that's safe to blanket-approve just because it's technically
read-only.

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
    "https://your-app.example.com/mcp/",
    headers={"Authorization": "Bearer as3m_YOUR_TOKEN_HERE"},
) as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
```

## Troubleshooting

### `INVALID_TOKEN` error

- Token may have been revoked. Check the `/api-tokens` page.
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

- Use the `presigned_url` tool to hand out a time-limited download link and
  fetch the file directly — this bypasses the read cap and works for binary
  files too (the same escape hatch `read_file` suggests on `BINARY_CONTENT`)
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

| Field                           | Default            | Purpose                                                                                                                                                                                            |
| ------------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mcp_enabled`                   | `true`             | Global kill-switch. When `false`, `/mcp/*` returns 503. Hot-reload.                                                                                                                                |
| `mcp_disable_writes`            | `false`            | Server-level read-only. Forces all tokens to read-only. Hot-reload.                                                                                                                                |
| `mcp_text_extensions`           | `[]`               | Per-deployment extension to the built-in text-extension whitelist for `read_file`.                                                                                                                 |
| `mcp_global_max_read_bytes`     | `10485760` (10 MB) | Server-level cap on `read_file` size. Cannot exceed 10 MB hard ceiling.                                                                                                                            |
| `mcp_summary_max_keys`          | `50000` (min 1000) | Keys the `bucket_summary` walk may visit per call. Larger buckets get an honest partial summary (`complete: false`, per-prefix `coverage`, a `note` explaining what may under-report — see below). |
| `mcp_summary_prefix_scan_pages` | `20`               | Pages (1000 entries each) `bucket_summary` may spend enumerating prefixes at a level before flagging `prefix_list_complete: false`.                                                                |
| `mcp_list_page_size`            | `1000`             | Default page size for `list_files` when the agent omits `max_keys`.                                                                                                                                |
| `mcp_list_max_page_size`        | `10000`            | Hard ceiling on the `max_keys` an agent may request via `list_files`; larger values are clamped, not rejected.                                                                                     |

MCP tool calls are covered by Prometheus metrics (`as3m_mcp_tool_calls_total`,
`as3m_mcp_tool_response_bytes`, etc.) — see [observability.md](observability.md).
