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
`disable_deletion` is set or the role has `allow_delete: false` (absent means
allowed). The role restriction also binds administrators. It does not prevent
uploading or copying over an existing key. A move rechecks deletion permission
after copying: if permission was revoked, the copy stays and the response says
`Copied, source kept`, with `moved: false` and `source_kept_reason`. `copy_object` copies within one role's credentials
only (both buckets must be in the role's allowed_buckets) — cross-role /
cross-provider copy is not supported.

A single-object move reserves both paths throughout copying and deletion, reads
its source ETag and VersionId, and copies that exact state with
`CopySourceIfMatch`. It rechecks the current source before deletion. If the
source changed or disappeared, the result is `copied: true`, `moved: false`,
`source_kept_reason: "SOURCE_CHANGED"`, with the message
`Copied, source changed after the copy — source kept`. A copy precondition
failure instead returns `ok: false`, `copied: false`, `moved: false` and
`SOURCE_CHANGED`; nothing is deleted. Always inspect `copied` as well as the
reason.

On versioned buckets the copy is pinned to the source `VersionId`, which needs
`s3:GetObjectVersion`. Without that permission each copy attempt falls back to
one copy without the version: `CopySourceIfMatch` still ensures the copied
bytes are the ones read, the source is deleted only if the copy reports the same
`CopySourceVersionId` that was read (otherwise `SOURCE_CHANGED`, source kept),
and the final HEAD still compares the VersionId before deleting.

Once the copy has succeeded, a later failure never hides it: an S3 403 returns
`copied: true`, `moved: false`, `S3_ACCESS_DENIED`; any other failure before the
source is confirmed deleted (5xx, network, credentials) returns
`SOURCE_DELETE_FAILED` — check the source, it may still exist.

For versioned sources the copy is pinned to the source's `VersionId`, but
deletion never names a version: with versioning **enabled** it creates a delete
marker, so the key disappears without exposing a previous version and all
versions are retained (an external write after the final HEAD is hidden by the
marker but stays available by its `VersionId`).

Every guarded delete carries `If-Match` with the copied ETag; a failed
precondition or a missing source during that DELETE returns `copied: true`,
`moved: false`, `SOURCE_CHANGED`. The final HEAD compares ETag, VersionId,
LastModified, ContentLength, ContentType and user Metadata, and the delete
permission is checked again right after that comparison.

Remaining window (accepted, best-effort): writes handled by this ASM process
share the reservation, but external clients and other replicas are not
coordinated. Between the final HEAD and the DELETE:

- on a backend that ignores `If-Match` on DELETE — MinIO RELEASE.2026-10-23 does —
  an external overwrite of an unversioned source is lost;
- on any backend, an external overwrite that keeps the same bytes but changes
  only metadata (same ETag) passes `If-Match` and is lost.

Enable bucket versioning to keep that data: deletes then only add a marker.

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
outright. None of the three write tools advertises `idempotentHint` —
`upload_file`'s repeat `PutObject` on a bucket with S3 object versioning
enabled mints a new object version instead of leaving the bucket unchanged,
so the "no additional effect on repeat" claim does not hold for every
bucket this generic S3 manager (AWS/R2/MinIO/Wasabi) can point at.

**One caveat if your client auto-approves read-only tools:** `presigned_url`
is annotated `readOnlyHint: true` because it never modifies the bucket — but
unlike the other read tools, it doesn't just describe state, it _mints_ a
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
      "url": "https://your-app.example.com/mcp",
      "headers": {
        "Authorization": "Bearer as3m_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

Note: `"type": "http"` is required by clients that don't auto-detect
Streamable HTTP transport (VS Code MCP, some SDK builds). Both `/mcp` and
`/mcp/` work — the bare form is served directly, with no redirect.

Restart Claude Desktop. The tools should appear under the MCP icon.

## Cursor

Edit `~/.cursor/mcp.json` (or via Cursor settings → Extensions → MCP):

```json
{
  "mcpServers": {
    "another-s3-manager": {
      "type": "http",
      "url": "https://your-app.example.com/mcp",
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

Reused for two different tools with two different limits — check which tool
raised it:

- **`read_file`**: the file exceeds the smaller of (per-token cap,
  server-level `mcp_global_max_read_bytes`). Either:
  - Use the `presigned_url` tool to hand out a time-limited download link and
    fetch the file directly — this bypasses the read cap and works for binary
    files too (the same escape hatch `read_file` suggests on `BINARY_CONTENT`)
  - Make a new token with a higher `max_read_bytes` (admin can raise the
    per-token cap up to 10 MB)
  - Use a non-MCP download path (web UI, direct S3 client) for large files
- **`upload_file`**: the payload exceeds the server-wide `max_file_size`
  setting (the same limit the web UI's upload form enforces — there is no
  per-token override for uploads). Reduce the file size or ask an admin to
  raise `max_file_size` in Settings. A request whose declared size is
  clearly over the limit may instead be rejected at the transport level
  (HTTP 413 on the `/mcp` request itself, before `upload_file` even runs) —
  same limit, enforced earlier.

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
