# LEGION Verify — MCP server (3 read-only tools) · v1.1.0

Check what an MCP server exposed, and when, against LEGION's signed, append-only transparency log of MCP tool lists.
Every answer is checked against a keyring anchored on a pinned root key fingerprint; evidence bundles can be re-checked
offline.

## Tools — all read-only (`readOnlyHint: true`, `destructiveHint: false`)
| Tool | What it does | Network |
|---|---|---|
| `get_checkpoint` | Latest signed tree head; signature checked against the keyring | GET fixed routes of `https://tlog.legion-api.com/tlog/v0` |
| `get_server_changes` | Signed tool-list history of one MCP server (registry id, `limit` 1–50), newest first, plus an evidence bundle for the latest record | GET fixed routes of `https://tlog.legion-api.com/tlog/v0` |
| `verify_evidence_bundle` | Verifies a bundle OFFLINE: keyring chain from the pinned root, record signature, signed head, RFC 9162 inclusion proof; optional check against a tools hash you approved (`MATCHES_APPROVED` / `UNAPPROVED_CHANGE`) | none |

Nothing else: no write, no purchase, no scan, no caller-supplied URL, no private key, no API key needed.

## Connect
**Claude Code (remote)**

    claude mcp add --transport http legion-verify https://mcp.legion-api.com/mcp

**Claude Desktop (local, stdio)** — `claude_desktop_config.json`:

    { "mcpServers": { "legion-verify": { "command": "python3", "args": ["/ABSOLUTE/PATH/server.py"] } } }

(requires `pip install "mcp==2.1.1"`; `server.py` and `legion_tlog_verify.py` in the same folder)

**Any MCP client (remote)**: streamable HTTP at `https://mcp.legion-api.com/mcp`, no auth.

## Try it
1. "Call get_checkpoint and give tree_size, root_sha256 and signature_valid."
2. "With get_server_changes, show the signed history of xyz.signomy/civitae (limit 3)."
3. "Pass the evidence_bundle you got to verify_evidence_bundle and tell me whether the proof is valid."

## Verify the whole log yourself (no MCP, no pip)
    PIN=a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036
    curl -fsSLO https://legion33shadow.github.io/legion-tlog-mirror/legion_verify_mirror.py
    python3 -I -S legion_verify_mirror.py "$PIN"

Root key fingerprint — pin it out of band: `a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036`

## Limits
The log is the signed record of one observer (LEGION). Bitcoin anchors are `pending` (no `ots verify` on a full node yet).
No independent witness has cosigned yet. Servers that require auth are not observed. Shared upstream rate limit: the
public server makes 2 log requests per `get_server_changes` call.

License: MIT (see LICENSE).
