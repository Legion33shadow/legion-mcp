# LEGION Verify — MCP server to detect MCP tool drift (5 read-only tools) · v1.3.0

Did an MCP server change its tools after you approved them? A model reads tool descriptions as instructions, so a
silent change to a description or an `inputSchema` (tool drift, "rug pull") matters. LEGION Verify answers from
LEGION's signed, append-only transparency log of MCP tool lists: what a server exposed, and when it changed.
Every answer is checked against a keyring anchored on a pinned root key fingerprint (Ed25519, RFC 9162 Merkle proofs);
evidence bundles can be re-checked offline.

To pin tool lists in a lockfile and fail CI on drift, see [legion-lock](https://github.com/Legion33shadow/legion-lock).

## Tools — all read-only (`readOnlyHint: true`, `destructiveHint: false`)
| Tool | What it does | Network |
|---|---|---|
| `get_checkpoint` | Latest signed tree head; signature checked against the keyring | GET fixed routes of `https://tlog.legion-api.com/tlog/v0` |
| `get_server_changes` | Signed tool-list history of one MCP server (registry id, `limit` 1–50), newest first, plus an evidence bundle for the latest record | GET fixed routes of `https://tlog.legion-api.com/tlog/v0` |
| `verify_evidence_bundle` | Verifies a bundle OFFLINE: keyring chain from the pinned root, record signature, signed head, RFC 9162 inclusion proof; optional check against a tools hash you approved (`MATCHES_APPROVED` / `UNAPPROVED_CHANGE`) | none |
| `verify_mcp_server` | Paste an MCP server URL: matched against the public MCP registry, then the latest signed tool-list record, change count (total / 30 days), RFC 9162 inclusion proof re-checked from the pinned root, and an evidence bundle. `live=true` adds the tool list served now, compared with the signed one (not signed) | GET `https://legion-api.com/drift/verify` (default; `LEGION_DRIFT_BASE`). The live comparison runs only on the hosted endpoint, and only for servers listed in the registry |
| `check_mcp_server` | One call for a registry id: signed tool-list fingerprint history, last change with fingerprints before/after and diff link, per-server coverage from the signed COVERAGE_V1 register (`full_register` is `COMPLETE` only if observed in every cycle, `UNKNOWN` if partial), proof URLs, and one command that re-checks everything offline (`legion_check` kit). Unknown id → `UNKNOWN` (absence from the log is not a verdict) | GET fixed routes of `https://tlog.legion-api.com/tlog/v0` and `https://legion-api.com/tlog/v0/coverage` |

Nothing else: no write, no purchase, no private key, no API key needed. The only caller-supplied URL is the one given to `verify_mcp_server`: it is looked up in the registry; this server never connects to it. On the hosted endpoint, `live=true` lets LEGION's drift service send `initialize` + `tools/list` to that server, and only if it is a registry entry with a public address.

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
4. "Use verify_mcp_server on https://tandem.ac/mcp with live=true: did its tools change since the signed record?"

Same check in a browser, with an embeddable badge: https://legion-api.com/drift/check/

## Verify the whole log yourself (no MCP, no pip)
    PIN=a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036
    curl -fsSLO https://legion33shadow.github.io/legion-tlog-mirror/legion_verify_mirror.py
    python3 -I -S legion_verify_mirror.py "$PIN"

Root key fingerprint — pin it out of band: `a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036`

## Limits
The log is the signed record of one observer (LEGION); it does not show what a server serves to other clients.
Only `name`, `description` and `inputSchema` are fingerprinted. A change appears only after the next LEGION
observation and the next signed head. Bitcoin anchors are `pending` (no `ots verify` on a full node yet).
No independent witness has cosigned yet. Servers that require auth are not observed.

Public server (v1.3.0): immutable proofs and per-head history are cached; each client (IP seen by Cloudflare) may
trigger at most 20 uncached log requests per minute (`CLIENT_RATE_LIMITED` otherwise; cached answers still served).

License: MIT (see LICENSE).
