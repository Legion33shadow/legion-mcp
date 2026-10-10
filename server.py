"""LEGION Verify — serveur MCP à 3 outils, lecture seule.

  get_checkpoint          dernière tête signée du journal MCP LEGION, signature vérifiée depuis l'empreinte racine épinglée
  get_server_changes      historique signé d'un serveur MCP + paquet de preuve (record, preuve d'inclusion, tête, trousseau)
  verify_evidence_bundle  vérifie un paquet de preuve HORS LIGNE (aucun appel réseau) ; option : empreinte d'outils approuvée

Aucune clé privée, aucun shell, aucun achat, aucune écriture, aucune URL fournie par l'appelant : seules des routes fixes
du journal public sont lues (LEGION_TLOG_BASE). Transport : stdio par défaut ; streamable-http si MCP_TRANSPORT=http
(mêmes réglages que la prod : 127.0.0.1, MCP_PORT, défaut 8802, protection DNS-rebinding).
"""
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from mcp.server.mcpserver import MCPServer

import legion_tlog_verify as T

ROOT_PIN = "a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036"
BASE = os.environ.get("LEGION_TLOG_BASE", "https://tlog.legion-api.com/tlog/v0").rstrip("/")
SERVER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:\-]*(/[A-Za-z0-9._@:\-]+){0,4}$")
MAX_SERVER_ID = 200
MAX_LIMIT = 50
MAX_BUNDLE_BYTES = 256 * 1024
MAX_FETCH_BYTES = 2 * 1024 * 1024
UA = "legion-verify-mcp/0.1"

mcp = MCPServer("LEGION Verify")


class ToolFail(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def _err(code, message):
    return {"ok": False, "error": {"code": code, "message": message}}


def _get(path, params=None):
    """GET sur une route FIXE du journal public. Jamais d'URL fournie par l'appelant."""
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=20) as r:
            data = r.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise ToolFail("NOT_FOUND" if e.code == 404 else "UPSTREAM_HTTP_%d" % e.code, "journal : HTTP %d sur %s" % (e.code, path))
    except Exception as e:
        raise ToolFail("UPSTREAM_UNREACHABLE", "journal injoignable (%s)" % type(e).__name__)
    if len(data) > MAX_FETCH_BYTES:
        raise ToolFail("UPSTREAM_TOO_LARGE", "réponse du journal trop grande")
    return data


def _keys(keyring_text):
    """Trousseau -> clés valides, ancré sur l'empreinte racine ÉPINGLÉE (jamais sur ce que dit le serveur)."""
    first = json.loads(next(l for l in keyring_text.splitlines() if l.strip()))
    root_pub = first.get("public_key_b64", "")
    if T.key_pin(root_pub) != ROOT_PIN:
        raise ToolFail("KEYRING_ROOT_MISMATCH", "la 1re entrée du trousseau n'a pas l'empreinte racine épinglée")
    try:
        return T.load_keyring(keyring_text, root_pub)
    except ValueError as e:
        raise ToolFail("KEYRING_INVALID", str(e))


def _head_and_keys():
    keyring = _get("/keyring").decode("utf-8")
    keys = _keys(keyring)
    head = json.loads(_get("/head"))
    return head["sth"], keys, keyring


@mcp.tool()
def get_checkpoint() -> dict:
    """Latest signed tree head of the LEGION MCP transparency log. The signature is checked against the keyring,
    anchored on the pinned root key fingerprint. Read-only. Returns tree_size, root_sha256, timestamp, signer and
    signature_valid. For a trustless check, verify it yourself (see `how_to_verify_yourself`)."""
    try:
        sth, keys, _ = _head_and_keys()
        th = sth["tree_head"]
        return {"ok": True, "tree_size": th["tree_size"], "root_sha256": th["root_sha256"], "timestamp": th.get("timestamp"),
                "signer_pin_sha256": th.get("issuer_pin_sha256"), "signature_valid": T.check_sth(sth, keys),
                "root_pin_sha256": ROOT_PIN, "signed_tree_head": sth, "claim_state": "observed_by_legion",
                "how_to_verify_yourself": "python3 -I -S legion_verify_mirror.py " + ROOT_PIN}
    except ToolFail as e:
        return _err(e.code, e.message)
    except Exception as e:
        return _err("INTERNAL", type(e).__name__)


@mcp.tool()
def get_server_changes(server_id: str, limit: int = 10) -> dict:
    """Signed tool-list history of one MCP server as observed by LEGION (registry id, e.g. "xyz.signomy/civitae"),
    newest first, at most `limit` (1-50) changes, plus an evidence bundle for the latest record (record + RFC 9162
    inclusion proof + signed tree head + keyring) that `verify_evidence_bundle` checks offline.
    A change is not a fault; history = what LEGION observed, not what other clients see."""
    if not isinstance(server_id, str) or not server_id or len(server_id) > MAX_SERVER_ID or not SERVER_ID_RE.match(server_id) \
            or ".." in server_id:
        return _err("INVALID_SERVER_ID", "server_id : 1-%d caractères [A-Za-z0-9._@:-] et au plus 4 '/'" % MAX_SERVER_ID)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        return _err("INVALID_LIMIT", "limit : entier entre 1 et %d" % MAX_LIMIT)
    try:
        sth, keys, keyring = _head_and_keys()
        size = sth["tree_head"]["tree_size"]
        srv = json.loads(_get("/servers/" + urllib.parse.quote(server_id, safe="/@:")))
        latest = srv.get("latest_record")
        if not isinstance(latest, dict):
            return _err("NOT_FOUND", "aucun enregistrement signé pour ce serveur")
        if latest["leaf_index"] >= size:
            return _err("NOT_YET_COVERED", "le dernier enregistrement n'est pas encore couvert par une tête signée")
        proof = json.loads(_get("/proof/inclusion", {"leaf_index": latest["leaf_index"], "tree_size": size}))
        changes = sorted(srv.get("records", []), key=lambda r: r.get("leaf_index", -1), reverse=True)
        return {"ok": True, "server_id": server_id, "changes_total": len(changes),
                "changes": [{k: c.get(k) for k in ("leaf_index", "observed_at", "change", "tools_sha256")} for c in changes[:limit]],
                "latest_tools_sha256": latest["tools_fingerprint"].get("sha256"),
                "evidence_bundle": {"record": latest, "proof": proof, "sth": sth, "keyring": keyring},
                "claim_state": "observed_by_legion"}
    except ToolFail as e:
        return _err(e.code, e.message)
    except Exception as e:
        return _err("INTERNAL", type(e).__name__)


@mcp.tool()
def verify_evidence_bundle(bundle: dict, approved_tools_sha256: str = "") -> dict:
    """Verify an evidence bundle OFFLINE (no network call): keyring chain from the pinned root fingerprint, record
    signature and integrity, signed tree head, RFC 9162 inclusion proof. If `approved_tools_sha256` is given, also
    reports whether the signed tool list still matches the version you approved (UNAPPROVED_CHANGE if not).
    Bundle = {record, proof, sth, keyring} as returned by get_server_changes (max 256 KB)."""
    try:
        raw = json.dumps(bundle)
    except Exception:
        return _err("INVALID_BUNDLE", "paquet non sérialisable en JSON")
    if len(raw) > MAX_BUNDLE_BYTES:
        return _err("BUNDLE_TOO_LARGE", "paquet > %d octets" % MAX_BUNDLE_BYTES)
    if not isinstance(bundle, dict) or not all(isinstance(bundle.get(k), dict) for k in ("record", "proof", "sth")) \
            or not isinstance(bundle.get("keyring"), str):
        return _err("INVALID_BUNDLE", "champs attendus : record, proof, sth (objets) et keyring (texte JSONL)")
    if approved_tools_sha256 and not re.fullmatch(r"[0-9a-f]{64}", approved_tools_sha256):
        return _err("INVALID_APPROVED_SHA", "approved_tools_sha256 : 64 caractères hexadécimaux minuscules")
    try:
        keys = _keys(bundle["keyring"])
    except ToolFail as e:
        return _err(e.code, e.message)
    except Exception as e:
        return _err("KEYRING_INVALID", type(e).__name__)
    rec, proof, sth = bundle["record"], bundle["proof"], bundle["sth"]
    integ, sig, _ = T.check_record(rec, keys)
    checks = {"keyring_from_pinned_root": True, "record_integrity": bool(integ), "record_signature": bool(sig),
              "head_signature": bool(T.check_sth(sth, keys)), "inclusion": bool(T.check_inclusion(rec, proof, sth))}
    ok = all(checks.values())
    out = {"ok": ok, "checks": checks, "verified_offline": True, "root_pin_sha256": ROOT_PIN}
    if ok:
        signed = (rec.get("tools_fingerprint") or {}).get("sha256")
        out.update(server_id=rec.get("server_id"), leaf_index=rec.get("leaf_index"), observed_at=rec.get("observed_at"),
                   tools_sha256=signed, tree_size=sth["tree_head"]["tree_size"], claim_state="verified_signed_observation")
        if approved_tools_sha256:
            out["approval"] = "MATCHES_APPROVED" if signed == approved_tools_sha256 else "UNAPPROVED_CHANGE"
    else:
        out["error"] = {"code": "EVIDENCE_REJECTED", "message": "échec : " + ", ".join(k for k, v in checks.items() if not v)}
    return out


def main():
    if os.environ.get("MCP_TRANSPORT") == "http":
        from mcp.server.transport_security import TransportSecuritySettings
        port = int(os.environ.get("MCP_PORT", "8802"))
        ts = TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                       allowed_hosts=["mcp.legion-api.com", "127.0.0.1:%d" % port, "localhost:%d" % port],
                                       allowed_origins=["https://mcp.legion-api.com"])
        mcp.run(transport="streamable-http", host="127.0.0.1", port=port, stateless_http=True, transport_security=ts)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
