"""LEGION Verify — serveur MCP à 4 outils, lecture seule.

  get_checkpoint          dernière tête signée du journal MCP LEGION, signature vérifiée depuis l'empreinte racine épinglée
  get_server_changes      historique signé d'un serveur MCP + paquet de preuve (record, preuve d'inclusion, tête, trousseau)
  verify_evidence_bundle  vérifie un paquet de preuve HORS LIGNE (aucun appel réseau) ; option : empreinte d'outils approuvée
  verify_mcp_server       URL d'un serveur MCP -> dernière définition signée, changements, preuve d'inclusion + tête signée
                          (revérifiées ici), et si la définition servie maintenant diffère (sonde du service drift, non signée)

Aucune clé privée, aucun shell, aucun achat, aucune écriture. Seules des routes fixes sont lues : journal public
(LEGION_TLOG_BASE) et /verify du service drift (LEGION_DRIFT_BASE) ; l'URL passée à verify_mcp_server n'est jamais
récupérée par ce serveur, le service drift ne sonde que des adresses publiques. Transport : stdio par défaut ; streamable-http si MCP_TRANSPORT=http
(mêmes réglages que la prod : 127.0.0.1, MCP_PORT, défaut 8802, protection DNS-rebinding).
"""
import collections
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations
from pydantic import StrictInt, StrictStr

import legion_tlog_verify as T

ROOT_PIN = "a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036"
BASE = os.environ.get("LEGION_TLOG_BASE", "https://tlog.legion-api.com/tlog/v0").rstrip("/")
SERVER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:\-]*(/[A-Za-z0-9._@:\-]+){0,4}$")
MAX_SERVER_ID = 200
MAX_LIMIT = 50
MAX_BUNDLE_BYTES = 256 * 1024
MAX_FETCH_BYTES = 2 * 1024 * 1024
UA = "legion-verify-mcp/0.1"
CACHE_TTL = 30            # s : trousseau + tête signée partagés entre appels (évite les 429 du limiteur du journal)
_CACHE, _LOCK = {}, threading.Lock()
# Cache des réponses IMMUABLES ou liées à une tête signée (version 1.2.0) :
#  - /proof/inclusion?leaf_index=I&tree_size=N avec N = taille d'une tête signée : ne change jamais ;
#  - /servers/{id} : mémorisé pour la tête signée courante, vidé dès que la tête change.
# Quota par client (IP vue par Cloudflare, en-tête CF-Connecting-IP) sur les seuls appels qui partent vers le journal :
# un gros utilisateur ne peut pas consommer plus de CLIENT_MISS_PER_MIN des ~60 requêtes/min allouées à notre IP.
PROOF_CACHE_MAX, SERVERS_CACHE_MAX, CLIENT_MISS_PER_MIN = 20000, 5000, 20
_PROOFS, _SERVERS, _SERVERS_HEAD, _MISSES = collections.OrderedDict(), collections.OrderedDict(), [None], {}

mcp = MCPServer("LEGION Verify", version="1.3.0")
# Les 4 outils sont en LECTURE SEULE : aucun n'écrit ni n'achète ; verify_mcp_server délègue la sonde tools/list au service drift.
READ_NET = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
READ_OFFLINE = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


class ToolFail(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def _err(code, message):
    return {"ok": False, "error": {"code": code, "message": message}}


def _get(path, params=None, cache=False):
    """GET sur une route FIXE du journal public. Jamais d'URL fournie par l'appelant.
    cache=True (trousseau, tête) : réponse réutilisée CACHE_TTL s ; la vérification reste faite à chaque appel."""
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    if cache:
        with _LOCK:
            hit = _CACHE.get(url)
            if hit and time.monotonic() - hit[0] < CACHE_TTL:
                return hit[1]
    for attempt in (0, 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=20) as r:
                data = r.read(MAX_FETCH_BYTES + 1)
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 0:
                time.sleep(min(float(e.headers.get("Retry-After") or 2), 5))
                continue
            raise ToolFail("NOT_FOUND" if e.code == 404 else "UPSTREAM_HTTP_%d" % e.code, "journal : HTTP %d sur %s" % (e.code, path))
        except Exception as e:
            raise ToolFail("UPSTREAM_UNREACHABLE", "journal injoignable (%s)" % type(e).__name__)
    if len(data) > MAX_FETCH_BYTES:
        raise ToolFail("UPSTREAM_TOO_LARGE", "réponse du journal trop grande")
    if cache:
        with _LOCK:
            _CACHE[url] = (time.monotonic(), data)
    return data


def _lru_get(d, k):
    with _LOCK:
        if k in d:
            d.move_to_end(k)
            return d[k]
    return None


def _lru_put(d, k, v, cap):
    with _LOCK:
        d[k] = v
        d.move_to_end(k)
        while len(d) > cap:
            d.popitem(last=False)


def _client(ctx):
    """Identité du client pour le quota : IP posée par Cloudflare ; None en stdio (un seul utilisateur local)."""
    try:
        h = ctx.headers if ctx is not None else None
    except Exception:
        h = None
    if h is None:
        return None
    return (h.get("cf-connecting-ip") or "local").strip()[:64]


def _take_miss(client):
    """Réserve un appel vers le journal pour ce client ; False si son quota de la minute est atteint."""
    if client is None:
        return True
    now = time.monotonic()
    with _LOCK:
        q = [t for t in _MISSES.get(client, []) if now - t < 60]
        if len(q) >= CLIENT_MISS_PER_MIN:
            _MISSES[client] = q
            return False
        q.append(now)
        _MISSES[client] = q
        if len(_MISSES) > 50000:
            _MISSES.clear()
        return True


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
    keyring = _get("/keyring", cache=True).decode("utf-8")
    keys = _keys(keyring)
    head = json.loads(_get("/head", cache=True))
    return head["sth"], keys, keyring


@mcp.tool(annotations=READ_NET)
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


@mcp.tool(annotations=READ_NET)
def get_server_changes(server_id: StrictStr, limit: StrictInt = 10, ctx: Context = None) -> dict:
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
        client = _client(ctx)
        with _LOCK:
            if _SERVERS_HEAD[0] != size:                 # nouvelle tête signée : les historiques mémorisés sont périmés
                _SERVERS.clear()
                _SERVERS_HEAD[0] = size
        raw = _lru_get(_SERVERS, (server_id, size))
        if raw is None:
            if not _take_miss(client):
                return _err("CLIENT_RATE_LIMITED", "quota de %d requêtes/min vers le journal atteint pour ce client ; "
                            "réessayez dans une minute (les réponses déjà en cache restent servies)" % CLIENT_MISS_PER_MIN)
            raw = _get("/servers/" + urllib.parse.quote(server_id, safe="/@:"))
            _lru_put(_SERVERS, (server_id, size), raw, SERVERS_CACHE_MAX)
        srv = json.loads(raw)
        latest = srv.get("latest_record")
        if not isinstance(latest, dict):
            return _err("NOT_FOUND", "aucun enregistrement signé pour ce serveur")
        if latest["leaf_index"] >= size:
            return _err("NOT_YET_COVERED", "le dernier enregistrement n'est pas encore couvert par une tête signée")
        pk = (latest["leaf_index"], size)
        praw = _lru_get(_PROOFS, pk)
        if praw is None:
            if not _take_miss(client):
                return _err("CLIENT_RATE_LIMITED", "quota de %d requêtes/min vers le journal atteint pour ce client ; "
                            "réessayez dans une minute (les réponses déjà en cache restent servies)" % CLIENT_MISS_PER_MIN)
            praw = _get("/proof/inclusion", {"leaf_index": latest["leaf_index"], "tree_size": size})
            _lru_put(_PROOFS, pk, praw, PROOF_CACHE_MAX)
        proof = json.loads(praw)
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


@mcp.tool(annotations=READ_OFFLINE)
def verify_evidence_bundle(bundle: dict, approved_tools_sha256: StrictStr = "") -> dict:
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


DRIFT_BASE = os.environ.get("LEGION_DRIFT_BASE", "https://legion-api.com/drift").rstrip("/")   # la prod fixe http://127.0.0.1:8898 (drop-in systemd)
MAX_URL = 500
_SELF = {"ip": None, "checked": 0.0}


def _self_ip():
    """IP sortante de LEGION (cdn-cgi/trace, 30 min) : un appel venant de LEGION via le tunnel n'est pas un tiers."""
    if time.monotonic() - _SELF["checked"] > 1800 or not _SELF["checked"]:
        _SELF["checked"] = time.monotonic()
        try:
            txt = urllib.request.urlopen(urllib.request.Request("https://legion-api.com/cdn-cgi/trace", headers={"User-Agent": UA}),
                                         timeout=5).read().decode()
            _SELF["ip"] = next(l.split("=", 1)[1] for l in txt.splitlines() if l.startswith("ip="))
        except Exception:
            pass
    return _SELF["ip"]


def _third_party(client):
    """Tiers = client vu par Cloudflare (CF-Connecting-IP) différent de l'IP sortante de LEGION. stdio / local : jamais tiers."""
    return client not in (None, "local") and client != _self_ip()


def _valid_url(url):
    if not isinstance(url, str) or not 0 < len(url) <= MAX_URL or any(ord(c) < 33 or ord(c) == 127 for c in url):
        return False
    p = urllib.parse.urlsplit(url)
    return p.scheme in ("https", "http") and bool(p.hostname) and p.username is None and p.password is None


def _drift_verify(url, live, third_party):
    """GET sur la route FIXE /verify du service drift LEGION (loopback). L'URL n'est jamais récupérée par ce serveur :
    le service drift la résout dans le registre et ne sonde (initialize + tools/list) que des adresses publiques."""
    q = DRIFT_BASE + "/verify?" + urllib.parse.urlencode({"url": url, "live": 1 if live else 0})
    h = {"User-Agent": UA, "X-Legion-Via": "mcp"}
    if not third_party:
        h["X-Legion-Test"] = "1"          # le service drift ne compte alors pas l'appel comme tiers
    try:
        with urllib.request.urlopen(urllib.request.Request(q, headers=h), timeout=40) as r:
            data = r.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise ToolFail({400: "INVALID_URL", 429: "RATE_LIMITED"}.get(e.code, "UPSTREAM_HTTP_%d" % e.code),
                       "service drift : HTTP %d" % e.code)
    except Exception as e:
        raise ToolFail("UPSTREAM_UNREACHABLE", "service drift injoignable (%s)" % type(e).__name__)
    if len(data) > MAX_FETCH_BYTES:
        raise ToolFail("UPSTREAM_TOO_LARGE", "réponse du service drift trop grande")
    return json.loads(data)


@mcp.tool(annotations=READ_NET)
def verify_mcp_server(url: StrictStr, live: bool = True, ctx: Context = None) -> dict:
    """Check an MCP server URL against LEGION's signed transparency log. Read-only. For each registry server at this
    URL: latest signed tool definition (leaf index, date, tools_sha256), number of tool changes (total and 30 days),
    date of the last change, RFC 9162 inclusion proof + signed tree head (re-verified here from the pinned root key),
    an evidence bundle for `verify_evidence_bundle`, and — if live=true — whether the tool list served NOW differs from
    the signed one (live check by LEGION: initialize + tools/list only, public addresses only, NOT signed).
    A change is not a fault; history = what LEGION observed, not what other clients see."""
    if not _valid_url(url):
        return _err("INVALID_URL", "url : http(s)://hôte[/chemin], 1-%d caractères imprimables, sans identifiants" % MAX_URL)
    if not isinstance(live, bool):
        return _err("INVALID_LIVE", "live : booléen")
    try:
        client = _client(ctx)
        if not _take_miss(client):
            return _err("CLIENT_RATE_LIMITED", "quota de %d requêtes/min atteint pour ce client ; réessayez dans une minute"
                        % CLIENT_MISS_PER_MIN)
        v = _drift_verify(url, live, _third_party(client))
        _, keys, keyring = _head_and_keys()
        servers = []
        for s in v.get("servers", []):
            if not s.get("observed"):
                servers.append({"server_id": s.get("server_id"), "observed": False, "claim_state": "not_observed"})
                continue
            rec, proof, sth = s["record"], s["proof"], s["sth"]
            integ, sig, _ = T.check_record(rec, keys)
            checks = {"record_integrity": bool(integ), "record_signature": bool(sig), "head_signature": bool(T.check_sth(sth, keys)),
                      "inclusion": bool(T.check_inclusion(rec, proof, sth))}
            out = {"server_id": s["server_id"], "observed": True,
                   "latest_signed_definition": {k: s["latest_signed"].get(k) for k in ("leaf_index", "observed_at", "tools_sha256", "tool_count")},
                   "changes_total": s["changes_total"], "changes_30d": s["changes_30d"], "last_change_at": s["last_change_at"],
                   "first_observed_at": s["first_observed_at"],
                   "inclusion_proof": {"leaf_index": proof["leaf_index"], "tree_size": proof["tree_size"], "audit_path": proof["audit_path"]},
                   "signed_tree_head": sth, "evidence_checks": checks, "evidence_verified": all(checks.values()),
                   "evidence_bundle": {"record": rec, "proof": proof, "sth": sth, "keyring": keyring},
                   "claim_state": "verified_signed_observation" if all(checks.values()) else "evidence_rejected"}
            lv = s.get("live")
            if lv is not None:
                out["current_definition"] = {"status": lv.get("status"), "checked_at": lv.get("checked_at"),
                                             "tools_sha256": lv.get("tools_sha256"), "differs_from_signed": lv.get("differs_from_signed"),
                                             "diff": lv.get("diff"), "signed": False,
                                             "note": "checked now by LEGION, not signed; a difference is not a fault"}
            servers.append(out)
        return {"ok": True, "url": v.get("url"), "known_in_registry": v.get("known_in_registry"), "servers": servers,
                "root_pin_sha256": ROOT_PIN, "claim_state": "observed_by_legion",
                "note": "signed history = LEGION observations; current_definition is a live, unsigned check. A change is not a fault."}
    except ToolFail as e:
        return _err(e.code, e.message)
    except Exception as e:
        return _err("INTERNAL", type(e).__name__)


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
