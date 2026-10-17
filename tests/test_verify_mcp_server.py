#!/usr/bin/env python3
"""Tests (+/-) de l'outil MCP verify_mcp_server (branche feat/verify-mcp-server, NON déployée).

Un service drift de TEST (create_app de ~/legion-mcp-tlog/drift, base d'état temporaire) écoute sur un port loopback libre ;
le journal est lu en GET sur le service local 127.0.0.1:8897 (lecture seule). Aucune donnée de prod n'est écrite.
  python3 tests/test_verify_mcp_server.py
"""
import copy
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DRIFT = os.path.expanduser("~/legion-mcp-tlog/drift")
TLOG_BASE = os.environ.get("TEST_TLOG_BASE", "http://127.0.0.1:8897/tlog/v0")
RES = []


def check(name, cond, detail=""):
    RES.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> %s" % str(detail)[:300]))


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def start_drift(tmp, port):
    code = ("import sys,uvicorn;sys.path.insert(0,%r);import drift_service as D;"
            "svc=D.Service(state_db=%r,alerts_log=%r);uvicorn.run(D.create_app(svc),host='127.0.0.1',port=%d,log_level='warning')"
            % (DRIFT, os.path.join(tmp, "drift.db"), os.path.join(tmp, "alerts.log"), port))
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=open(os.path.join(tmp, "drift.err"), "w"))
    for _ in range(240):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return p
        except OSError:
            time.sleep(0.5)
    p.kill()
    raise RuntimeError("service drift de test non démarré : " + open(os.path.join(tmp, "drift.err")).read()[-400:])


class Stdio:
    """Vrai client JSON-RPC MCP sur stdio."""
    def __init__(self, env):
        self.p = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, cwd=ROOT, env=env)
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}})
        self.rpc("notifications/initialized", notify=True)

    def rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
        if not notify:
            self.n += 1; msg["id"] = self.n
        self.p.stdin.write(json.dumps(msg) + "\n"); self.p.stdin.flush()
        if notify:
            return None
        while True:
            r = json.loads(self.p.stdout.readline())
            if r.get("id") == self.n:
                return r

    def call(self, name, args):
        res = self.rpc("tools/call", {"name": name, "arguments": args})["result"]
        sc = res.get("structuredContent")
        if isinstance(sc, dict) and set(sc) == {"result"}:
            sc = sc["result"]
        if sc is None:
            txt = res["content"][0]["text"] if res.get("content") else ""
            try:
                sc = json.loads(txt)
            except ValueError:
                sc = {"_isError": txt[:200]}
        return sc

    def close(self):
        self.p.stdin.close(); self.p.wait(timeout=10)


class Ctx:
    def __init__(self, ip):
        self.headers = {"cf-connecting-ip": ip} if ip else {}


def counters(db):
    c = sqlite3.connect(db)
    r = dict(((n, e), v) for n, e, v in c.execute("SELECT name, external, sum(n) FROM counters GROUP BY 1, 2"))
    c.close()
    return r


def main():
    tmp = tempfile.mkdtemp(prefix="vms_")
    port = free_port()
    drift = start_drift(tmp, port)
    env = dict(os.environ, LEGION_DRIFT_BASE="http://127.0.0.1:%d" % port, LEGION_TLOG_BASE=TLOG_BASE)
    os.environ.update(LEGION_DRIFT_BASE=env["LEGION_DRIFT_BASE"], LEGION_TLOG_BASE=TLOG_BASE)
    sys.path.insert(0, ROOT); sys.path.insert(0, DRIFT)
    import server as S
    import drift_service as D
    try:
        # cible : dernier serveur « changed » du journal ayant une URL au registre (même choix que les tests drift)
        J = D.Journal(D.DEFAULTS["data"]); J.refresh()
        reg = D.Registry(D.DEFAULTS["registry"]); reg.refresh()
        url_of = {}
        for u, ids in reg.by_url.items():
            for s in ids:
                url_of.setdefault(s, u)
        N = J.latest_size()
        tgt = next(r for r in reversed(J.records[:N]) if (r.get("change") or {}).get("kind") == "changed" and r["server_id"] in url_of)
        sid, url = tgt["server_id"], url_of[tgt["server_id"]]
        print("cible : %s (%s), tête %d" % (sid, url, N))

        # mise en chauffe : le 1er /verify d'un service drift neuf recharge et revérifie tout le journal (le service de prod est chaud)
        import urllib.parse, urllib.request
        t0 = time.time()
        urllib.request.urlopen(env["LEGION_DRIFT_BASE"] + "/verify?" + urllib.parse.urlencode({"url": url, "live": 0}),
                               timeout=600).read()
        print("   chauffe du service drift de test : %.1f s" % (time.time() - t0))

        # ---- bout en bout sur stdio
        C = Stdio(env)
        tools = {t["name"]: t for t in C.rpc("tools/list", {})["result"]["tools"]}
        check("tools/list : 5 outils dont verify_mcp_server et check_mcp_server", len(tools) == 5 and "verify_mcp_server" in tools and "check_mcp_server" in tools, list(tools))
        ann = (tools.get("verify_mcp_server") or {}).get("annotations") or {}
        check("verify_mcp_server annoncé en lecture seule, non destructif", ann.get("readOnlyHint") is True and ann.get("destructiveHint") is False, ann)

        v = C.call("verify_mcp_server", {"url": url, "live": False})
        s0 = next((s for s in v.get("servers", []) if s.get("server_id") == sid), {})
        check("URL connue -> ok, serveur observé", v.get("ok") and s0.get("observed"), str(v)[:300])
        last_leaf = max(i for i in J.by_server[sid] if i < N)
        check("dernière définition signée = dernière feuille du serveur sous la tête", s0.get("latest_signed_definition", {}).get("leaf_index") == last_leaf,
              (s0.get("latest_signed_definition"), last_leaf))
        nchg = sum(1 for i in J.by_server[sid] if i < N and (J.records[i].get("change") or {}).get("kind") == "changed")
        check("nombre de changements = journal (%d)" % nchg, s0.get("changes_total") == nchg, s0.get("changes_total"))
        lastc = max(J.records[i]["observed_at"] for i in J.by_server[sid] if i < N and (J.records[i].get("change") or {}).get("kind") == "changed")
        check("date du dernier changement = journal", s0.get("last_change_at") == lastc, (s0.get("last_change_at"), lastc))
        check("preuve d'inclusion + tête signée revérifiées par l'outil", s0.get("evidence_verified") is True and all(s0.get("evidence_checks", {}).values()),
              s0.get("evidence_checks"))
        check("tête signée retournée avec racine", len(((s0.get("signed_tree_head") or {}).get("tree_head") or {}).get("root_sha256", "")) == 64)
        b = C.call("verify_evidence_bundle", {"bundle": s0.get("evidence_bundle")})
        check("paquet de preuve accepté HORS LIGNE par verify_evidence_bundle", b.get("ok") is True, b)
        check("live=false -> aucune définition actuelle annoncée", "current_definition" not in s0)

        t0 = time.time()
        vl = C.call("verify_mcp_server", {"url": url, "live": True})
        cd = next((s for s in vl.get("servers", []) if s.get("server_id") == sid), {}).get("current_definition") or {}
        check("live=true -> définition actuelle sondée, non signée, différence explicite",
              cd.get("status") and cd.get("signed") is False and "differs_from_signed" in cd and
              (cd.get("status") != "ok" or isinstance(cd.get("differs_from_signed"), bool)), cd)
        print("   live :", {k: cd.get(k) for k in ("status", "differs_from_signed", "diff")}, "%.1fs" % (time.time() - t0))

        # ---- négatifs
        for bad, lab in (("ftp://exemple.org/mcp", "schéma ftp"), ("https://user:pw@exemple.org/mcp", "identifiants dans l'URL"),
                         ("https://exemple.org/" + "a" * 600, "URL > 500 caractères"), ("https://exe mple.org/", "espace"),
                         ("pas une url", "texte libre"), ("", "vide")):
            r = C.call("verify_mcp_server", {"url": bad})
            check("URL invalide (%s) -> INVALID_URL" % lab, r.get("ok") is False and r["error"]["code"] == "INVALID_URL", r)
        r = C.call("verify_mcp_server", {"url": "https://exemple.invalid/mcp", "live": False})
        check("URL hors registre -> ok, known_in_registry=false, aucun serveur", r.get("ok") and r.get("known_in_registry") is False and r.get("servers") == [], r)
        C.close()

        # ---- preuve falsifiée (réponse amont modifiée) -> rejetée
        real = S._drift_verify
        def forged(u, live, tp):
            d = real(u, live, tp)
            for s in d.get("servers", []):
                if s.get("observed"):
                    s["record"] = copy.deepcopy(s["record"]); s["record"]["observed_at"] = "2020-01-01T00:00:00Z"
            return d
        S._drift_verify = forged
        r = S.verify_mcp_server(url, live=False, ctx=None)
        sf = next((s for s in r.get("servers", []) if s.get("observed")), {})
        check("enregistrement modifié -> evidence_verified=false, evidence_rejected", sf.get("evidence_verified") is False and sf.get("claim_state") == "evidence_rejected",
              sf.get("evidence_checks"))
        def forged_path(u, live, tp):
            d = real(u, live, tp)
            for s in d.get("servers", []):
                if s.get("observed") and s["proof"]["audit_path"]:
                    s["proof"]["audit_path"][0] = "00" * 32
            return d
        S._drift_verify = forged_path
        r = S.verify_mcp_server(url, live=False, ctx=None)
        sf = next((s for s in r.get("servers", []) if s.get("observed")), {})
        check("chemin d'audit modifié -> inclusion refusée", sf.get("evidence_checks", {}).get("inclusion") is False, sf.get("evidence_checks"))
        S._drift_verify = real

        # ---- service drift injoignable
        S.DRIFT_BASE = "http://127.0.0.1:%d" % free_port()
        r = S.verify_mcp_server(url, live=False, ctx=None)
        check("service drift injoignable -> UPSTREAM_UNREACHABLE (pas d'exception)", r.get("ok") is False and r["error"]["code"] == "UPSTREAM_UNREACHABLE", r)
        S.DRIFT_BASE = env["LEGION_DRIFT_BASE"]

        # ---- compteur d'appels tiers (base drift de TEST)
        db = os.path.join(tmp, "drift.db")
        S._SELF.update(ip="198.51.100.7", checked=time.monotonic())        # IP sortante simulée de LEGION
        c0 = counters(db)
        S.verify_mcp_server(url, live=False, ctx=None)                       # stdio
        S.verify_mcp_server(url, live=False, ctx=Ctx(None))                  # http local sans Cloudflare
        S.verify_mcp_server(url, live=False, ctx=Ctx("198.51.100.7"))        # LEGION via le tunnel
        c1 = counters(db)
        check("appels stdio / local / LEGION -> 0 appel tiers compté", c1.get(("verify_mcp", 1), 0) == c0.get(("verify_mcp", 1), 0), (c0, c1))
        S.verify_mcp_server(url, live=False, ctx=Ctx("203.0.113.9"))         # tiers (TEST-NET-3)
        c2 = counters(db)
        check("appel d'un tiers -> +1 appel tiers compté", c2.get(("verify_mcp", 1), 0) == c1.get(("verify_mcp", 1), 0) + 1, (c1, c2))
    finally:
        drift.terminate()
        try:
            drift.wait(timeout=10)
        except Exception:
            drift.kill()
    print("%d/%d" % (sum(RES), len(RES)))
    return 0 if all(RES) else 1


if __name__ == "__main__":
    sys.exit(main())
