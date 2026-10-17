"""Tests de bout en bout du serveur MCP « LEGION Verify » : un VRAI client JSON-RPC parle au serveur sur stdio.
  python3 tests/test_mcp_verify.py            (réseau requis pour get_checkpoint / get_server_changes : journal public)
Le paquet de preuve obtenu est sauvé dans tests/out/bundle.json pour le test hors ligne (unshare -rn)."""
import copy
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(os.path.dirname(HERE), "server.py")
OUT = os.path.join(HERE, "out")
SERVER_ID = os.environ.get("TEST_SERVER_ID", "xyz.signomy/civitae")
OFFLINE = os.environ.get("TEST_OFFLINE") == "1"


class Client:
    def __init__(self):
        self.p = subprocess.Popen([sys.executable, SRV], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, cwd=os.path.dirname(SRV))
        self.n = 0

    def rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self.n += 1
            msg["id"] = self.n
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("serveur arrêté : " + self.p.stderr.read()[-500:])
            r = json.loads(line)
            if r.get("id") == self.n:
                return r

    def call(self, name, args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        if "error" in r:
            return {"_jsonrpc_error": r["error"]}
        res = r["result"]
        sc = res.get("structuredContent")
        if isinstance(sc, dict) and set(sc) == {"result"}:
            sc = sc["result"]
        if sc is None:
            sc = json.loads(res["content"][0]["text"]) if res.get("content") and not res.get("isError") else {"_isError": res}
        return sc

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


C = None
BUNDLE = None


def setUpModule():
    global C
    C = Client()
    r = C.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "legion-test", "version": "0"}})
    assert r["result"]["serverInfo"]["name"] == "LEGION Verify", r
    C.rpc("notifications/initialized", notify=True)


def tearDownModule():
    C.close()


def bundle():
    global BUNDLE
    if BUNDLE is None:
        if OFFLINE:
            with open(os.path.join(OUT, "bundle.json")) as f:
                BUNDLE = json.load(f)
        else:
            r = C.call("get_server_changes", {"server_id": SERVER_ID, "limit": 5})
            assert r.get("ok"), r
            BUNDLE = r
            os.makedirs(OUT, exist_ok=True)
            with open(os.path.join(OUT, "bundle.json"), "w") as f:
                json.dump(r, f)
    return BUNDLE


class T1_Protocol(unittest.TestCase):
    def test_tools_list_exactly_five(self):
        names = sorted(t["name"] for t in C.rpc("tools/list")["result"]["tools"])
        self.assertEqual(names, ["check_mcp_server", "get_checkpoint", "get_server_changes", "verify_evidence_bundle", "verify_mcp_server"])

    def test_removed_tools_are_unreachable(self):
        for name, args in [("notarize", {"sha256": "0" * 64}), ("scan_n8n", {"target": "http://example.com"}),
                           ("get_gpu_decision", {})]:
            r = C.call(name, args)
            self.assertTrue("_jsonrpc_error" in r or "_isError" in r, (name, r))

    def test_verify_mcp_server_never_probes_unlisted_url(self):
        # v1.3.0 : l'URL est seulement cherchée dans le registre ; une adresse hors registre (métadonnées cloud) n'est jamais sondée
        r = C.call("verify_mcp_server", {"url": "http://169.254.169.254/", "live": True})
        if "_jsonrpc_error" in r or "_isError" in r:
            return          # refus en amont : acceptable
        self.assertFalse(r.get("known_in_registry"), r)
        self.assertEqual(r.get("servers"), [], r)


@unittest.skipIf(OFFLINE, "réseau requis")
class T2_Online(unittest.TestCase):
    def test_checkpoint(self):
        r = C.call("get_checkpoint", {})
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["signature_valid"])
        self.assertGreater(r["tree_size"], 0)

    def test_server_changes(self):
        b = bundle()
        self.assertGreaterEqual(b["changes_total"], 1)
        self.assertLessEqual(len(b["changes"]), 5)
        self.assertEqual(set(b["evidence_bundle"]), {"record", "proof", "sth", "keyring"})

    def test_invalid_params(self):
        for sid in ["../../etc/passwd", "http://evil.example/x", "a" * 201, "", "x/../y", "a b", "a/b/c/d/e/f"]:
            self.assertEqual(C.call("get_server_changes", {"server_id": sid})["error"]["code"], "INVALID_SERVER_ID", sid)
        for lim in [0, 51, 10 ** 9, -1]:
            self.assertEqual(C.call("get_server_changes", {"server_id": SERVER_ID, "limit": lim})["error"]["code"], "INVALID_LIMIT")

    def test_unknown_server(self):
        self.assertEqual(C.call("get_server_changes", {"server_id": "zz.legion-test/does-not-exist"})["error"]["code"], "NOT_FOUND")


class T3_Verify(unittest.TestCase):
    def eb(self):
        return copy.deepcopy(bundle()["evidence_bundle"])

    def v(self, b, approved=""):
        return C.call("verify_evidence_bundle", {"bundle": b, "approved_tools_sha256": approved} if approved else {"bundle": b})

    def test_valid_bundle(self):
        r = self.v(self.eb())
        self.assertTrue(r["ok"], r)
        self.assertTrue(all(r["checks"].values()))

    def test_approved_match_and_unapproved_change(self):
        b = self.eb()
        self.assertEqual(self.v(b, b["record"]["tools_fingerprint"]["sha256"])["approval"], "MATCHES_APPROVED")
        old = [c["tools_sha256"] for c in bundle()["changes"] if c["tools_sha256"] != b["record"]["tools_fingerprint"]["sha256"]]
        other = old[0] if old else "0" * 64
        self.assertEqual(self.v(b, other)["approval"], "UNAPPROVED_CHANGE")

    def test_tampered_tools_fingerprint(self):
        b = self.eb(); b["record"]["tools_fingerprint"]["sha256"] = "0" * 64
        r = self.v(b); self.assertFalse(r["ok"]); self.assertFalse(r["checks"]["record_signature"])

    def test_tampered_server_id(self):
        b = self.eb(); b["record"]["server_id"] += "-x"
        self.assertFalse(self.v(b)["ok"])

    def test_tampered_inclusion_path(self):
        b = self.eb(); p = b["proof"]["audit_path"]; p[0] = ("0" if p[0][0] != "0" else "1") + p[0][1:]
        r = self.v(b); self.assertFalse(r["ok"]); self.assertFalse(r["checks"]["inclusion"])

    def test_tampered_head(self):
        b = self.eb(); b["sth"]["tree_head"]["root_sha256"] = "0" * 64
        r = self.v(b); self.assertFalse(r["ok"]); self.assertFalse(r["checks"]["head_signature"])

    def test_foreign_keyring(self):
        b = self.eb(); lines = b["keyring"].splitlines(); e0 = json.loads(lines[0])
        e0["public_key_b64"] = __import__("base64").b64encode(os.urandom(32)).decode()  # != racine
        lines[0] = json.dumps(e0); b["keyring"] = "\n".join(lines)
        self.assertEqual(self.v(b)["error"]["code"], "KEYRING_ROOT_MISMATCH")

    def test_truncated_keyring_drops_signer(self):
        b = self.eb(); b["keyring"] = b["keyring"].splitlines()[0]
        r = self.v(b)
        signer = b["record"]["key_id"]
        if signer == "a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036":
            self.skipTest("feuille signée par la racine")
        self.assertFalse(r["ok"])

    def test_bad_inputs(self):
        self.assertEqual(self.v({"record": {}})["error"]["code"], "INVALID_BUNDLE")
        big = self.eb(); big["pad"] = "x" * (300 * 1024)
        self.assertEqual(self.v(big)["error"]["code"], "BUNDLE_TOO_LARGE")
        self.assertEqual(self.v(self.eb(), "XYZ")["error"]["code"], "INVALID_APPROVED_SHA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
