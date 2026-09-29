"""Tests for scripts/fake-token-endpoint.py (run: python -m unittest discover -s scripts -p 'test_*.py')."""
import base64
import http.client
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ENDPOINT = Path(__file__).resolve().with_name("fake-token-endpoint.py")


def start(*args):
    proc = subprocess.Popen([sys.executable, str(ENDPOINT), *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    listening = json.loads(proc.stdout.readline())["listening"]
    proc.stdout.close()
    return proc, listening


def post(listening, path, body, headers):
    host, _, port = listening.rpartition(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    hdrs.update(headers)
    conn.request("POST", path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()
    return resp.status, data


BASIC = {"Authorization": "Basic " + base64.b64encode(b"cid:csecret").decode()}


class FakeTokenEndpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "tokens.jsonl")
        self.proc, self.listening = start("--bind", "127.0.0.1:0", "--lifetime", "10", "--log", self.log)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()
        self.tmp.cleanup()

    def test_each_mint_is_a_new_token_with_the_lifetime(self):
        s1, t1 = post(self.listening, "/token", "grant_type=client_credentials", BASIC)
        s2, t2 = post(self.listening, "/token", "grant_type=client_credentials", BASIC)
        self.assertEqual((s1, s2), (200, 200))
        self.assertEqual(t1["token_type"], "Bearer")
        self.assertEqual(t1["expires_in"], 10)
        self.assertNotEqual(t1["access_token"], t2["access_token"])
        with open(self.log, encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual([l["token"] for l in lines], [t1["access_token"], t2["access_token"]])
        self.assertEqual(lines[0]["client_id"], "cid")

    def test_missing_basic_auth_is_401(self):
        status, body = post(self.listening, "/token", "grant_type=client_credentials", {})
        self.assertEqual((status, body), (401, {"error": "invalid_client"}))

    def test_wrong_grant_is_400(self):
        status, body = post(self.listening, "/token", "grant_type=password", BASIC)
        self.assertEqual((status, body), (400, {"error": "unsupported_grant_type"}))

    def test_other_path_is_404(self):
        status, _ = post(self.listening, "/oauth", "grant_type=client_credentials", BASIC)
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
