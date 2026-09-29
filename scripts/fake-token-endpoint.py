#!/usr/bin/env python3
"""fake-token-endpoint: a standard-library stand-in for an OAuth 2.0 token
endpoint (client_credentials grant, client_secret_basic), used only by the
e2e scripts. Every POST /token mints a NEW token "tok-<n>-<hex>" with the
configured --lifetime as expires_in, and appends one JSON line per mint to
--log so a test can check exactly which tokens were issued and in what order.
It validates nothing beyond the request shape and holds no real credential.
"""
import argparse
import base64
import json
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("fake-token-endpoint: " + (fmt % args) + "\n")

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/token":
            self._send(404, {"error": "not found"})
            return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self._send(401, {"error": "invalid_client"})
            return
        try:
            client_id = unquote(base64.b64decode(auth[6:]).decode().split(":", 1)[0])
        except (ValueError, UnicodeDecodeError):
            self._send(401, {"error": "invalid_client"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(400, {"error": "invalid_request"})
            return
        form = parse_qs(self.rfile.read(length).decode())
        if form.get("grant_type") != ["client_credentials"]:
            self._send(400, {"error": "unsupported_grant_type"})
            return
        opts = self.server.opts
        self.server.minted += 1
        token = "tok-%d-%s" % (self.server.minted, os.urandom(4).hex())
        if opts.log:
            with open(opts.log, "a", encoding="utf-8") as f:
                f.write(json.dumps({"token": token, "client_id": client_id}) + "\n")
        self._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": opts.lifetime})


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bind", required=True, help="TCP host:port to listen on (port 0 picks a free one)")
    p.add_argument("--lifetime", type=int, default=60, help="expires_in returned with every token")
    p.add_argument("--log", help="append one JSON line per minted token to this file")
    return p.parse_args(argv)


def main(argv=None):
    opts = parse_args(argv)
    host, _, port = opts.bind.rpartition(":")
    srv = Server((host, int(port)), Handler)
    srv.opts = opts
    srv.minted = 0
    print(json.dumps({"listening": "%s:%d" % srv.server_address[:2]}), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
