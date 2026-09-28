#!/usr/bin/env python3
"""fake-openai-provider: a standard-library stand-in for an OpenAI-compatible
model provider, used only by the e2e scripts and tests. It serves
POST /v1/chat/completions, requires a bearer token, answers every call with a
fixed --reply text, and appends one JSON line per request to --log so a test
can check exactly what reached it (path, bearer, model, header names). It
never contacts a real provider and holds no real credential.
"""
import argparse
import json
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler

ROUTE = "/v1/chat/completions"


class Handler(BaseHTTPRequestHandler):
    def address_string(self):
        # A Unix-socket peer has no host:port; BaseHTTPRequestHandler's default
        # indexes client_address[0], which fails on the '' a Unix peer gets.
        return self.client_address[0] if isinstance(self.client_address, tuple) else "unix"

    def log_message(self, fmt, *args):
        sys.stderr.write("fake-provider: " + (fmt % args) + "\n")

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != ROUTE:
            self._send(404, {"error": {"message": "not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(400, {"error": {"message": "bad request"}})
            return
        try:
            req = json.loads(self.rfile.read(length))
        except ValueError:
            self._send(400, {"error": {"message": "bad request"}})
            return
        auth = self.headers.get("Authorization", "")
        opts = self.server.opts
        if opts.log:
            record = {
                "path": self.path,
                "authorization": auth,
                "model": req.get("model") if isinstance(req, dict) else None,
                "messages": req.get("messages") if isinstance(req, dict) else None,
                "headers": sorted(k.lower() for k in self.headers.keys()),
            }
            with open(opts.log, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        if not auth.startswith("Bearer "):
            self._send(401, {"error": {"message": "missing bearer"}})
            return
        if opts.status != 200:
            self._send(opts.status, {"error": {"message": "fake provider refused"}})
            return
        self._send(200, {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "created": 0,
            "model": (req.get("model") if isinstance(req, dict) else None) or "fake",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": opts.reply},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8},
        })


class _Threaded(socketserver.ThreadingMixIn):
    daemon_threads = True


class TCPProvider(_Threaded, socketserver.TCPServer):
    allow_reuse_address = True


class UnixProvider(_Threaded, socketserver.UnixStreamServer):
    pass


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument("--bind", help="TCP host:port to listen on (port 0 picks a free one)")
    where.add_argument("--unix", help="Unix socket path to listen on")
    p.add_argument("--reply", default="fake reply", help="assistant content returned on every call")
    p.add_argument("--log", help="append one JSON line per request to this file")
    p.add_argument("--status", type=int, default=200, help="HTTP status to answer with; non-200 simulates a refusal")
    return p.parse_args(argv)


def make_server(opts):
    if opts.unix:
        try:
            os.unlink(opts.unix)
        except FileNotFoundError:
            pass
        srv = UnixProvider(opts.unix, Handler)
        listening = "unix:" + opts.unix
    else:
        host, _, port = opts.bind.rpartition(":")
        srv = TCPProvider((host, int(port)), Handler)
        listening = "%s:%d" % srv.server_address[:2]
    srv.opts = opts
    return srv, listening


def main(argv=None):
    opts = parse_args(argv)
    srv, listening = make_server(opts)
    print(json.dumps({"listening": listening}), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        if opts.unix:
            try:
                os.unlink(opts.unix)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
