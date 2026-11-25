#!/usr/bin/env python3
"""fake-openai-provider: a standard-library stand-in for an OpenAI-compatible
model provider, used only by the e2e scripts and tests. It serves
POST /v1/chat/completions (and a deterministic POST /v1/embeddings: equal text
gives an identical fixed-size vector, texts sharing words are closer, and the
input text is logged), requires a bearer token, answers every call with a
fixed --reply text, and appends one JSON line per request to --log so a test
can check exactly what reached it (path, bearer, model, header names, the
tool names offered). With --tool-script it also plays a tool-calling model:
a request that offers tools gets the scripted tool calls for its round — the
round is the number of assistant tool-call messages already in the
conversation, read from the request body, never from a call counter, so one
process can serve a parent's rounds and its children's plain calls at once —
and the fixed --reply once the script is exhausted; a request offering no
tools gets the plain --reply as before. With --delay it holds every
successful answer for that many seconds, so a test that must inspect a
caller's compartment while its call is in flight has time to. With one or more
--reply-for MODEL=TEXT it answers a call whose request names that model with
TEXT instead of --reply, so one process can play a classifier and an
answerer at once. It never contacts a real provider
and holds no real credential.
"""
import argparse
import hashlib
import json
import math
import os
import socketserver
import sys
import time
from http.server import BaseHTTPRequestHandler

ROUTE = "/v1/chat/completions"
EMBEDDINGS_ROUTE = "/v1/embeddings"
EMBEDDING_DIM = 512


# Words that carry no topic (and the boilerplate every sample note shares) are
# dropped, so retrieval is decided by content words alone.
STOPWORDS = frozenset("""a an and are as at be been but by can do does for from had has have how i if in is it
its of on or so than that the their then there these they this to was we were what when which who will with
meeting notes attendees action items dana example com""".split())


def embed(text):
    """A deterministic embedding of text: EMBEDDING_DIM non-negative floats,
    unit length. Each content token (lower-cased alphanumeric run, not a
    stopword, a trailing plural 's' stripped) adds weight to a few
    hash-chosen dimensions, so equal text gives a byte-identical vector and
    texts sharing content words are closer than unrelated ones: a
    nearest-neighbour search selects the matching chunk. Text with no content
    token maps to a fixed unit vector."""
    vec = [0.0] * EMBEDDING_DIM
    token = []
    for ch in text.lower() + " ":
        if ch.isalnum():
            token.append(ch)
            continue
        if token:
            word = "".join(token)
            token = []
            if word in STOPWORDS:
                continue
            if len(word) > 3 and word.endswith("s"):
                word = word[:-1]
            digest = hashlib.sha256(word.encode()).digest()
            for k in range(2):
                vec[int.from_bytes(digest[2 * k:2 * k + 2], "big") % EMBEDDING_DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0:
        vec[0] = 1.0
        return vec
    return [round(v / norm, 8) for v in vec]


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

    def _embeddings(self, auth, body):
        raw = body.get("input")
        texts = raw if isinstance(raw, list) else [raw]
        if not texts or not all(isinstance(t, str) for t in texts):
            self._send(400, {"error": {"message": "input must be a string or a list of strings"}})
            return
        opts = self.server.opts
        if opts.log:
            record = {
                "path": self.path,
                "authorization": auth,
                "model": body.get("model"),
                "input": raw,
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
            "object": "list",
            "data": [{"object": "embedding", "index": i, "embedding": embed(t)} for i, t in enumerate(texts)],
            "model": body.get("model") or "fake",
            "usage": {"prompt_tokens": 3, "total_tokens": 3},
        })

    def do_POST(self):
        if self.path not in (ROUTE, EMBEDDINGS_ROUTE):
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
        body = req if isinstance(req, dict) else {}
        if self.path == EMBEDDINGS_ROUTE:
            self._embeddings(auth, body)
            return
        messages = body.get("messages") if isinstance(body.get("messages"), list) else []
        tools = body.get("tools") if isinstance(body.get("tools"), list) else []
        tool_names = [t["function"].get("name") if isinstance(t.get("function"), dict) else None
                      for t in tools if isinstance(t, dict)]
        rounds_done = sum(1 for m in messages
                          if isinstance(m, dict) and m.get("role") == "assistant" and m.get("tool_calls"))
        if opts.log:
            record = {
                "path": self.path,
                "authorization": auth,
                "model": body.get("model"),
                "messages": body.get("messages"),
                "headers": sorted(k.lower() for k in self.headers.keys()),
                "tools": tool_names,
                "tool_rounds": rounds_done,
            }
            with open(opts.log, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        if not auth.startswith("Bearer "):
            self._send(401, {"error": {"message": "missing bearer"}})
            return
        if opts.status != 200:
            self._send(opts.status, {"error": {"message": "fake provider refused"}})
            return
        script = self.server.tool_script
        if tools and script is not None and rounds_done < len(script):
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_%d_%d" % (rounds_done, i), "type": "function",
                 "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}}
                for i, c in enumerate(script[rounds_done])]}
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": self.server.replies.get(body.get("model"), opts.reply)}
            finish = "stop"
        if opts.delay > 0:
            time.sleep(opts.delay)
        self._send(200, {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "created": 0,
            "model": body.get("model") or "fake",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
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
    p.add_argument("--reply-for", action="append", default=[], metavar="MODEL=TEXT",
                   help="answer a call naming MODEL with TEXT instead of --reply (repeatable)")
    p.add_argument("--status", type=int, default=200, help="HTTP status to answer with; non-200 simulates a refusal")
    p.add_argument("--tool-script", help="JSON file {\"rounds\": [[{\"name\", \"arguments\"}, ...], ...]}: play a tool-calling model for requests that offer tools")
    p.add_argument("--delay", type=float, default=0.0,
                   help="hold every 200 answer this many seconds before sending it (keeps a caller's compartment alive for inspection)")
    return p.parse_args(argv)


def load_tool_script(path):
    """The rounds of a tool script, validated: a list of non-empty lists of
    {"name": str, "arguments": object}. Anything else is a usage error."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    rounds = doc.get("rounds") if isinstance(doc, dict) else None
    if not isinstance(rounds, list):
        raise ValueError("--tool-script: expected an object with a \"rounds\" list")
    for r, calls in enumerate(rounds):
        if not isinstance(calls, list) or not calls:
            raise ValueError("--tool-script: round %d is not a non-empty list" % r)
        for c in calls:
            if not isinstance(c, dict) or not isinstance(c.get("name"), str) or not isinstance(c.get("arguments"), dict):
                raise ValueError("--tool-script: round %d has a call without a string name and an object arguments" % r)
    return rounds


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
    srv.tool_script = None
    srv.replies = {}
    for item in opts.reply_for:
        model, sep, text = item.partition("=")
        if not sep or not model:
            raise SystemExit("fake-provider: --reply-for expects MODEL=TEXT")
        srv.replies[model] = text
    return srv, listening


def main(argv=None):
    opts = parse_args(argv)
    srv, listening = make_server(opts)
    if opts.tool_script:
        try:
            srv.tool_script = load_tool_script(opts.tool_script)
        except (OSError, ValueError) as exc:
            sys.stderr.write("fake-provider: %s\n" % exc)
            srv.server_close()
            return 2
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
