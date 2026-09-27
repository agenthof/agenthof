#!/usr/bin/env python3
"""A minimal Agenthof fronted agent, in Python, with no third-party dependencies.

Agenthof reaches an agent as an external HTTP service and POSTs one JSON step per
workflow step. This agent implements that contract with the standard library only,
so it runs under any Python 3.8+ with no `pip install`.

By default it echoes the step input back as its artifact (like the Go `echo-agent`),
so it runs hermetically with no model backend. With `--call-model` it makes one model
call through Agenthof's model gateway, using the per-step proxy coordinates in the
request headers — it never holds a provider key.

Run it on the address the example config points agents at:

    python3 examples/python-agent/agent.py            # echo mode, 127.0.0.1:8080

Then, from the repository root, the usual quickstart works unchanged:

    ./agenthof apply --as you@example.com --config examples/config
    ./agenthof run software-engineer fix-bug --input "fix the login bug" \\
        --as you@example.com --config examples/config
    ./agenthof audit <run-id>

The wire contract this file implements is documented in docs/agent-protocol.md.
"""

import argparse
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1 << 20  # 1 MiB, matching the Go examples' cap.


class Config:
    """Runtime options shared with the request handler."""

    def __init__(self, call_model: bool, model: str) -> None:
        self.call_model = call_model
        self.model = model


def make_handler(cfg: Config):
    class StepHandler(BaseHTTPRequestHandler):
        # Silence the default per-request stderr logging; the agent is quiet.
        def log_message(self, *_args) -> None:  # noqa: D401
            pass

        def do_POST(self) -> None:  # noqa: N802 (name fixed by BaseHTTPRequestHandler)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._reply(success=False, reason="request too large")
                return
            try:
                step = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self.send_error(400, "bad request")
                return

            # The step request: {"input": str, "artifacts": {..}, "agent": str}.
            step_input = step.get("input", "")

            if not cfg.call_model:
                # Echo mode: the input becomes the artifact. No credentials, no gateway.
                self._reply(artifact=step_input, success=True)
                return

            # Model mode: call the model gateway named by the per-step headers.
            proxy_url = self.headers.get("X-Agenthof-Proxy-URL", "")
            run_token = self.headers.get("X-Agenthof-Run-Token", "")
            if not proxy_url or not run_token:
                self._reply(success=False, reason="model proxy coordinates missing")
                return
            try:
                reply = call_model_gateway(proxy_url, run_token, cfg.model, step_input)
            except Exception:  # noqa: BLE001 — report a fixed reason, never leak details.
                self._reply(success=False, reason="model proxy request failed")
                return
            self._reply(artifact=reply, success=True)

        def _reply(self, artifact: str = "", success: bool = False, reason: str = "") -> None:
            body = {"artifact": artifact, "success": success}
            if reason:
                body["reason"] = reason
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return StepHandler


def call_model_gateway(proxy_url: str, run_token: str, model: str, content: str) -> str:
    """POST one OpenAI-style chat completion to the gateway; return the reply text.

    The agent authenticates to the gateway with the per-run token only. Agenthof
    injects the real provider key upstream — this process never sees it.

    Only the TCP form of the proxy URL (http://host:port) is handled here; a
    unix:// proxy URL (used inside refbox) needs a socket-dialing transport, which
    the stdlib urllib does not provide out of the box.
    """
    endpoint = proxy_url.rstrip("/") + "/v1/chat/completions"
    payload = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": content}]}
    ).encode()
    req = urllib.request.Request(endpoint, data=payload, method="POST")
    req.add_header("Authorization", "Bearer " + run_token)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310 (trusted local gateway)
        parsed = json.loads(resp.read(MAX_BODY))
    return parsed["choices"][0]["message"]["content"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal Agenthof fronted agent (Python).")
    parser.add_argument("--addr", default="127.0.0.1:8080", help="host:port to listen on")
    parser.add_argument(
        "--call-model",
        action="store_true",
        help="make one model call through the gateway instead of echoing",
    )
    parser.add_argument(
        "--model", default="fast", help="logical model name declared for this agent"
    )
    args = parser.parse_args()

    host, _, port = args.addr.rpartition(":")
    cfg = Config(call_model=args.call_model, model=args.model)
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(cfg))
    mode = "model" if args.call_model else "echo"
    print(f"python-agent listening on {args.addr} ({mode} mode)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
