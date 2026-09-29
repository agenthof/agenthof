# refbridge — a stdio MCP server, governed

`refbridge` fronts a stdio-only MCP server so Agenthof's tool door can govern
it. Agenthof reaches the bridge over a Unix socket (`url: unix://<path>` on
the tool resource); the bridge spawns the stdio server once per MCP session,
hands it the credential Agenthof injected on the call, forwards `tools/list`
and `tools/call`, and ends the process when the session ends. The agent has
no path to the bridge: it talks to Agenthof only.

## Config (every key is required; nothing is defaulted)

```yaml
socket: /tmp/agenthof-bridge/stdio-tool.sock   # absolute; its directory must be mode 0700 and owned by the user refbridge runs as
command: ["/tmp/stdio-tool", "-credential-env", "DEMO_TOKEN"]   # the stdio MCP server's argv
credential:
  env: DEMO_TOKEN                # the variable the credential is materialized into
  materialization: env-at-spawn  # env-at-spawn (static credential) | respawn-on-rotation (rotating credential)
env_passthrough: []              # the ONLY variables copied from refbridge's own environment; [] = none
egress:
  allow: []                      # hosts the server may reach; [] = no network at all (see deploy/refbridge)
sessions:
  max: 4                         # concurrent sessions (= subprocesses)
  idle_timeout: 10m              # a session with no request for this long is ended — set it ABOVE Agenthof's step timeout (5m by default)
  max_lifetime: 30m              # a session is ended after this long regardless
```

`refbridge -config refbridge.yaml -check` validates the file and prints
`egress=none` or `egress=<host,...>` without listening; a file that omits any
key fails there.

The socket's directory is the access gate. refbridge checks at startup that
it is mode 0700 and owned by the user refbridge runs as, and refuses to start
otherwise. Never point `socket` into the refbox socket directory
(`gateway.refbox_socket_dir`): that directory is mounted into the agent's
compartment, and the bridge's socket must never be reachable from there.

## The two materialization modes

- `env-at-spawn` — for a static credential (`credential_source: static_env`
  with a fixed bearer): the value on the session's first tool request, which
  is Agenthof's `tools/list` when the step starts, is set in the subprocess
  environment and kept for the session.
- `respawn-on-rotation` — for a rotating credential
  (`grant_type: client_credentials`): Agenthof injects the current token on
  every call; when it changes, the bridge ends the subprocess and starts a new
  one with the new value before forwarding that call. The subprocess's own MCP
  state resets at that point, which is fine for the usual stateless tool
  server.

## Run it locally

Save the config above as `refbridge.yaml`, then:

```
go build -o /tmp/refbridge ./examples/refbridge
go build -o /tmp/stdio-tool ./examples/stdio-tool
mkdir -m 0700 /tmp/agenthof-bridge
/tmp/refbridge -config refbridge.yaml
```

Then declare the resource in Agenthof's `gateway.yaml`:

```yaml
tools:
  stdio-tool:
    kind: mcp
    url: unix:///tmp/agenthof-bridge/stdio-tool.sock
    credential_source: static_env
    token_env: DEMO_TOKEN
```

`scripts/e2e-refbridge-local.sh` runs this whole path against the real
`agenthof` binary. `deploy/refbridge` runs the bridge in a rootless-podman
compartment. Inside that image the socket is
`/run/agenthof-bridge/stdio-tool.sock` and the server is `/stdio-tool`; those
are the image's paths, not the local ones above.

## Limits, stated

- Whoever can connect to the socket decides which credential the subprocess
  gets: the bridge does not validate the bearer as a caller identity. The
  socket directory's permissions and the mount namespace are the gate.
- An allowed egress host is a path the credential can leave through. Keep
  the list minimal.
- The subprocess's own actions are not on Agenthof's ledger; `tool_call`
  records the call the bridge received.
- Under `respawn-on-rotation`, closing the old subprocess holds the session's
  lock for up to about ten seconds (five seconds to exit after its stdin
  closes, five more after SIGTERM), so calls on that session wait.
- The mirrored tool list is taken once, from the first subprocess, and is not
  refreshed when a rotation respawns it: the tool set is a property of the
  command, not of the credential.
- A subprocess that exits on its own is not noticed until the idle timeout or
  the max lifetime ends the session.
