# Local test harness (macOS)

Agenthof's compartment tests run an agent, or a tool, inside a locked-down
rootless-podman container and reach it only through a bind-mounted Unix socket.
That needs a real Linux host: Docker Desktop on macOS cannot bind-mount the
socket across its VM boundary. This harness gives you one — a small, headless
[Lima](https://lima-vm.org) VM running **Ubuntu 24.04, the same distribution the
CI e2es run on**, so a green run here matches CI.

Everything for the harness lives in this directory. Nothing here is required to
build or run Agenthof itself; it is a convenience for exercising the
compartmented tests locally.

## Prerequisites

- macOS with [Lima](https://lima-vm.org) installed (`brew install lima`).
- The `vz` VM type (the default here) needs macOS 13 or newer. On older macOS,
  change `vmType` in `agenthof.yaml` to `qemu` and install QEMU.

## Quick start

```sh
deploy/lima/lima.sh up            # create + provision the VM (first run takes a few minutes)
deploy/lima/lima.sh e2e           # run the refbox, refbridge, refexec and spawn e2es, then self-clean
```

`up` provisions rootless podman, Go, and python3, and mounts the repository
read-only at `/agenthof` inside the VM. The repository path is detected
automatically, so the VM definition carries no machine-specific path.

## Commands

| Command | What it does |
| --- | --- |
| `lima.sh up` | Create the VM on first run, or start it if it already exists. |
| `lima.sh e2e [refbox\|refbridge\|refexec\|spawn\|all] [--keep]` | Run the compartment e2e(s) (default `all`), then self-clean unless `--keep`. |
| `lima.sh build` | Compile `agenthof` (to `~/agenthof`) and build the compartment images, ready for manual runs. |
| `lima.sh shell` | Open a shell in the VM at `/agenthof`, with Go, podman, and python3 on `PATH`. |
| `lima.sh clean [--all]` | Remove stopped containers and dangling images; `--all` also drops cached base images. |
| `lima.sh down` | Stop the VM, keeping it for next time. |
| `lima.sh destroy` | Delete the VM entirely. |

## Manual mode

To drive Agenthof by hand inside the compartment environment:

```sh
deploy/lima/lima.sh build         # compile agenthof + build the images once
deploy/lima/lima.sh shell         # you are now in the VM, in /agenthof
```

Inside the shell, `~/agenthof` is the built binary and the compartment images
(`refbridge:test`, `refbox-echo:test`) are ready.

The e2e scripts are the canonical worked examples of a full governed run: they
set up the socket directories, rewrite the demo config to point at them, export
the tool credential into Agenthof's environment (never the compartment's), start
the agent process, then `apply` and `run`. Run one end to end:

```sh
bash scripts/e2e-refbridge.sh   # a stdio tool, run in refbridge, over unix://
bash scripts/e2e-refbox.sh      # the agent itself, run inside refbox
bash scripts/e2e-refexec.sh     # a command run first-hand by refexec, on a workspace shared with refbox
bash scripts/e2e-spawn.sh       # a spawned child run, in the compartments refspawn provisions for it
```

To drive Agenthof by hand, follow the same steps that script does. The detail a
from-scratch attempt trips on: the bridge's `socket:` and `refbridge-run.sh`'s
socket directory must be the *same* writable path (the compartment mounts it at
that path inside and out), and the shipped
`deploy/refbridge/bridge-config/refbridge.yaml` carries a placeholder path — so
point both at a directory you own (e.g. `$XDG_RUNTIME_DIR/agenthof-bridge`)
before starting the bridge. Write run state (`--control-log`, `--log-dir`,
`--artifact-dir`) to a writable path such as `/tmp`, since the repository is
mounted read-only.

## Keeping disk usage in check

Repeated image builds leave dangling layers behind. `lima.sh e2e` prunes them
after each run and prints `podman system df` before and after, so growth is
always visible. Run `lima.sh clean` any time to prune on demand, or
`lima.sh clean --all` to also drop the cached base images (the next run
re-pulls them).
