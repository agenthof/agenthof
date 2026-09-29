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
deploy/lima/lima.sh e2e           # run the refbox and refbridge e2es, then self-clean
```

`up` provisions rootless podman, Go, and python3, and mounts the repository
read-only at `/agenthof` inside the VM. The repository path is detected
automatically, so the VM definition carries no machine-specific path.

## Commands

| Command | What it does |
| --- | --- |
| `lima.sh up` | Create the VM on first run, or start it if it already exists. |
| `lima.sh e2e [refbox\|refbridge\|all] [--keep]` | Run the compartment e2e(s) (default `all`), then self-clean unless `--keep`. |
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
(`refbridge:test`, `refbox-echo:test`) are ready. From there you run the pieces
yourself — for example, start a bridge compartment and then apply a config and
launch a run against it:

```sh
REFBRIDGE_DETACH=1 deploy/refbridge/refbridge-run.sh
~/agenthof apply --config deploy/refbridge/config --control-log /tmp/control.jsonl --as you --groups bridge-users
~/agenthof run bridge-operator bridge-demo --input "call echo hi" \
  --as you --groups bridge-users --config deploy/refbridge/config \
  --log-dir /tmp/logs --artifact-dir /tmp/artifacts
```

Write run state (`--control-log`, `--log-dir`, `--artifact-dir`) to a writable
path such as `/tmp`, since the repository is mounted read-only.

The `scripts/e2e-refbox.sh` and `scripts/e2e-refbridge.sh` scripts are the
worked, end-to-end examples of the full sequence.

## Keeping disk usage in check

Repeated image builds leave dangling layers behind. `lima.sh e2e` prunes them
after each run and prints `podman system df` before and after, so growth is
always visible. Run `lima.sh clean` any time to prune on demand, or
`lima.sh clean --all` to also drop the cached base images (the next run
re-pulls them).
