# Agenthof — maintainer convenience targets. Testing and the hermetic e2es are
# plain `go` and `scripts/*.sh` (see CONTRIBUTING.md and .github/workflows). This
# file holds installing the binaries and the real-backend containment proofs —
# the combined podman run (Linux/Lima) and the macOS Seatbelt run — run by
# judgment on a developer machine, never by CI.
.DEFAULT_GOAL := help
.PHONY: help install build-runtimes acceptance-podman acceptance-seatbelt

GO ?= go
UNAME_S ?= $(shell uname -s)
KEEP_FLAG := $(if $(filter 1,$(KEEP)),--keep,)

help:
	@echo "make install          Build and install the agenthof control-plane CLI (go install ./cmd/agenthof)."
	@echo "make build-runtimes   Build and install the operator-side runtimes: refexec, refspawn, refbridge."
	@echo "make acceptance-podman [KEEP=1]"
	@echo "    The combined acceptance run on real rootless podman (scripts/e2e-acceptance.sh):"
	@echo "    every door in one governed run, every compartment real — the containment proof."
	@echo "    Linux: runs natively (needs rootless podman). macOS: runs inside the Lima VM"
	@echo "    (deploy/lima; started if needed). KEEP=1 leaves compartments and files for inspection."
	@echo "make acceptance-seatbelt"
	@echo "    The real-backend macOS Seatbelt proof (scripts/e2e-refexec-seatbelt.sh):"
	@echo "    first-hand exec under sandbox-exec — direct network denied, writes scoped,"
	@echo "    off-allowlist refused, ledger verified. macOS only (self-cleans)."

install:
	$(GO) install ./cmd/agenthof
	@echo "installed agenthof (the control-plane CLI) to the Go bin dir — ensure it is on PATH."

# The runtimes run on the host and drive rootless podman to create compartments;
# refbox is not here because it is a container IMAGE, not a binary (build it with
# podman from deploy/refbox/Containerfile[.python], or 'deploy/lima/lima.sh build').
build-runtimes:
	$(GO) install ./deploy/refexec ./deploy/refspawn ./deploy/refbridge
	@echo "installed refexec, refspawn, refbridge to the Go bin dir."
	@echo "note: refbox is a container image, not a binary — see deploy/refbox/Containerfile[.python]."

acceptance-podman:
ifeq ($(UNAME_S),Linux)
	@command -v podman >/dev/null || { echo "make acceptance-podman: podman is not installed (rootless podman is required)"; exit 1; }
	scripts/e2e-acceptance.sh $(KEEP_FLAG)
else ifeq ($(UNAME_S),Darwin)
	deploy/lima/lima.sh up
	deploy/lima/lima.sh e2e acceptance $(KEEP_FLAG)
else
	@echo "make acceptance-podman: unsupported host $(UNAME_S) — run scripts/e2e-acceptance.sh on a Linux host with rootless podman"; exit 1
endif

# The macOS Seatbelt backend needs no container runtime: refexec confines each
# command with /usr/bin/sandbox-exec. macOS-only — the sibling of the podman
# combined run above, and like it local/by-judgment, never CI.
acceptance-seatbelt:
ifeq ($(UNAME_S),Darwin)
	@command -v sandbox-exec >/dev/null || { echo "make acceptance-seatbelt: sandbox-exec not found (macOS required)"; exit 1; }
	scripts/e2e-refexec-seatbelt.sh
else
	@echo "make acceptance-seatbelt: the Seatbelt backend is macOS-only — run on a Mac (unsupported host $(UNAME_S))"; exit 1
endif
