# Agenthof — maintainer convenience targets. Testing and the hermetic e2es are
# plain `go` and `scripts/*.sh` (see CONTRIBUTING.md and .github/workflows). This
# file holds installing the binaries and the one thing that needs a real
# container runtime: the combined containment proof, run by judgment on a
# developer machine, never by CI.
.DEFAULT_GOAL := help
.PHONY: help install build-runtimes acceptance-podman

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
