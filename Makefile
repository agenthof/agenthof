# Agenthof — maintainer targets. Building, testing and the hermetic e2es are
# plain `go` and `scripts/*.sh` (see CONTRIBUTING.md and .github/workflows);
# this file holds only what needs a real container runtime: the combined
# containment proof, run by judgment on a developer machine, never by CI.
.DEFAULT_GOAL := help
.PHONY: help acceptance-podman

UNAME_S ?= $(shell uname -s)
KEEP_FLAG := $(if $(filter 1,$(KEEP)),--keep,)

help:
	@echo "make acceptance-podman [KEEP=1]"
	@echo "    The combined acceptance run on real rootless podman (scripts/e2e-acceptance.sh):"
	@echo "    every door in one governed run, every compartment real — the containment proof."
	@echo "    Linux: runs natively (needs rootless podman). macOS: runs inside the Lima VM"
	@echo "    (deploy/lima; started if needed). KEEP=1 leaves compartments and files for inspection."

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
