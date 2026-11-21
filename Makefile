# Agenthof — maintainer convenience targets. Testing and the hermetic e2es are
# plain `go` and `scripts/*.sh` (see CONTRIBUTING.md and .github/workflows). This
# file holds installing the binaries and the real-backend proofs — the combined
# podman containment run (Linux/Lima), the macOS Seatbelt run, the enrolled-agent
# artifact binding runs (podman and Seatbelt), the Rekor v1 anchoring run
# the embeddings run against a real embeddings server (both Linux/Lima)
# and the memory-store run against a real Qdrant (Linux/Lima, plus Seatbelt on macOS) — run by judgment on a developer machine, never by CI.
.DEFAULT_GOAL := help
.PHONY: help install build-runtimes acceptance-podman acceptance-seatbelt acceptance-rekor acceptance-embeddings acceptance-memory acceptance-enroll

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
	@echo "make acceptance-enroll"
	@echo "    The enrolled-agent artifact binding on the REAL backends: a signed card's consented"
	@echo "    image digest (podman) or program hash (Seatbelt) is bound at spawn — bound success,"
	@echo "    repointed artifact refused, nothing of it run (scripts/e2e-refspawn.sh,"
	@echo "    scripts/e2e-refspawn-seatbelt.sh). Linux: podman natively. macOS: podman inside the"
	@echo "    Lima VM (started if needed; it runs the tree mounted at /agenthof) and Seatbelt natively."
	@echo "make acceptance-rekor [KEEP=1]"
	@echo "    The real-backend anchoring proof against a REAL Rekor v1 log (scripts/e2e-rekor.sh):"
	@echo "    the audit anchor / verify command path over a podman-compose Rekor stack."
	@echo "    Linux: runs natively (needs rootless podman + podman-compose). macOS: inside the"
	@echo "    Lima VM (started if needed). KEEP=1 leaves the stack and files for inspection."
	@echo "make acceptance-embeddings [KEEP=1]"
	@echo "    The real-backend embeddings proof against a REAL OpenAI-compatible embeddings server"
	@echo "    (scripts/e2e-embeddings.sh): a governed embed, a mismatched-model refusal and a"
	@echo "    no-grant refusal, no external key. Linux: runs natively (needs rootless podman)."
	@echo "    macOS: inside the Lima VM (started if needed). KEEP=1 leaves the server and files."
	@echo "make acceptance-memory [KEEP=1]"
	@echo "    The real-backend memory-store proof: the governed memory MCP server on the embedded"
	@echo "    backend and on a REAL Qdrant (digest-pinned), with a seam proof that both return the"
	@echo "    same top-k ids and scores (scripts/e2e-memory.sh). Linux: podman natively. macOS: podman"
	@echo "    inside the Lima VM (started if needed) plus the native Seatbelt store-file falsifier"
	@echo "    (scripts/e2e-memory-seatbelt.sh). KEEP=1 leaves the Qdrant container and files."

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

# The artifact binding proof: an enrolled agent's spawn is bound to the digest or
# program hash its signed card consented to, on the real runtime (podman) and the
# real sandbox launch (Seatbelt). Each script covers the scenarios of its own
# backend; on Linux only podman applies, on macOS podman runs in the Lima VM and
# Seatbelt natively. Like the runs above, local/by-judgment, never CI.
acceptance-enroll:
ifeq ($(UNAME_S),Linux)
	@command -v podman >/dev/null || { echo "make acceptance-enroll: podman is not installed (rootless podman is required)"; exit 1; }
	scripts/e2e-refspawn.sh
else ifeq ($(UNAME_S),Darwin)
	@command -v sandbox-exec >/dev/null || { echo "make acceptance-enroll: sandbox-exec not found (macOS required)"; exit 1; }
	deploy/lima/lima.sh up
	deploy/lima/lima.sh e2e refspawn
	scripts/e2e-refspawn-seatbelt.sh
else
	@echo "make acceptance-enroll: unsupported host $(UNAME_S) — run scripts/e2e-refspawn.sh on a Linux host with rootless podman"; exit 1
endif

# The Rekor v1 anchoring proof drives the binary's anchor command path (audit
# anchor / verify) against a REAL transparency log (deploy/rekor/docker-compose.yml)
# over podman-compose. Linux/Lima like the podman combined run above, and like it
# local/by-judgment, never CI.
acceptance-rekor:
ifeq ($(UNAME_S),Linux)
	@command -v podman >/dev/null || { echo "make acceptance-rekor: podman is not installed (rootless podman + podman-compose are required)"; exit 1; }
	scripts/e2e-rekor.sh $(KEEP_FLAG)
else ifeq ($(UNAME_S),Darwin)
	deploy/lima/lima.sh up
	deploy/lima/lima.sh e2e rekor $(KEEP_FLAG)
else
	@echo "make acceptance-rekor: unsupported host $(UNAME_S) — run scripts/e2e-rekor.sh on a Linux host with rootless podman + podman-compose"; exit 1
endif

# The embeddings proof drives a governed embed through the model door against a REAL
# OpenAI-compatible embeddings server (a pinned container, no external key). Linux/Lima
# like the runs above, and like them local/by-judgment, never CI.
acceptance-embeddings:
ifeq ($(UNAME_S),Linux)
	@command -v podman >/dev/null || { echo "make acceptance-embeddings: podman is not installed (rootless podman is required)"; exit 1; }
	scripts/e2e-embeddings.sh $(KEEP_FLAG)
else ifeq ($(UNAME_S),Darwin)
	deploy/lima/lima.sh up
	deploy/lima/lima.sh e2e embeddings $(KEEP_FLAG)
else
	@echo "make acceptance-embeddings: unsupported host $(UNAME_S) — run scripts/e2e-embeddings.sh on a Linux host with rootless podman"; exit 1
endif

# The memory-store proof runs the governed memory MCP server against a REAL Qdrant
# (a digest-pinned container on loopback) beside the embedded backend, and proves
# the two agree. On macOS the embedded store file's confinement is also proven on
# the real Seatbelt sandbox. Linux/Lima like the runs above, and like them
# local/by-judgment, never CI.
acceptance-memory:
ifeq ($(UNAME_S),Linux)
	@command -v podman >/dev/null || { echo "make acceptance-memory: podman is not installed (rootless podman is required)"; exit 1; }
	scripts/e2e-memory.sh $(KEEP_FLAG)
else ifeq ($(UNAME_S),Darwin)
	@command -v sandbox-exec >/dev/null || { echo "make acceptance-memory: sandbox-exec not found (macOS required)"; exit 1; }
	deploy/lima/lima.sh up
	deploy/lima/lima.sh e2e memory $(KEEP_FLAG)
	scripts/e2e-memory-seatbelt.sh
else
	@echo "make acceptance-memory: unsupported host $(UNAME_S) — run scripts/e2e-memory.sh on a Linux host with rootless podman"; exit 1
endif
