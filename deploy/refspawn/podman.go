package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

// containerPrefix names everything refspawn makes: agent compartments
// (<prefix><id>-<agent>) and workspace stores (<prefix><id>-work). The
// start-up reap removes whatever carries it. refexec's own transient exec
// compartments are named refexec-… and are never reaped here: every
// child's refexec shares that prefix, and each refexec removes its own.
const containerPrefix = "agenthof-spawn-"

// execDirSuffix distinguishes a child's exec directory from its socket
// directory under the one spawn_root. A child run id ending in it is
// refused, so the two names stay one-to-one with the id.
const execDirSuffix = "-exec"

// compartmentName is the container name for one agent of one child. The
// supervisor claims every name a set needs before it starts anything: an
// id and an agent name may both contain "-", so this is not unique on its
// own.
func compartmentName(id, agent string) string { return containerPrefix + id + "-" + agent }

// renderRefexecConfig writes the key set refexec requires (every key, no
// unknowns) for one child: this child's exec socket in the sibling exec
// directory, the confiner tier, this child's workspace store, and the
// operator's exec template for everything else. Each backend gets only the
// keys it consumes, because refexec refuses one its backend does not: podman
// gets the image and the guest workspace path; Seatbelt gets store_root,
// pid_dir, deny_read (the operator's list plus spawn_root, so the exec
// compartments' profile also denies reads under spawn_root) and, when set,
// shared_host_scratch. Neither gets a volume key: the store name is the only
// handle on the workspace.
func renderRefexecConfig(rc refexecConfig, socket, store string, tier confiner.Tier, keys confiner.Keys, spawnRoot string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "socket: %s\n", socket)
	fmt.Fprintf(&b, "confiner: %s\n", tier)
	switch tier {
	case confiner.TierPodman:
		fmt.Fprintf(&b, "image: %s\n", rc.Image)
		fmt.Fprintf(&b, "workspace:\n  store: %s\n  path: /work\n", store)
	case confiner.TierSeatbelt:
		fmt.Fprintf(&b, "store_root: %s\npid_dir: %s\n", keys.StoreRoot, keys.PIDDir)
		deny := make([]string, 0, len(keys.DenyRead)+1)
		for _, p := range append(append([]string{}, keys.DenyRead...), spawnRoot) {
			deny = append(deny, strconv.Quote(p))
		}
		fmt.Fprintf(&b, "deny_read: [%s]\n", strings.Join(deny, ", "))
		if keys.SharedHostScratch {
			b.WriteString("shared_host_scratch: true\n")
		}
	}
	fmt.Fprintf(&b, "timeout: %s\n", rc.Timeout)
	fmt.Fprintf(&b, "limits:\n  memory: %s\n  cpus: %q\n  pids: %d\n", rc.Limits.Memory, rc.Limits.CPUs, rc.Limits.PIDs)
	fmt.Fprintf(&b, "compartments:\n  max: %d\n", rc.MaxCompartments)
	b.WriteString("env_allow: [")
	for i, n := range rc.EnvAllow {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(n)
	}
	b.WriteString("]\n")
	if tier != confiner.TierPodman { // podman's workspace block carries its guest path and sits with its image
		fmt.Fprintf(&b, "workspace:\n  store: %s\n", store)
	}
	return b.String()
}

// reap removes every compartment and store the confiner finds under
// refspawn's prefix, and every directory under spawn_root: the leftovers of
// a previous refspawn that died with children in flight. Run at start and
// again at shutdown. The spawn_root sweep is refspawn's own and runs even
// when the confiner's reap failed; that failure is returned for the caller
// to refuse on (at start) or warn about (at shutdown).
func (s *supervisor) reap() error {
	err := s.confiner.Reap(context.Background(), containerPrefix)
	entries, rdErr := os.ReadDir(s.cfg.SpawnRoot)
	if rdErr != nil {
		return err
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(s.cfg.SpawnRoot, e.Name()))
	}
	return err
}
