package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// containerPrefix names everything refspawn makes: agent compartments
// (<prefix><id>-<agent>) and workspace volumes (<prefix><id>-work). The
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

// refboxRunArgs is the one `podman run` for an agent compartment: the
// refbox recipe's arg set (deploy/refbox/refbox-run.sh) with the child's
// workspace volume at /work, the child's socket directory bind-mounted at
// its own path, --pull=never (a missing image is a fast exit 125, never a
// pull inside a --network none start), the supervisor's --timeout as the
// backstop, and the agent's socket path appended after the image so it
// overrides the image's own -socket (last wins).
func refboxRunArgs(cfg spawnConfig, name, image, volume, childDir, sock string) []string {
	secs := int(cfg.Timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	return []string{"run", "--rm", "--name", name, "--pull=never",
		"--network", "none", "--read-only",
		"-v", volume + ":/work",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges",
		"--userns=keep-id", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--memory=" + cfg.Limits.Memory, "--cpus=" + cfg.Limits.CPUs, "--pids-limit=" + strconv.Itoa(cfg.Limits.PIDs),
		"--timeout=" + strconv.Itoa(secs),
		"-v", childDir + ":" + childDir,
		image, "-socket", sock,
	}
}

// renderRefexecConfig writes the full key set refexec requires (every key,
// no unknowns) for one child: this child's exec socket in the sibling exec
// directory, this child's volume at /work, and the operator's exec
// template for everything else.
func renderRefexecConfig(rc refexecConfig, socket, volume string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "socket: %s\n", socket)
	fmt.Fprintf(&b, "image: %s\n", rc.Image)
	fmt.Fprintf(&b, "workspace:\n  volume: %s\n  path: /work\n", volume)
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
	return b.String()
}

// podman runs one podman command to completion under a bound and returns
// its combined output on failure. podman's text may name a container or a
// volume; it never carries a value.
func (s *supervisor) podman(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	full := append(append([]string{}, s.podmanArgv[1:]...), args...)
	cmd := exec.CommandContext(ctx, s.podmanArgv[0], full...)
	cmd.Env = s.environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("podman %s: %w: %s", strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// remove stops and deletes one container. Best effort: a container that
// already exited under --rm is gone, and podman's complaint is noise.
func (s *supervisor) remove(name string) {
	if _, err := s.podman(context.Background(), 30*time.Second, "rm", "-f", name); err != nil {
		s.logger.Warn("compartment not removed", "compartment", name, "error", err)
	}
}

// reap removes every container and volume refspawn's prefix names, and
// every directory under spawn_root: the leftovers of a previous refspawn
// that died with children in flight. Run at start and again at shutdown.
func (s *supervisor) reap() {
	ctx := context.Background()
	if out, err := s.podman(ctx, 30*time.Second, "ps", "-aq", "--filter", "name=^"+containerPrefix); err == nil {
		for _, c := range strings.Fields(string(out)) {
			s.logger.Info("reaping leftover compartment", "compartment", c)
			s.remove(c)
		}
	} else {
		s.logger.Warn("could not list leftover compartments", "error", err)
	}
	if out, err := s.podman(ctx, 30*time.Second, "volume", "ls", "-q", "--filter", "name=^"+containerPrefix); err == nil {
		for _, v := range strings.Fields(string(out)) {
			s.logger.Info("reaping leftover volume", "volume", v)
			// -f here, unlike an ordered teardown: a leftover may still be
			// mounted by a container refspawn does not name — an exec
			// compartment of a refexec that died with its supervisor — and
			// there is nothing left running to release it.
			if _, err := s.podman(ctx, 30*time.Second, "volume", "rm", "-f", v); err != nil {
				s.logger.Warn("leftover volume not removed", "volume", v, "error", err)
			}
		}
	} else {
		s.logger.Warn("could not list leftover volumes", "error", err)
	}
	entries, err := os.ReadDir(s.cfg.SpawnRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(s.cfg.SpawnRoot, e.Name()))
	}
}
