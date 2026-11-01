//go:build linux

package confiner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ownerStart is the start time of pid in clock ticks since boot, from
// /proc/<pid>/stat (field 22), for an OWNER check: it is what the podman
// backend reads about a refexec or refspawn process on the host its engine
// runs on. The ticks are compared raw, never converted to wall-clock time:
// that conversion goes through the boot time, which can shift by a second
// between two reads under clock adjustment, and an owner whose stamp stopped
// matching would be taken for dead and its live compartments reaped. bootID
// tells one boot's ticks from another's. A process that has exited (a zombie,
// state Z, or a dead one, state X) is reported as gone.
func ownerStart(pid int) (int64, error) {
	body, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	// The second field, comm, sits in parentheses and may itself contain
	// spaces and parentheses, so the fields are counted from the LAST ")":
	// state is field 3, start time field 22.
	s := string(body)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("confiner: /proc/%d/stat: no comm field", pid)
	}
	fields := strings.Fields(s[i+1:])
	const stateIndex, startIndex = 3 - 3, 22 - 3
	if len(fields) <= startIndex {
		return 0, fmt.Errorf("confiner: /proc/%d/stat: %d fields after comm, want at least %d", pid, len(fields), startIndex+1)
	}
	switch fields[stateIndex] {
	case "Z", "X", "x":
		return 0, errOwnerExited
	}
	ticks, err := strconv.ParseInt(fields[startIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("confiner: /proc/%d/stat: start time: %w", pid, err)
	}
	return ticks, nil
}

// bootID is the kernel's id for this boot. Ticks since boot only name a
// process within the boot they count from; the id makes a stamp from before
// a reboot unmatchable afterwards.
func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("confiner: /proc/sys/kernel/random/boot_id is empty")
	}
	return id, nil
}
