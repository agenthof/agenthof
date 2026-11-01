//go:build darwin

package confiner

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// processStart returns the start time of pid in microseconds since the Unix
// epoch, from the kernel's own process record. ANY error means the process is
// gone: a missing pid makes the sysctl return no record (EIO from the size
// check), which is what callers need to treat a stale PID file as "already
// gone". The value is stable for the life of the process and is what makes a
// reused pid distinguishable from the process a record was written for.
func processStart(pid int) (int64, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	tv := kp.Proc.P_starttime
	return tv.Sec*1_000_000 + int64(tv.Usec), nil
}

// descendants lists every live process that descends from pid, transitively,
// by parent pid. A descendant whose parent has already exited has been
// reparented to launchd and is not found: the walk is best-effort by
// construction, which is the tier's stated teardown limit.
func descendants(pid int) []int {
	all, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	in := map[int]bool{pid: true}
	var out []int
	for changed := true; changed; {
		changed = false
		for _, kp := range all {
			child, parent := int(kp.Proc.P_pid), int(kp.Eproc.Ppid)
			if child > 1 && in[parent] && !in[child] {
				in[child] = true
				out = append(out, child)
				changed = true
			}
		}
	}
	return out
}

// killSession SIGKILLs the compartment's session: the process group pid leads
// (Launch starts every compartment with Setsid, so pid is its own group id)
// and then every descendant the walk can still see. The descendants are
// listed BEFORE the group is signalled, because killing a parent reparents its
// children to launchd and would hide them from the walk. Every signal is
// best-effort. A pid of 1 or lower is refused outright: kill(-1) would signal
// every process the user owns and kill(0) the caller's own group — the PID
// record reader already rejects such values, and this guard stands on its own
// so no caller can reach them.
func killSession(pid int) {
	if pid <= 1 {
		return
	}
	desc := descendants(pid)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	for _, d := range desc {
		if d > 1 {
			_ = syscall.Kill(d, syscall.SIGKILL)
		}
	}
}
