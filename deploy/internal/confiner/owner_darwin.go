//go:build darwin

package confiner

import "golang.org/x/sys/unix"

// szomb is the kernel's P_stat for a process that has exited but has not been
// reaped by its parent (sys/proc.h SZOMB). The kernel still has a record for
// such a pid, so kill(pid, 0) still succeeds for it.
const szomb = 5

// ownerStart is the start time of pid in microseconds since the Unix epoch,
// for an OWNER check. It differs from processStart in one respect: a zombie
// is reported as gone (errOwnerExited). processStart matches a zombie on
// purpose, so a compartment's session is still signalled while its leader
// waits to be reaped; an owner that has exited, however, has no compartment
// left to attest, whatever its parent has yet to do.
func ownerStart(pid int) (int64, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if kp.Proc.P_stat == szomb {
		return 0, errOwnerExited
	}
	return startMicro(kp), nil
}

// bootID is "" on macOS: a start time there counts from the Unix epoch, so
// two boots never produce the same stamp for one pid.
func bootID() (string, error) { return "", nil }
