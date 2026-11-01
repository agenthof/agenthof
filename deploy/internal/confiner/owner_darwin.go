//go:build darwin

package confiner

import (
	"errors"

	"golang.org/x/sys/unix"
)

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

// ownerGone reports whether an ownerStart error means the process is
// definitely gone: it has exited, or the kernel has no record for the pid.
// unix.SysctlKinfoProc reports the latter as EIO — its own size check, when
// the kernel answers kern.proc.pid with no record rather than failing the
// call — so EIO here is "no such process", not a device error. ESRCH, the
// POSIX "no such process" errno, is accepted for the same condition as a
// defensive guard, though this sysctl reports a missing pid as EIO and does
// not itself return ESRCH. Every other error leaves the owner's liveness
// undeterminable (see ownerRef.alive).
func ownerGone(err error) bool {
	return errors.Is(err, errOwnerExited) || errors.Is(err, unix.EIO) || errors.Is(err, unix.ESRCH)
}

// bootID is "" on macOS: a start time there counts from the Unix epoch, so
// two boots never produce the same stamp for one pid.
func bootID() (string, error) { return "", nil }
