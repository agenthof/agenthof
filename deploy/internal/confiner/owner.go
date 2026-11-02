package confiner

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ownerRef names the process that launched a compartment — the refexec or
// refspawn instance whose backend this is — by its pid, the start time the
// kernel reports for that pid, and, where the platform has one, the id of
// the boot that start time counts from. Every compartment a backend launches
// is stamped with its owner, so a later Reap can tell a LEFTOVER (its owner
// is gone) from a compartment another, still-running instance is using: the
// two are indistinguishable by name alone, and reaping the latter would end
// a command mid-flight and hand its runtime a killed exit to attest as the
// command's own.
type ownerRef struct {
	pid   int
	start int64
	boot  string
}

// ownerLabel is the container label an owner stamp travels under.
const ownerLabel = "agenthof.owner"

// errOwnerExited reports a pid the kernel still knows but whose process has
// exited (a zombie its parent has yet to reap). For an owner check that is
// "gone": an exited owner has no compartment left to attest.
var errOwnerExited = errors.New("confiner: the process has exited")

// String renders the stamp as <pid>-<start>, with -<boot> appended when the
// platform has a boot id. It contains no spaces, so it survives a
// space-separated listing.
func (o ownerRef) String() string {
	s := strconv.Itoa(o.pid) + "-" + strconv.FormatInt(o.start, 10)
	if o.boot != "" {
		s += "-" + o.boot
	}
	return s
}

// parseOwner reads a stamp String wrote. ok is false for anything else — an
// empty value, a malformed one, a pid of 1 or lower — which a caller treats
// as an unknown owner.
func parseOwner(s string) (o ownerRef, ok bool) {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) < 2 {
		return ownerRef{}, false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 1 {
		return ownerRef{}, false
	}
	start, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return ownerRef{}, false
	}
	o = ownerRef{pid: pid, start: start}
	if len(parts) == 3 {
		o.boot = parts[2]
	}
	return o, true
}

var (
	selfOnce sync.Once
	self     ownerRef
	selfErr  error
)

// selfOwner is this process's own stamp, read once per process: every
// backend in the process stamps the compartments it launches with it. A
// process whose own start time or boot id cannot be read gets an error, and
// its backends refuse to launch rather than launch compartments no later
// sweep could tell from leftovers.
func selfOwner() (ownerRef, error) {
	selfOnce.Do(func() {
		pid := os.Getpid()
		start, err := ownerStart(pid)
		if err != nil {
			selfErr = fmt.Errorf("confiner: own process start time unavailable, so compartments could not be stamped with their owner: %w", err)
			return
		}
		boot, err := bootID()
		if err != nil {
			selfErr = fmt.Errorf("confiner: boot id unavailable, so compartments could not be stamped with their owner: %w", err)
			return
		}
		self = ownerRef{pid: pid, start: start, boot: boot}
	})
	return self, selfErr
}

// alive reports whether o still names a running process in the boot
// identified by boot: the kernel must report the recorded start time for
// the pid (a reused pid never has it), and the process must not have exited.
// A pid of 1 or lower, and an owner from another boot, are never alive. The
// pid is checked BEFORE the kernel is asked, because pid 0 names a kernel
// process whose start time a stale or unstamped record must never match.
//
// An owner whose liveness cannot be determined is reported ALIVE. The two
// mistakes are not symmetric: taking a live owner for dead reaps a sibling
// instance's compartment, ending its command mid-flight and handing its
// runtime a killed exit to attest as the command's own; taking a dead owner
// for alive leaves a leftover in place for the next sweep to remove. So only
// an error that definitively says the process is gone (ownerGone) counts as
// dead; any other — a permission denial, an I/O error, a kernel record that
// does not parse — leaves the compartment where it is.
func (o ownerRef) alive(boot string) bool {
	if o.pid <= 1 || o.boot != boot {
		return false
	}
	start, err := ownerStart(o.pid)
	if err == nil {
		return start == o.start
	}
	return !ownerGone(err)
}

// reapableBy reports whether a compartment stamped with owner o is a
// leftover to the instance self: its owner is self (an instance sweeping its
// own leftovers on the way out) or its owner is no longer running. An
// unknown owner (the zero ownerRef, from a record or container written
// before stamps existed) is never alive and so is reapable: only an instance
// that predates the stamp could have written it, and that instance is gone.
func (o ownerRef) reapableBy(self ownerRef) bool {
	return o == self || !o.alive(self.boot)
}
