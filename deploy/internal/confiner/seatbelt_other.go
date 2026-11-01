//go:build !darwin

package confiner

// The Seatbelt backend runs only on macOS. These stand-ins let the package
// build everywhere: a process is never reported as live, nothing is listed and
// nothing is signalled, so the backend's Reap and RemoveStore treat every
// record as already gone and never act on a process here.

func processStart(int) (int64, error) { return 0, ErrNotImplemented }

func descendants(int) []int { return nil }

func killSession(int) {}
