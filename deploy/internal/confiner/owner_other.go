//go:build !darwin && !linux

package confiner

// No backend launches a compartment on this OS (podman needs a local Linux
// engine, Seatbelt is macOS), so no owner stamp can be computed here:
// selfOwner fails, and a backend built here refuses to launch. A Reap here
// finds every owner gone and so reaps every leftover it is asked about,
// which is exactly the behaviour before stamps existed.

func ownerStart(int) (int64, error) { return 0, ErrNotImplemented }

func bootID() (string, error) { return "", nil }
