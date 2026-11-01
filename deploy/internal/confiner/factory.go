package confiner

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
)

// Keys are the backend-specific operator keys exactly as the runtime's YAML
// decoded them; the zero value means omitted.
type Keys struct {
	// Image is the podman image every exec compartment runs.
	Image string
	// WorkspacePath is podman's `workspace.path`, the guest mount point; ""
	// means "/work".
	WorkspacePath string
	// StoreRoot is Seatbelt's `store_root`.
	StoreRoot string
	// PIDDir is Seatbelt's `pid_dir`.
	PIDDir string
	// DenyRead is Seatbelt's optional `deny_read`.
	DenyRead []string
	// SharedHostScratch is Seatbelt's optional `shared_host_scratch` opt-in.
	SharedHostScratch bool
}

// Options selects and configures one backend.
type Options struct {
	// Tier is the config's `confiner:`; "" selects the OS default.
	Tier Tier
	// GOOS is the host OS; "" means runtime.GOOS.
	GOOS string
	Keys Keys
	// SpawnRoot is refspawn's own key, handed to Seatbelt as a read-deny root;
	// "" for refexec.
	SpawnRoot string
	// Environ returns the backend client's environment; nil means os.Environ.
	Environ func() []string
	// Logger receives operational events; nil discards.
	Logger *slog.Logger
}

// DefaultTier is the backend used when the config names none: podman on Linux,
// Seatbelt on macOS, and no default elsewhere.
func DefaultTier(goos string) (Tier, error) {
	switch goos {
	case "linux":
		return TierPodman, nil
	case "darwin":
		return TierSeatbelt, nil
	}
	return "", fmt.Errorf("no confiner backend for %s: %w", goos, ErrNotImplemented)
}

// Select constructs the backend the config names, or the OS default when it
// names none. The config wins over the OS default, and a key the selected
// backend does not consume is refused rather than ignored. Select does not
// Probe: the runtime probes and refuses to start.
func Select(opts Options) (Confiner, error) {
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	tier := opts.Tier
	if tier == "" {
		def, err := DefaultTier(goos)
		if err != nil {
			return nil, err
		}
		tier = def
	}
	k := opts.Keys
	switch {
	case Reserved(tier):
		return nil, fmt.Errorf("confiner %q: %w", tier, ErrNotImplemented)
	case tier == TierPodman:
		if err := unconsumed(tier, "seatbelt", seatbeltKeysSet(k)); err != nil {
			return nil, err
		}
		p := NewPodman(PodmanConfig{GuestWorkspace: k.WorkspacePath, Environ: opts.Environ, Logger: opts.Logger})
		if err := p.ValidateProgram(k.Image); err != nil {
			return nil, fmt.Errorf("confiner %q: image: %w", tier, err)
		}
		return p, nil
	case tier == TierSeatbelt:
		if err := unconsumed(tier, "podman", podmanKeysSet(k)); err != nil {
			return nil, err
		}
		for _, key := range []struct{ name, val string }{{"store_root", k.StoreRoot}, {"pid_dir", k.PIDDir}} {
			if !filepath.IsAbs(key.val) {
				return nil, fmt.Errorf("confiner %q: %s must be an absolute path, got %q", tier, key.name, key.val)
			}
		}
		s, err := NewSeatbelt(SeatbeltConfig{
			StoreRoot: k.StoreRoot, PIDDir: k.PIDDir, DenyRead: k.DenyRead, SharedHostScratch: k.SharedHostScratch,
			SpawnRoot: opts.SpawnRoot, Environ: opts.Environ, Logger: opts.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("confiner %q: %w", tier, err)
		}
		return s, nil
	}
	return nil, fmt.Errorf("confiner %q: %w", tier, ErrNotImplemented)
}

// podmanKeysSet names the podman-only keys k sets.
func podmanKeysSet(k Keys) []string {
	var set []string
	if k.Image != "" {
		set = append(set, "image")
	}
	if k.WorkspacePath != "" {
		set = append(set, "workspace.path")
	}
	return set
}

// seatbeltKeysSet names the Seatbelt-only keys k sets.
func seatbeltKeysSet(k Keys) []string {
	var set []string
	if k.StoreRoot != "" {
		set = append(set, "store_root")
	}
	if k.PIDDir != "" {
		set = append(set, "pid_dir")
	}
	if len(k.DenyRead) > 0 {
		set = append(set, "deny_read")
	}
	if k.SharedHostScratch {
		set = append(set, "shared_host_scratch")
	}
	return set
}

// unconsumed returns ErrUnconsumedKeys naming keys, or nil when there are none.
func unconsumed(tier Tier, owner string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	return fmt.Errorf("confiner %s does not consume %s keys: %s: %w", tier, owner, strings.Join(keys, ", "), ErrUnconsumedKeys)
}
