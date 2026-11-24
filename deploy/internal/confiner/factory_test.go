package confiner

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSelectConfigIsLaw(t *testing.T) {
	c, err := Select(Options{Tier: TierPodman, GOOS: "darwin", Keys: Keys{Image: "img:1"}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if _, ok := c.(*Podman); !ok {
		t.Fatalf("got %T, want *Podman: the config wins over the OS default", c)
	}
	if c.Tier() != TierPodman {
		t.Fatalf("tier = %q", c.Tier())
	}
}

func TestSelectHonoursTheGuestWorkspace(t *testing.T) {
	c, err := Select(Options{Tier: TierPodman, Keys: Keys{Image: "img:1", WorkspacePath: "/ws"}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := c.StorePath("s"); got != "/ws" {
		t.Fatalf("StorePath = %q, want /ws", got)
	}
}

func TestSelectOSDefault(t *testing.T) {
	c, err := Select(Options{GOOS: "linux", Keys: Keys{Image: "img:1"}})
	if err != nil {
		t.Fatalf("linux: %v", err)
	}
	if c.Tier() != TierPodman {
		t.Fatalf("linux default = %q, want podman", c.Tier())
	}

	// The darwin default constructs the Seatbelt backend (it runs nothing:
	// Probe is the runtime's call), on any build OS.
	c, err = Select(Options{GOOS: "darwin", Keys: Keys{StoreRoot: "/s", PIDDir: "/p"}})
	if err != nil {
		t.Fatalf("darwin: %v", err)
	}
	if _, ok := c.(*Seatbelt); !ok || c.Tier() != TierSeatbelt {
		t.Fatalf("darwin default = %T (%q), want *Seatbelt", c, c.Tier())
	}

	_, err = Select(Options{GOOS: "windows", Keys: Keys{Image: "img:1"}})
	if !errors.Is(err, ErrNotImplemented) || !strings.Contains(err.Error(), "windows") {
		t.Fatalf("windows = %v, want ErrNotImplemented naming windows", err)
	}
}

func TestSelectRefusesReservedAndNone(t *testing.T) {
	for _, tier := range []Tier{"none", "wsl2", "landlock", "microvm", "zzz"} {
		_, err := Select(Options{Tier: tier, GOOS: "linux", Keys: Keys{Image: "img:1"}})
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("tier %q: err = %v, want ErrNotImplemented", tier, err)
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd"} {
		if d, err := DefaultTier(goos); err == nil && d == "none" {
			t.Errorf("DefaultTier(%q) = none", goos)
		}
	}
}

func TestSelectPodmanRequiresAnImage(t *testing.T) {
	_, err := Select(Options{Tier: TierPodman})
	if !errors.Is(err, ErrEmptyProgram) {
		t.Fatalf("no image: err = %v, want ErrEmptyProgram", err)
	}
	if _, err = Select(Options{Tier: TierPodman, Keys: Keys{Image: "busy box"}}); err == nil {
		t.Fatal("a malformed image was accepted")
	}
}

func TestSelectRejectsUnconsumedKeys(t *testing.T) {
	_, err := Select(Options{Tier: TierPodman, Keys: Keys{Image: "i:1", StoreRoot: "/s", DenyRead: []string{"/x"}}})
	if !errors.Is(err, ErrUnconsumedKeys) || !strings.Contains(err.Error(), "store_root, deny_read") {
		t.Fatalf("podman + seatbelt keys: %v", err)
	}
	_, err = Select(Options{Tier: TierPodman, Keys: Keys{Image: "i:1", PIDDir: "/p", SharedHostScratch: true}})
	if !errors.Is(err, ErrUnconsumedKeys) || !strings.Contains(err.Error(), "pid_dir, shared_host_scratch") {
		t.Fatalf("podman + pid_dir/shared_host_scratch: %v", err)
	}

	_, err = Select(Options{Tier: TierSeatbelt, Keys: Keys{Image: "i:1", WorkspacePath: "/work", StoreRoot: "/s", PIDDir: "/p"}})
	want := "confiner seatbelt does not consume podman keys: image, workspace.path"
	if !errors.Is(err, ErrUnconsumedKeys) || !strings.Contains(err.Error(), want) {
		t.Fatalf("seatbelt + podman keys: %v, want %q", err, want)
	}
}

func TestSelectSeatbeltRequiresAbsoluteRoots(t *testing.T) {
	for _, k := range []Keys{
		{},
		{StoreRoot: "/s"},
		{PIDDir: "/p"},
		{StoreRoot: "rel", PIDDir: "/p"},
		{StoreRoot: "/s", PIDDir: "rel"},
	} {
		_, err := Select(Options{Tier: TierSeatbelt, Keys: k})
		if err == nil || errors.Is(err, ErrNotImplemented) || errors.Is(err, ErrUnconsumedKeys) {
			t.Errorf("keys %+v: err = %v, want an absolute-path refusal", k, err)
		}
	}
}

func TestSelectDarwinDefaultRejectsAPodmanShapedConfig(t *testing.T) {
	_, err := Select(Options{GOOS: "darwin", Keys: Keys{Image: "i:1", WorkspacePath: "/work"}})
	if !errors.Is(err, ErrUnconsumedKeys) {
		t.Fatalf("err = %v, want ErrUnconsumedKeys", err)
	}
}

// The factory hands Keys.DenyRead (which carries a refspawn deny_config_read)
// to the Seatbelt backend, whose read-deny set then contains it.
func TestSelectSeatbeltDeniesConfiguredConfigDir(t *testing.T) {
	c, err := Select(Options{GOOS: "darwin", Keys: Keys{StoreRoot: "/s", PIDDir: "/p", DenyRead: []string{"/x/cfg"}}})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	sb, ok := c.(*Seatbelt)
	if !ok {
		t.Fatalf("got %T, want *Seatbelt", c)
	}
	if !slices.Contains(sb.denyRead, "/x/cfg") || !strings.Contains(sbplProfile(profileInput{DenyRead: sb.denyRead}), `(deny file-read* (subpath "/x/cfg"))`) {
		t.Fatalf("denyRead = %q, missing /x/cfg", sb.denyRead)
	}
}
