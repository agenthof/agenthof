package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
)

// stubFlag re-executes this test binary as the hermetic e2e's refspawn: the
// real config, listener, serve loop, supervisor and wire contract, with the
// fake podman (podman_test.go) in place of podman — so each "compartment" is
// the configured program run directly on the host, and each "volume" is a
// directory under REFSPAWN_TEST_VOLROOT. Test-tree code on purpose: the
// shipped refspawn has no mode that skips podman. Built with `go test -c`.
const stubFlag = "-refspawn-test-stub"

func runStub(args []string) int {
	fs := flag.NewFlagSet("refspawn-stub", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "refspawn YAML config")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Getenv("REFSPAWN_TEST_VOLROOT") == "" {
		fmt.Fprintln(os.Stderr, "refspawn stub: REFSPAWN_TEST_VOLROOT must name the directory that stands in for podman volumes")
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("refspawn stub: compartments are host processes, volumes are directories")
	return serve(cfg, logger, []string{exe, fakePodmanFlag})
}
