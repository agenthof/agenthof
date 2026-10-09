package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
)

// cmdConfig is the `config` subcommand group; `pull` is its only verb.
func cmdConfig(args []string, out io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(out, "config needs a subcommand: pull")
		return 2
	}
	switch args[0] {
	case "pull":
		return cmdConfigPull(args[1:], out)
	default:
		_, _ = fmt.Fprintf(out, "unknown config subcommand %q\n", args[0])
		return 2
	}
}

// cmdConfigPull is `config pull`: the installed configuration, from a
// running serve API (--server, the bearer is the invoker and the server
// authorizes it) or from the local store (no identity: the caller owns the
// filesystem, as audit control does). Either way the content address is
// checked here before anything is printed or written — HashFiles over the
// files must equal the hash — because that check is the consumer's half of
// the contract, not a courtesy. --out writes the configuration as a
// directory that must not exist and re-hashes it on disk; --json prints
// the document, which apply --bundle accepts as is. Exit 0 only when
// pulled (and, with --out, written and verified); 1 for every other
// answer, transport error, mismatch or write failure; 2 for usage.
func cmdConfigPull(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("config pull", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it (ignored with --server)")
	server := fs.String("server", "", "pull from an agenthof serve API at this base URL (env AGENTHOF_SERVER); needs --token/AGENTHOF_TOKEN")
	token := fs.String("token", "", "bearer for --server (env AGENTHOF_TOKEN)")
	outDir := fs.String("out", "", "write the configuration as a directory at this path, which must not exist; it then applies with apply --config")
	jsonOut := fs.Bool("json", false, "print the pulled document as JSON — the bundle apply --bundle accepts")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *outDir != "" {
		// Lstat, so a dangling symlink reads as "exists" too: extra files
		// already there would change HashDir(out) and break the round trip
		// silently.
		if _, err := os.Lstat(*outDir); err == nil {
			_, _ = fmt.Fprintf(out, "config pull: --out %s exists; name a new directory\n", *outDir)
			return 2
		}
	}

	var snap apiclient.ConfigSnapshot
	if base := serverBase(*server); base != "" {
		tok := serverToken(*token)
		if tok == "" {
			_, _ = fmt.Fprintln(out, "config pull: --server needs --token or AGENTHOF_TOKEN")
			return 2
		}
		warnInsecureServer(base, os.Stderr)
		s, err := apiclient.New(base, tok, nil).PullConfig(context.Background())
		if err != nil {
			_, _ = fmt.Fprintf(out, "config pull: %v\n", err)
			return 1
		}
		snap = s
	} else {
		o := pullConfig(pullRequest{ControlLog: *controlLog})
		switch o.Kind {
		case pulled:
			snap = o.Snapshot
		case pullNothingInstalled:
			_, _ = fmt.Fprintf(out, "config pull: %s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, installedStore(*controlLog), *controlLog)
			return 1
		case pullNotRecorded:
			_, _ = fmt.Fprintf(out, "config pull: %s\n", apiclient.PullBodyNotRecorded)
			return 1
		default:
			// Store, bundle, ledger and lock failures carry their cause; the
			// caller owns the host, so the paths in it are theirs to see.
			_, _ = fmt.Fprintf(out, "config pull: %v\n", o.Err)
			return 1
		}
	}
	return printPull(snap, *outDir, *jsonOut, out)
}

// printPull checks the content address, then writes (--out), then prints:
// the summary (the first line is the string apply --server prints on
// success, so scripts read one shape; the listing is in the canon's order)
// or the document (--json), then the wrote line.
func printPull(snap apiclient.ConfigSnapshot, outDir string, jsonOut bool, out io.Writer) int {
	files := make(map[string][]byte, len(snap.Files))
	for rel, text := range snap.Files {
		if config.ValidBundlePath(rel) {
			files[rel] = []byte(text)
			continue
		}
		_, _ = fmt.Fprintf(out, "config pull: invalid config path: %q\n", rel)
		return 1
	}
	got, err := config.HashFiles(files)
	if err != nil {
		_, _ = fmt.Fprintf(out, "config pull: %v\n", err)
		return 1
	}
	if got != snap.Hash {
		_, _ = fmt.Fprintf(out, "config pull: snapshot does not hash as its pointer: got %s, want %s\n", got, snap.Hash)
		return 1
	}
	if outDir != "" {
		if err := config.WriteBundle(outDir, files); err != nil {
			_, _ = fmt.Fprintf(out, "config pull: %v\n", err)
			return 1
		}
		// The on-disk round-trip proof: a filesystem that normalizes names
		// would change the directory's hash, and such a directory must not
		// be left for an operator to apply.
		written, err := config.HashDir(outDir)
		if err != nil {
			_ = os.RemoveAll(outDir)
			_, _ = fmt.Fprintf(out, "config pull: wrote %s but could not hash it: %v; removed\n", outDir, err)
			return 1
		}
		if written != snap.Hash {
			_ = os.RemoveAll(outDir)
			_, _ = fmt.Fprintf(out, "config pull: wrote %s but it hashes as %s, not %s; removed\n", outDir, written, snap.Hash)
			return 1
		}
	}
	if jsonOut {
		if err := json.NewEncoder(out).Encode(snap); err != nil {
			_, _ = fmt.Fprintf(out, "config pull: %v\n", err)
			return 1
		}
	} else {
		_, _ = fmt.Fprintf(out, "installed: %s\nversion: %d  installed_at: %s\nfiles: %d\n", snap.Hash, snap.Version, snap.InstalledAt.UTC().Format(time.RFC3339), len(files))
		for _, rel := range config.BundleOrder(files) {
			_, _ = fmt.Fprintf(out, "  %s  %d bytes\n", rel, len(files[rel]))
		}
	}
	if outDir != "" {
		_, _ = fmt.Fprintf(out, "wrote %d files to %s\n", len(files), outDir)
	}
	return 0
}
