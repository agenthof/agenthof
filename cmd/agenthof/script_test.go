package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"agenthof": func() {
			os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
		},
	})
}

func TestScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoCompatHandler))
	t.Cleanup(srv.Close)
	testscript.Run(t, testscript.Params{
		Dir: filepath.Join("testdata", "script"),
		Setup: func(e *testscript.Env) error {
			// Hermetic: never inherit the developer's identity/gateway env.
			e.Setenv("AGENTHOF_TOKEN", "")
			e.Setenv("AGENTHOF_OIDC_ISSUER", "")
			e.Setenv("AGENTHOF_OIDC_CLIENT_ID", "")
			if err := copyDir(filepath.Join("..", "..", "examples", "config"),
				filepath.Join(e.WorkDir, "examples", "config")); err != nil {
				return err
			}
			// Example agents and inline script configs declare either a placeholder
			// loopback endpoint or none. Point every agent at this process's
			// echo-compatible stub so a fronted run succeeds without a
			// separate server.
			return rewriteAgentEndpoints(e.WorkDir, srv.URL)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// lastrun <log-dir>: finds the single newest run log and exports
			// its run id (filename minus .jsonl) as $RUNID for later exec lines.
			"lastrun": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 1 {
					ts.Fatalf("usage: lastrun <log-dir>")
				}
				entries, err := os.ReadDir(ts.MkAbs(args[0]))
				ts.Check(err)
				newest := ""
				var newestMod int64
				for _, ent := range entries {
					if ent.IsDir() || filepath.Ext(ent.Name()) != ".jsonl" {
						continue
					}
					info, err := ent.Info()
					ts.Check(err)
					if mod := info.ModTime().UnixNano(); mod >= newestMod {
						newestMod, newest = mod, ent.Name()
					}
				}
				if newest == "" {
					ts.Fatalf("no run logs in %s", args[0])
				}
				id := newest
				if ext := filepath.Ext(id); ext != "" {
					id = id[:len(id)-len(ext)]
				}
				ts.Setenv("RUNID", id)
			},
		},
	})
}

func rewriteAgentEndpoints(root, endpoint string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if filepath.Base(filepath.Dir(p)) != "agents" || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		found := false
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "endpoint:") {
				lines[i] = "endpoint: " + endpoint
				found = true
			}
		}
		out := strings.Join(lines, "\n")
		if !found {
			if out != "" && !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			out += "endpoint: " + endpoint + "\n"
		}
		return os.WriteFile(p, []byte(out), 0o644)
	})
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}
