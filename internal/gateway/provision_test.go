package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

const testMasterKey = "sk-master-test"

func TestEnsureRoleKeyFreshGenerate(t *testing.T) {
	root := t.TempDir()
	role := config.RoleDef{Name: "coder", BudgetUSDMonth: 25}

	var gotMethod, gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/key/info":
			t.Errorf("unexpected info call on fresh generate")
			w.WriteHeader(http.StatusInternalServerError)
		case r.Method == http.MethodPost && r.URL.Path == "/key/generate":
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Errorf("decode body: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "sk-generated-123"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p := Provisioner{AdminBase: srv.URL, MasterKey: testMasterKey, HTTP: srv.Client()}
	created, err := p.EnsureRoleKey(root, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created {
		t.Fatal("expected created=true")
	}

	if gotMethod != http.MethodPost || gotPath != "/key/generate" {
		t.Fatalf("request = %s %s, want POST /key/generate", gotMethod, gotPath)
	}
	if gotAuth != "Bearer "+testMasterKey {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotBody["key_alias"] != "agenthof-coder" {
		t.Fatalf("key_alias = %v", gotBody["key_alias"])
	}
	if gotBody["max_budget"] != float64(25) {
		t.Fatalf("max_budget = %v", gotBody["max_budget"])
	}

	path := RoleKeyPath(root, "coder")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(data) != "sk-generated-123" {
		t.Fatalf("key file content = %q", string(data))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perm = %o, want 0600", perm)
	}
}

func TestEnsureRoleKeyExistingValid(t *testing.T) {
	root := t.TempDir()
	role := config.RoleDef{Name: "coder", BudgetUSDMonth: 25}

	writeRoleKey(t, root, "coder", "sk-existing")

	generateCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/key/info":
			if r.URL.Query().Get("key") != "sk-existing" {
				t.Errorf("info key = %q", r.URL.Query().Get("key"))
			}
			if r.Header.Get("Authorization") != "Bearer "+testMasterKey {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"spend": 1.5})
		case r.Method == http.MethodPost && r.URL.Path == "/key/generate":
			generateCalls++
			t.Errorf("unexpected generate call for valid existing key")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p := Provisioner{AdminBase: srv.URL, MasterKey: testMasterKey, HTTP: srv.Client()}
	created, err := p.EnsureRoleKey(root, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Fatal("expected created=false")
	}
	if generateCalls != 0 {
		t.Fatalf("generateCalls = %d, want 0", generateCalls)
	}
}

func TestEnsureRoleKeyExistingInvalidRegenerates(t *testing.T) {
	root := t.TempDir()
	role := config.RoleDef{Name: "coder", BudgetUSDMonth: 25}

	writeRoleKey(t, root, "coder", "sk-stale")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/key/info":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/key/generate":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "sk-fresh-456"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p := Provisioner{AdminBase: srv.URL, MasterKey: testMasterKey, HTTP: srv.Client()}
	created, err := p.EnsureRoleKey(root, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created {
		t.Fatal("expected created=true when regenerating")
	}

	got := LoadRoleKey(root, "coder")
	if got != "sk-fresh-456" {
		t.Fatalf("key file content = %q, want regenerated key", got)
	}
}

func TestEnsureRoleKeyZeroBudgetSkips(t *testing.T) {
	root := t.TempDir()
	role := config.RoleDef{Name: "coder", BudgetUSDMonth: 0}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s for zero-budget role", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := Provisioner{AdminBase: srv.URL, MasterKey: testMasterKey, HTTP: srv.Client()}
	created, err := p.EnsureRoleKey(root, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Fatal("expected created=false for zero-budget role")
	}
}

func TestEnsureRoleKeyGenerateServerError(t *testing.T) {
	root := t.TempDir()
	role := config.RoleDef{Name: "coder", BudgetUSDMonth: 25}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := Provisioner{AdminBase: srv.URL, MasterKey: testMasterKey, HTTP: srv.Client()}
	_, err := p.EnsureRoleKey(root, role)
	if err == nil {
		t.Fatal("expected error on generate 500")
	}
}

func writeRoleKey(t *testing.T, root, role, key string) {
	t.Helper()
	path := RoleKeyPath(root, role)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
