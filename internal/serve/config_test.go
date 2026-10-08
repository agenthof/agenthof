package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
)

const (
	goodHash  = "sha256:3a2f6d0c0df4546527ad1ba5c5ae63cc803851f99614247fcbf38b16b4a5d885"
	otherHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var goodBundle = apiclient.ApplyRequest{Files: map[string]string{"roles/ops.yaml": "name: ops\ncontrol: [apply]\nallowed_groups: [engineering]\n"}}

// tryApply sends a bundle with the given raw body and headers and returns
// the status, the body and any transport error. It takes no *testing.T so
// it may run in a goroutine (t.Fatal from a goroutine is not allowed).
func (ts *testServer) tryApply(token string, body []byte, hdr map[string]string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, ts.http.URL+"/v1/config/apply", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, data, nil
}

// postApply is tryApply for the test's own goroutine: a transport error is fatal.
func (ts *testServer) postApply(t *testing.T, token string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	resp, data, err := ts.tryApply(token, body, hdr)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

// applyCode is a goroutine's report: the status, or the transport error.
type applyCode struct {
	code int
	err  error
}

// goApply posts from a goroutine and reports on the returned channel.
func (ts *testServer) goApply(token string, body []byte, hdr map[string]string) <-chan applyCode {
	ch := make(chan applyCode, 1)
	go func() {
		resp, _, err := ts.tryApply(token, body, hdr)
		if err != nil {
			ch <- applyCode{err: err}
			return
		}
		ch <- applyCode{code: resp.StatusCode}
	}()
	return ch
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shutdownReturnsPromptly is the WaitGroup-balance check: after any
// rejected request the drain must not wait on a count nobody decrements.
func shutdownReturnsPromptly(t *testing.T, ts *testServer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := ts.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after rejected requests: %v (the WaitGroup leaked)", err)
	}
}

func TestApplyConfig401NeverCallsHost(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	resp, body := ts.postApply(t, "bad", mustJSON(t, goodBundle), map[string]string{"If-None-Match": "*"})
	if resp.StatusCode != http.StatusUnauthorized || strings.TrimSpace(string(body)) != "unauthorized" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if ts.config.count() != 0 {
		t.Fatal("the host must not be called")
	}
}

func TestApplyConfig400Cases(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	good := mustJSON(t, goodBundle)
	ifMatch := map[string]string{"If-Match": goodHash}
	cases := []struct {
		name string
		body []byte
		hdr  map[string]string
		want string
	}{
		{"malformed json", []byte(`{"files":`), ifMatch, "malformed request body"},
		{"invalid utf-8", []byte("{\"files\":{\"roles/a.yaml\":\"\xff\"}}"), ifMatch, "request body is not valid UTF-8"},
		{"no files", []byte(`{}`), ifMatch, "files is required"},
		{"empty files", []byte(`{"files":{}}`), ifMatch, "files is required"},
		{"too many files", mustJSON(t, bigBundle(apiclient.MaxBundleFiles+1)), ifMatch, "too many files"},
		{"escaping key", mustJSON(t, apiclient.ApplyRequest{Files: map[string]string{"../x.yaml": "x"}}), ifMatch, "invalid config path: ../x.yaml"},
		{"wrong group", mustJSON(t, apiclient.ApplyRequest{Files: map[string]string{"Agents/x.yaml": "x"}}), ifMatch, "invalid config path: Agents/x.yaml"},
		{"control rune in key", mustJSON(t, apiclient.ApplyRequest{Files: map[string]string{"agents/x\x1b[2J.yaml": "x"}}), ifMatch, "invalid config path: agents/x[2J.yaml"},
		{"no precondition", good, nil, "exactly one of If-Match and If-None-Match is required"},
		{"both preconditions", good, map[string]string{"If-Match": goodHash, "If-None-Match": "*"}, "exactly one of If-Match and If-None-Match is required"},
		{"if-none-match not star", good, map[string]string{"If-None-Match": goodHash}, "If-None-Match must be *"},
		{"uppercase hex", good, map[string]string{"If-Match": strings.ToUpper(goodHash[:10]) + goodHash[10:]}, "lowercase hex"},
		{"weak validator", good, map[string]string{"If-Match": `W/"` + goodHash + `"`}, "lowercase hex"},
		{"list", good, map[string]string{"If-Match": goodHash + ", " + otherHash}, "lowercase hex"},
		{"star", good, map[string]string{"If-Match": "*"}, "lowercase hex"},
		{"not a hash", good, map[string]string{"If-Match": "sha256:abc"}, "lowercase hex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := ts.postApply(t, goodToken, c.body, c.hdr)
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), c.want) {
				t.Fatalf("%d %q, want 400 containing %q", resp.StatusCode, body, c.want)
			}
		})
	}
	if ts.config.count() != 0 {
		t.Fatalf("the host must not be called on a 400; called %d times", ts.config.count())
	}
	shutdownReturnsPromptly(t, ts)
}

func bigBundle(n int) apiclient.ApplyRequest {
	files := make(map[string]string, n)
	for i := 0; i < n; i++ {
		files["roles/r"+strconv.Itoa(i)+".yaml"] = "name: r\n"
	}
	return apiclient.ApplyRequest{Files: files}
}

func TestApplyConfig413OverCapHostNotCalled(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	huge := apiclient.ApplyRequest{Files: map[string]string{"roles/r.yaml": strings.Repeat("a", apiclient.MaxApplyBody+1)}}
	resp, body := ts.postApply(t, goodToken, mustJSON(t, huge), map[string]string{"If-Match": goodHash})
	if resp.StatusCode != http.StatusRequestEntityTooLarge || strings.TrimSpace(string(body)) != "request body too large" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if ts.config.count() != 0 {
		t.Fatal("the host must not be called")
	}
	shutdownReturnsPromptly(t, ts)
}

func TestApplyConfig200EtagAndHostArguments(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.result = apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: otherHash, Head: &apiclient.Head{Hash: "h", Count: 2}, Agents: 1, Workflows: 1, Roles: 1}
	resp, body := ts.postApply(t, goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": `"` + goodHash + `"`, "User-Agent": "cli/1", "X-Forwarded-For": "10.0.0.9"})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"`+otherHash+`"` {
		t.Fatalf("%d etag %q: %s", resp.StatusCode, resp.Header.Get("ETag"), body)
	}
	if res := decode[apiclient.ApplyResult](t, body); res.Status != apiclient.ApplyInstalled || res.ConfigHash != otherHash || res.Agents != 1 {
		t.Fatalf("%+v", res)
	}
	call := ts.config.last()
	if call.inv.Subject != testInvoker.Subject || call.inv.Method != "oidc" || call.pre != (apiclient.Precondition{ExpectInstalled: goodHash}) {
		t.Fatalf("host got inv %+v pre %+v", call.inv, call.pre)
	}
	if string(call.files["roles/ops.yaml"]) != goodBundle.Files["roles/ops.yaml"] || len(call.files) != 1 {
		t.Fatalf("host got files %q", call.files)
	}
	if o := call.via; o == nil || o.Via != "api" || o.RemoteAddr == "" || o.ServerHost != "127.0.0.1:0" || o.UserAgent != "cli/1" || o.ForwardedFor != "10.0.0.9" {
		t.Fatalf("host got origin %+v", call.via)
	}
}

func TestApplyConfigBootstrapHeaderMapsToExpectNone(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.result = apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: goodHash, Bootstrap: true, Head: &apiclient.Head{Hash: "h", Count: 1}}
	resp, body := ts.postApply(t, goodToken, mustJSON(t, goodBundle), map[string]string{"If-None-Match": "*"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if call := ts.config.last(); call.pre != (apiclient.Precondition{ExpectNone: true}) {
		t.Fatalf("pre = %+v", call.pre)
	}
	if res := decode[apiclient.ApplyResult](t, body); !res.Bootstrap {
		t.Fatalf("%+v", res)
	}
}

func TestApplyConfigStatusMapping(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	head := &apiclient.Head{Hash: "h", Count: 3}
	cases := []struct {
		name     string
		result   apiclient.ApplyResult
		code     int
		etag     string
		reason   string
		retry    bool
		exactRaw string
	}{
		{"412 with current", apiclient.ApplyResult{Status: apiclient.ApplyPreconditionFailed, CurrentHash: goodHash}, 412, `"` + goodHash + `"`, "", false, ""},
		{"412 nothing installed", apiclient.ApplyResult{Status: apiclient.ApplyPreconditionFailed}, 412, "", "", false, `{"status":"precondition_failed"}` + "\n"},
		{"403", apiclient.ApplyResult{Status: apiclient.ApplyRefused, Reason: "not authorized: no role grants apply to the invoker", ConfigHash: goodHash, Head: head}, 403, "", "not authorized: no role grants apply to the invoker", false, ""},
		{"422", apiclient.ApplyResult{Status: apiclient.ApplyRejected, Reason: "roles/a.yaml: x: bad", Errors: []string{"roles/a.yaml: x: bad", "roles/b.yaml: y: bad"}, ConfigHash: goodHash, Head: head}, 422, "", "roles/a.yaml: x: bad", false, ""},
		{"409 from host", apiclient.ApplyResult{Status: apiclient.ApplyBusy}, 409, "", "", true, `{"status":"busy"}` + "\n"},
		{"500 error hides OS text", apiclient.ApplyResult{Status: apiclient.ApplyError, Reason: "open /srv/.agenthof/installed/.staging-1: permission denied", Head: head}, 500, "", apiclient.ReasonStoreUnusable, false, ""},
		{"500 append failed", apiclient.ApplyResult{Status: apiclient.ApplyError, Reason: "whatever"}, 500, "", apiclient.ReasonNotRecorded, false, ""},
		{"500 ledger damaged", apiclient.ApplyResult{Status: apiclient.ApplyLedgerDamaged, Reason: "ledger torn at byte 9"}, 500, "", apiclient.ReasonLedgerDamaged, false, ""},
		{"500 installed not recorded", apiclient.ApplyResult{Status: apiclient.ApplyInstalledNotRecorded, ConfigHash: goodHash, Agents: 2, Workflows: 1, Roles: 2}, 500, "", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts.config.result = c.result
			resp, body := ts.postApply(t, goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
			if resp.StatusCode != c.code || resp.Header.Get("ETag") != c.etag {
				t.Fatalf("%d etag %q: %s", resp.StatusCode, resp.Header.Get("ETag"), body)
			}
			if c.retry != (resp.Header.Get("Retry-After") == "1") {
				t.Fatalf("Retry-After = %q", resp.Header.Get("Retry-After"))
			}
			if c.exactRaw != "" && string(body) != c.exactRaw {
				t.Fatalf("body %q, want %q", body, c.exactRaw)
			}
			res := decode[apiclient.ApplyResult](t, body)
			if res.Status != c.result.Status || res.Reason != c.reason {
				t.Fatalf("%+v, want status %s reason %q", res, c.result.Status, c.reason)
			}
			if c.name == "422" && len(res.Errors) != 2 {
				t.Fatalf("422 must return every line: %+v", res.Errors)
			}
			if c.name == "500 installed not recorded" && (res.Agents != 2 || res.ConfigHash != goodHash) {
				t.Fatalf("the counts and hash are known: %+v", res)
			}
			if strings.Contains(string(body), "/srv/") || strings.Contains(string(body), "torn at") {
				t.Fatalf("a 500 body must carry no host text: %s", body)
			}
		})
	}
}

func TestApplyConfig409WhileAnotherApplyIsInFlight(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.block = make(chan struct{})
	ts.config.result = apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: goodHash, Head: &apiclient.Head{Hash: "h", Count: 1}}
	first := ts.goApply(goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
	deadline := time.Now().Add(2 * time.Second)
	for ts.config.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first apply never reached the host")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp, body := ts.postApply(t, goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
	if resp.StatusCode != http.StatusConflict || string(body) != `{"status":"busy"}`+"\n" || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("second apply = %d %q retry %q", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
	if ts.config.count() != 1 {
		t.Fatal("the second apply must not reach the host")
	}
	close(ts.config.block)
	if r := <-first; r.err != nil || r.code != http.StatusOK {
		t.Fatalf("first apply = %d err %v", r.code, r.err)
	}
	shutdownReturnsPromptly(t, ts)
}

func TestApplyConfig503WhileDrainingAndShutdownWaitsForApply(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.block = make(chan struct{})
	ts.config.result = apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: goodHash, Head: &apiclient.Head{Hash: "h", Count: 1}}
	inflight := ts.goApply(goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
	for ts.config.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- ts.srv.Shutdown(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, body := ts.postApply(t, goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
		if resp.StatusCode == http.StatusServiceUnavailable {
			if strings.TrimSpace(string(body)) != "server is shutting down" {
				t.Fatalf("503 body %q", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("apply during drain = %d, want 503", resp.StatusCode)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned (%v) while an apply was in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(ts.config.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r := <-inflight; r.err != nil || r.code != http.StatusOK {
		t.Fatalf("the in-flight apply must finish: %d err %v", r.code, r.err)
	}
}

func TestApplyConfigLogsNeitherTokenNorBody(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.result = apiclient.ApplyResult{Status: apiclient.ApplyRefused, Reason: "not authorized: no role grants apply to the invoker", ConfigHash: goodHash, Head: &apiclient.Head{Hash: "h", Count: 1}}
	secret := apiclient.ApplyRequest{Files: map[string]string{"roles/ops.yaml": "name: SENTINEL-ROLE-BODY\n"}}
	ts.postApply(t, goodToken, mustJSON(t, secret), map[string]string{"If-Match": goodHash})
	logs := ts.logs.String()
	if strings.Contains(logs, goodToken) || strings.Contains(logs, "SENTINEL-ROLE-BODY") {
		t.Fatalf("the bearer and the body must never be logged:\n%s", logs)
	}
	if !strings.Contains(logs, "config apply") || !strings.Contains(logs, "status=refused") || !strings.Contains(logs, "invoker=dana@example.com") {
		t.Fatalf("one config apply line naming invoker and status expected:\n%s", logs)
	}
}
