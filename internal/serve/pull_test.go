package serve

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
)

var pulledSnapshot = apiclient.ConfigSnapshot{
	Hash: goodHash, Version: 7, InstalledAt: time.Date(2026, 10, 9, 2, 12, 1, 0, time.UTC),
	Files: map[string]string{"roles/ops.yaml": "name: ops\ncontrol: [apply]\nallowed_groups: [engineering]\n"},
}

func TestPullConfig401NeverCallsHost(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	for _, path := range []string{"/v1/config", "/v1/config/hash"} {
		for _, token := range []string{"", "wrong"} {
			resp, body := ts.do(t, http.MethodGet, path, token, nil)
			if resp.StatusCode != http.StatusUnauthorized || strings.TrimSpace(string(body)) != "unauthorized" {
				t.Fatalf("%s token %q: %d %q", path, token, resp.StatusCode, body)
			}
		}
	}
	if ts.config.pullCount() != 0 {
		t.Fatal("an unauthenticated request must never reach the host")
	}
}

func TestPullConfigStatusMapping(t *testing.T) {
	cases := []struct {
		status     string
		code       int
		body       string
		retryAfter bool
	}{
		{PullNothingInstalled, http.StatusNotFound, "no configuration installed", false},
		{PullRefused, http.StatusForbidden, apiclient.PullBodyRefused, false},
		{PullStoreUnusable, http.StatusInternalServerError, apiclient.ReasonStoreUnusable, false},
		{PullNotBundleable, http.StatusInternalServerError, apiclient.PullBodyNotBundleable, false},
		{PullLedgerDamaged, http.StatusInternalServerError, apiclient.ReasonLedgerDamaged, false},
		{PullBusy, http.StatusServiceUnavailable, apiclient.PullBodyBusy, true},
		{PullNotRecorded, http.StatusServiceUnavailable, apiclient.PullBodyNotRecorded, true},
		{PullNotSigned, http.StatusServiceUnavailable, apiclient.PullBodyNotSigned, true},
		{"something-new", http.StatusInternalServerError, apiclient.ReasonStoreUnusable, false},
	}
	for _, path := range []string{"/v1/config", "/v1/config/hash"} {
		for _, c := range cases {
			t.Run(path+" "+c.status, func(t *testing.T) {
				ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
				ts.config.pull = PullResult{Status: c.status}
				resp, body := ts.do(t, http.MethodGet, path, goodToken, nil)
				if resp.StatusCode != c.code || strings.TrimSpace(string(body)) != c.body {
					t.Fatalf("%d %q, want %d %q", resp.StatusCode, body, c.code, c.body)
				}
				if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
					t.Fatalf("non-200 bodies are text: %q", resp.Header.Get("Content-Type"))
				}
				if got := resp.Header.Get("Retry-After"); (got == "1") != c.retryAfter {
					t.Fatalf("Retry-After %q, want present=%v", got, c.retryAfter)
				}
				if resp.Header.Get("ETag") != "" {
					t.Fatal("no ETag on a non-200")
				}
				if ts.config.pullCount() != 1 {
					t.Fatalf("host called %d times, want 1", ts.config.pullCount())
				}
			})
		}
	}
}

func TestPullConfig200AndHashRouteShareOnePull(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.pull = PullResult{Status: PullOK, Snapshot: pulledSnapshot}

	resp, body := ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"`+goodHash+`"` || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d etag %q ct %q", resp.StatusCode, resp.Header.Get("ETag"), resp.Header.Get("Content-Type"))
	}
	snap := decode[apiclient.ConfigSnapshot](t, body)
	if snap.Hash != goodHash || snap.Version != 7 || !snap.InstalledAt.Equal(pulledSnapshot.InstalledAt) || snap.Files["roles/ops.yaml"] != pulledSnapshot.Files["roles/ops.yaml"] {
		t.Fatalf("%+v", snap)
	}
	if got := ts.config.lastPull(); got.Subject != testInvoker.Subject {
		t.Fatalf("the verified invoker must reach the host: %+v", got)
	}

	resp, body = ts.do(t, http.MethodGet, "/v1/config/hash", goodToken, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"`+goodHash+`"` {
		t.Fatalf("%d etag %q", resp.StatusCode, resp.Header.Get("ETag"))
	}
	if strings.Contains(string(body), `"files"`) {
		t.Fatalf("the hash route must omit files: %s", body)
	}
	if hashOnly := decode[apiclient.ConfigSnapshot](t, body); hashOnly.Hash != goodHash || hashOnly.Version != 7 || hashOnly.Files != nil {
		t.Fatalf("%+v", hashOnly)
	}
	if ts.config.pullCount() != 2 {
		t.Fatal("both routes run the host's one Pull")
	}
	// No wildcard under /v1/config/: a named snapshot is not a route.
	if resp, _ := ts.do(t, http.MethodGet, "/v1/config/"+goodHash, goodToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/v1/config/{hash} = %d, want 404", resp.StatusCode)
	}
}

// TestPullConfigServedThroughDrain: a pull is a read — answered 200 while
// an apply is in flight and the server is draining, and Shutdown does not
// wait on it.
func TestPullConfigServedThroughDrain(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.block = make(chan struct{})
	ts.config.result = apiclient.ApplyResult{Status: apiclient.ApplyInstalled, ConfigHash: goodHash, Head: &apiclient.Head{Hash: "h", Count: 1}}
	ts.config.pull = PullResult{Status: PullOK, Snapshot: pulledSnapshot}
	inflight := ts.goApply(goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
	for ts.config.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- ts.srv.Shutdown(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, _ := ts.postApply(t, goodToken, mustJSON(t, goodBundle), map[string]string{"If-Match": goodHash})
		if resp.StatusCode == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the drain never started")
		}
	}
	resp, body := ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull during drain = %d %q, want 200", resp.StatusCode, body)
	}
	if resp, _ := ts.do(t, http.MethodGet, "/v1/config/hash", goodToken, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("hash poll during drain = %d, want 200", resp.StatusCode)
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

func TestPullConfigLogsOnceAndNeverTheToken(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.pull = PullResult{Status: PullOK, Snapshot: pulledSnapshot}
	ts.do(t, http.MethodGet, "/v1/config/hash", goodToken, nil)
	if logs := ts.logs.String(); strings.Contains(logs, "config pulled") {
		t.Fatalf("the hash poll must not log a pull line:\n%s", logs)
	}
	ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	logs := ts.logs.String()
	if !strings.Contains(logs, "config pulled") || !strings.Contains(logs, "invoker=dana@example.com") || !strings.Contains(logs, "hash="+goodHash) || !strings.Contains(logs, "version=7") {
		t.Fatalf("one Info line naming invoker, hash and version expected:\n%s", logs)
	}
	if strings.Contains(logs, goodToken) || strings.Contains(logs, "name: ops") {
		t.Fatalf("neither the bearer nor the files may be logged:\n%s", logs)
	}
	ts.logs.Reset()
	ts.config.pull = PullResult{Status: PullRefused}
	ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	if logs := ts.logs.String(); !strings.Contains(logs, "config pull refused") || !strings.Contains(logs, "invoker=dana@example.com") {
		t.Fatalf("a refusal is one Warn line naming the invoker:\n%s", logs)
	}
	ts.logs.Reset()
	ts.config.pull = PullResult{Status: PullStoreUnusable}
	ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	if logs := ts.logs.String(); strings.Contains(logs, "config pull") {
		t.Fatalf("a 500 writes no handler line (the host already logged the cause):\n%s", logs)
	}
}

// TestPullHandlerSourceNeverAdmitsOrRecords pins by source that the pull
// handler takes no drain gate and writes no ledger.
func TestPullHandlerSourceNeverAdmitsOrRecords(t *testing.T) {
	src, err := os.ReadFile("handlers_pull.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"admit(", "reserve(", ".wg.", "control.Append", "ledger.Open("} {
		if strings.Contains(string(src), forbidden) {
			t.Fatalf("handlers_pull.go must not contain %q: a pull is a read served through the drain", forbidden)
		}
	}
}

var signedSnapshot = apiclient.ConfigSnapshot{
	Hash: goodHash, Version: 7, InstalledAt: time.Date(2026, 10, 9, 2, 12, 1, 500000000, time.UTC),
	Files: map[string]string{"roles/ops.yaml": "name: ops\ncontrol: [apply]\nallowed_groups: [engineering]\n"},
	Signature: &apiclient.ConfigSignature{Format: "agenthof-config-signature/v1", LogID: "00112233445566778899aabbccddeeff",
		KeyID: "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
		Sig:   "7Zj+G/3H5lmX+zAr8dVH+/R9r0f08gA7DLnMYD4x7OkIn/JG51vkZsUybg4O7USrgfhnQJgw488YTrPxqsGODg=="},
}

// TestPullConfigBothRoutesCarryTheSignature: the full pull and the hash
// poll both carry the signature object verbatim (the poll lets an edge
// verify BEFORE it fetches the files); the full pull's log line names the
// key id; the poll logs nothing.
func TestPullConfigBothRoutesCarryTheSignature(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ts.config.pull = PullResult{Status: PullOK, Snapshot: signedSnapshot}
	const sigJSON = `"signature":{"format":"agenthof-config-signature/v1","log_id":"00112233445566778899aabbccddeeff","key_id":"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c","sig":"7Zj+G/3H5lmX+zAr8dVH+/R9r0f08gA7DLnMYD4x7OkIn/JG51vkZsUybg4O7USrgfhnQJgw488YTrPxqsGODg=="}`
	resp, body := ts.do(t, http.MethodGet, "/v1/config/hash", goodToken, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), sigJSON) || strings.Contains(string(body), `"files"`) {
		t.Fatalf("hash route: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(ts.logs.String(), "config pulled") {
		t.Fatalf("the poll logs nothing:\n%s", ts.logs.String())
	}
	resp, body = ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), sigJSON) || !strings.Contains(string(body), `"files"`) {
		t.Fatalf("full route: %d %s", resp.StatusCode, body)
	}
	snap := decode[apiclient.ConfigSnapshot](t, body)
	if snap.Signature == nil || *snap.Signature != *signedSnapshot.Signature {
		t.Fatalf("%+v", snap.Signature)
	}
	logs := ts.logs.String()
	if !strings.Contains(logs, "config pulled") || !strings.Contains(logs, "key_id="+signedSnapshot.Signature.KeyID) || strings.Contains(logs, signedSnapshot.Signature.Sig) {
		t.Fatalf("the 200 line names the key id, never the signature bytes:\n%s", logs)
	}
	// Not signed: a retryable 503 with the fixed body, logged once at Info.
	ts.logs.Reset()
	ts.config.pull = PullResult{Status: PullNotSigned}
	resp, body = ts.do(t, http.MethodGet, "/v1/config", goodToken, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || strings.TrimSpace(string(body)) != apiclient.PullBodyNotSigned || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("%d %q %q", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
	if logs := ts.logs.String(); !strings.Contains(logs, "level=INFO") || !strings.Contains(logs, "status=not_signed") || strings.Contains(logs, "config sign") {
		t.Fatalf("one Info status line, no remedy (the host's Warn carries it):\n%s", logs)
	}
}
