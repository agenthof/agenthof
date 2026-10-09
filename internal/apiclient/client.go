package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrUnauthorized is a 401 from the server: the bearer was missing or
// rejected. The token itself never enters an error.
var ErrUnauthorized = errors.New("server rejected the token")

// StatusError is any other non-success answer, with the body capped so a
// misbehaving proxy cannot flood a terminal.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("server answered %d: %s", e.Code, e.Body) }

// Client speaks the serve API with one bearer.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New builds a client for base (scheme://host[:port]) with token. hc nil
// means a 30-second-timeout client.
func New(base, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: hc}
}

func (c *Client) do(ctx context.Context, method, path string, body any, prepare ...func(*http.Request)) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("server: bad request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json, text/plain")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, p := range prepare {
		p(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		return nil, ErrUnauthorized
	}
	return resp, nil
}

// readBody drains and caps a response body.
func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func statusError(resp *http.Response, body []byte) error {
	s := strings.TrimSpace(string(body))
	if utf8.RuneCountInString(s) > 200 {
		s = string([]rune(s)[:200])
	}
	return &StatusError{Code: resp.StatusCode, Body: s}
}

// StartRun posts a run. 202 and the refusal answers (403, 422) all decode
// into RunAccepted — a refusal is an outcome, not an error.
func (c *Client) StartRun(ctx context.Context, req RunRequest) (RunAccepted, error) {
	resp, err := c.do(ctx, http.MethodPost, "/v1/runs", req)
	if err != nil {
		return RunAccepted{}, err
	}
	body, err := readBody(resp)
	if err != nil {
		return RunAccepted{}, err
	}
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusForbidden, http.StatusUnprocessableEntity:
		var acc RunAccepted
		if err := json.Unmarshal(body, &acc); err != nil {
			return RunAccepted{}, fmt.Errorf("server: malformed answer: %w", err)
		}
		return acc, nil
	default:
		return RunAccepted{}, statusError(resp, body)
	}
}

// Apply posts a configuration bundle with its precondition: If-Match:
// sha256:<hex>, or If-None-Match: * for a bootstrap. Every governed answer
// — 200, 403, 412, 422, 409 and the 500s — decodes into ApplyResult: an
// outcome, not an error (the StartRun rule). 401 is ErrUnauthorized;
// anything else is a StatusError.
func (c *Client) Apply(ctx context.Context, req ApplyRequest, pre Precondition) (ApplyResult, error) {
	resp, err := c.do(ctx, http.MethodPost, "/v1/config/apply", req, func(r *http.Request) {
		if pre.ExpectNone {
			r.Header.Set("If-None-Match", "*")
		} else {
			r.Header.Set("If-Match", pre.ExpectInstalled)
		}
	})
	if err != nil {
		return ApplyResult{}, err
	}
	body, err := readBody(resp)
	if err != nil {
		return ApplyResult{}, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden, http.StatusPreconditionFailed, http.StatusUnprocessableEntity,
		http.StatusConflict, http.StatusInternalServerError:
		var res ApplyResult
		if err := json.Unmarshal(body, &res); err != nil {
			return ApplyResult{}, fmt.Errorf("server: malformed answer: %w", err)
		}
		return res, nil
	default:
		return ApplyResult{}, statusError(resp, body)
	}
}

// GetRun fetches a run's status.
func (c *Client) GetRun(ctx context.Context, id string) (RunStatus, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/runs/"+id, nil)
	if err != nil {
		return RunStatus{}, err
	}
	body, err := readBody(resp)
	if err != nil {
		return RunStatus{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return RunStatus{}, statusError(resp, body)
	}
	var st RunStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return RunStatus{}, fmt.Errorf("server: malformed answer: %w", err)
	}
	return st, nil
}

// WaitRun polls GetRun every interval until the run is no longer running.
func (c *Client) WaitRun(ctx context.Context, id string, every time.Duration) (RunStatus, error) {
	for {
		st, err := c.GetRun(ctx, id)
		if err != nil {
			return RunStatus{}, err
		}
		if st.Status != StatusRunning {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return RunStatus{}, ctx.Err()
		case <-time.After(every):
		}
	}
}

// Cancel asks the server to cancel a hosted run.
func (c *Client) Cancel(ctx context.Context, id string) (RunStatus, error) {
	resp, err := c.do(ctx, http.MethodPost, "/v1/runs/"+id+"/cancel", nil)
	if err != nil {
		return RunStatus{}, err
	}
	body, err := readBody(resp)
	if err != nil {
		return RunStatus{}, err
	}
	if resp.StatusCode != http.StatusAccepted {
		return RunStatus{}, statusError(resp, body)
	}
	var st RunStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return RunStatus{}, fmt.Errorf("server: malformed answer: %w", err)
	}
	return st, nil
}

// Audit fetches the server-rendered audit text and its integrity verdict.
func (c *Client) Audit(ctx context.Context, id string) (text, integrity string, err error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/runs/"+id+"/audit", nil)
	if err != nil {
		return "", "", err
	}
	body, err := readBody(resp)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", statusError(resp, body)
	}
	return string(body), resp.Header.Get(IntegrityHeader), nil
}

// Investigate fetches the investigate/1 document for q, verbatim.
func (c *Client) Investigate(ctx context.Context, q InvestigateQuery) ([]byte, error) {
	path := "/v1/investigate"
	if v := q.Values(); len(v) > 0 {
		path += "?" + v.Encode()
	}
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp, body)
	}
	return body, nil
}

// PullConfig fetches the installed configuration: 200 decodes into a
// ConfigSnapshot with Files; 401 is ErrUnauthorized; every other answer —
// 403, 404, the 500s, the retry 503s — is a StatusError carrying the fixed
// body (the GetRun rule: one JSON shape, on 200 only). The body is read
// under readBody's 8 MiB cap: a snapshot larger than that is refused as a
// malformed answer, never handed over truncated.
func (c *Client) PullConfig(ctx context.Context) (ConfigSnapshot, error) {
	return c.getSnapshot(ctx, "/v1/config")
}

// ConfigHash is PullConfig without Files — the cheap poll.
func (c *Client) ConfigHash(ctx context.Context) (ConfigSnapshot, error) {
	return c.getSnapshot(ctx, "/v1/config/hash")
}

func (c *Client) getSnapshot(ctx context.Context, path string) (ConfigSnapshot, error) {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	body, err := readBody(resp)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ConfigSnapshot{}, statusError(resp, body)
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("server: malformed answer: %w", err)
	}
	return snap, nil
}
