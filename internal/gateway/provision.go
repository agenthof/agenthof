package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/agenthof/agenthof/internal/config"
)

// sanitizeURLErr strips any query string (which may carry a secret, e.g.
// checkKey's "?key=<key>") out of a *url.Error before it can reach a log
// line or a printed error. net/http's transport embeds the full request
// URL, query string included, in both *http.NewRequest's parse errors and
// the error returned by (*http.Client).Do — so this must wrap both call
// sites, not just one, or the redaction is bypassed by whichever path
// happens to fail.
func sanitizeURLErr(err error) error {
	if u, ok := errors.AsType[*url.Error](err); ok {
		return fmt.Errorf("%s %s: %w", u.Op, redactURL(u.URL), u.Err)
	}
	return err
}

// redactURL replaces a URL's query string with a fixed marker, so a secret
// passed as a query parameter (e.g. "?key=sk-...") never appears in an
// error message.
func redactURL(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i] + "?[redacted]"
	}
	return s
}

// Provisioner talks to a LiteLLM-compatible admin API to provision and
// verify per-role API keys.
type Provisioner struct {
	AdminBase string
	MasterKey string
	HTTP      *http.Client
}

func (p Provisioner) httpClient() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}

// EnsureRoleKey makes sure role has a valid, budgeted API key stored under
// root, generating one via the admin API if needed. Roles with no budget
// are skipped entirely (no HTTP calls, no key file). created reports
// whether a new key was generated.
func (p Provisioner) EnsureRoleKey(root string, role config.RoleDef) (created bool, err error) {
	if role.BudgetUSDMonth <= 0 {
		return false, nil
	}

	if existing := LoadRoleKey(root, role.Name); existing != "" {
		valid, err := p.checkKey(existing)
		if err != nil {
			return false, err
		}
		if valid {
			return false, nil
		}
	}

	key, err := p.generateKey(role)
	if err != nil {
		return false, err
	}

	path := RoleKeyPath(root, role.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("gateway: creating key directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return false, fmt.Errorf("gateway: writing key file: %w", err)
	}

	return true, nil
}

// checkKey asks the admin API whether key is still valid. It returns
// (true, nil) on a 200 response, (false, nil) on 404/401 (key should be
// regenerated), and an error for any other status.
func (p Provisioner) checkKey(key string) (bool, error) {
	q := url.Values{"key": {key}}
	reqURL := p.AdminBase + "/key/info?" + q.Encode()

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("gateway: building key info request: %w", sanitizeURLErr(err))
	}
	req.Header.Set("Authorization", "Bearer "+p.MasterKey)

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return false, fmt.Errorf("gateway: key info request failed: %w", sanitizeURLErr(err))
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("gateway: key info returned status %d", resp.StatusCode)
	}
}

// generateKey requests a new API key for role from the admin API.
func (p Provisioner) generateKey(role config.RoleDef) (string, error) {
	body, err := json.Marshal(map[string]any{
		"key_alias":  "agenthof-" + role.Name,
		"max_budget": role.BudgetUSDMonth,
	})
	if err != nil {
		return "", fmt.Errorf("gateway: encoding key generate request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, p.AdminBase+"/key/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("gateway: building key generate request: %w", sanitizeURLErr(err))
	}
	req.Header.Set("Authorization", "Bearer "+p.MasterKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("gateway: key generate request failed: %w", sanitizeURLErr(err))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gateway: key generate returned status %d", resp.StatusCode)
	}

	var out struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("gateway: decoding key generate response: %w", err)
	}
	if out.Key == "" {
		return "", fmt.Errorf("gateway: key generate response missing key")
	}

	return out.Key, nil
}
