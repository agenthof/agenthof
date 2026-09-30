package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
)

// token answers RFC 8693 token exchange. The requesting client is
// authenticated with client_secret_basic (RFC 6749 §2.3.1: id and secret
// are form-urlencoded before Basic); the subject token must be one of this
// provider's own, of the configured subject_token_type; the requested
// audience must be on the allowlist. The issued token copies the subject's
// sub and names the requested audience — the upstream reads both.
func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	user, pass, ok := r.BasicAuth()
	id, _ := url.QueryUnescape(user)
	secret, _ := url.QueryUnescape(pass)
	if !ok || subtle.ConstantTimeCompare([]byte(id), []byte(p.clientID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(p.clientSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="obo-idp"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form did not parse")
		return
	}
	if r.Form.Get("grant_type") != grantExchange {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only token exchange is served")
		return
	}
	if r.Form.Get("subject_token_type") != p.subjectTokenType {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unexpected subject_token_type")
		return
	}
	claims, err := p.verify(r.Form.Get("subject_token"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject token rejected: "+err.Error())
		return
	}
	audience := r.Form.Get("audience")
	if audience == "" || !p.audiences[audience] {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "audience is not one this server issues for")
		return
	}
	sub, _ := claims["sub"].(string)
	now := p.now()
	access, err := p.sign(map[string]any{
		"iss": p.issuer, "sub": sub, "aud": audience, "iat": now.Unix(), "exp": now.Add(p.lifetime).Unix(),
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "sign failed")
		return
	}
	if p.tokenLog != nil {
		p.mu.Lock()
		_ = json.NewEncoder(p.tokenLog).Encode(map[string]string{"sub": sub, "aud": audience, "token": access})
		p.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      access,
		"issued_token_type": issuedTokenType,
		"token_type":        "Bearer",
		"expires_in":        int(p.lifetime.Seconds()),
	})
}
