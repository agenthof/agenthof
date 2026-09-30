package main

import "net/http"

// token answers RFC 8693 token exchange. Not served yet: every request is
// refused so the program never issues a token it cannot account for.
func (p *idp) token(w http.ResponseWriter, _ *http.Request) {
	writeOAuthError(w, http.StatusNotImplemented, "unsupported_grant_type", "token exchange is not served yet")
}
