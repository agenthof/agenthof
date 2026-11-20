package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

func TestValidateTrustedSigners(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	cases := []struct {
		name    string
		signers []config.TrustedSigner
		wantBad bool
	}{
		{"none", nil, false},
		{"valid", []config.TrustedSigner{{KID: "curator-1", Key: good}}, false},
		{"empty kid", []config.TrustedSigner{{KID: "", Key: good}}, true},
		{"kid with space", []config.TrustedSigner{{KID: "a b", Key: good}}, true},
		{"kid too long", []config.TrustedSigner{{KID: strings.Repeat("k", config.MaxSignerKIDLen+1), Key: good}}, true},
		{"duplicate kid", []config.TrustedSigner{{KID: "k", Key: good}, {KID: "k", Key: good}}, true},
		{"not base64", []config.TrustedSigner{{KID: "k", Key: "!!!"}}, true},
		{"short key", []config.TrustedSigner{{KID: "k", Key: base64.StdEncoding.EncodeToString([]byte("short"))}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseCfg()
			cfg.Gateway.TrustedSigners = c.signers
			if got := hasCode(Validate(cfg), "bad-trusted-signer"); got != c.wantBad {
				t.Fatalf("bad-trusted-signer = %v, want %v", got, c.wantBad)
			}
		})
	}
}
