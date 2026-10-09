package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// The two key files beside the control store, as the CLI writes and reads
// them: signing.key is the operator's Ed25519 private key as PKCS#8 PEM
// (block type PRIVATE KEY — the form openssl pkey reads and writes, so an
// operator can inspect or back it up with standard tools); signing.pub is
// the public key as PKIX PEM (block type PUBLIC KEY — what the operator pins
// at every execution point). The CLI derives their paths; this package only
// encodes and parses them.
const (
	pemTypeSigningKey = "PRIVATE KEY"
	pemTypeSigningPub = "PUBLIC KEY"
)

// EncodeSigningKey renders priv as PKCS#8 PEM, trailing newline included.
func EncodeSigningKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeSigningKey, Bytes: der}), nil
}

// ParseSigningKey reads what EncodeSigningKey wrote. Any other block type,
// a key of any other algorithm, and any bytes after the first block are
// errors: a credential file is honored whole or not at all.
func ParseSigningKey(data []byte) (ed25519.PrivateKey, error) {
	der, err := onePEMBlock(data, pemTypeSigningKey)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key: %T; want Ed25519", key)
	}
	return priv, nil
}

// EncodeSigningPub renders pub as PKIX PEM, trailing newline included.
func EncodeSigningPub(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("signing public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeSigningPub, Bytes: der}), nil
}

// ParseSigningPub reads what EncodeSigningPub wrote, with the same refusals
// as ParseSigningKey.
func ParseSigningPub(data []byte) (ed25519.PublicKey, error) {
	der, err := onePEMBlock(data, pemTypeSigningPub)
	if err != nil {
		return nil, fmt.Errorf("signing public key: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("signing public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing public key: %T; want Ed25519", key)
	}
	return pub, nil
}

// onePEMBlock decodes exactly one block of the wanted type. Whitespace after
// it is what pem.Encode writes; anything else after it is refused — fail
// closed, never "ignore the rest".
func onePEMBlock(data []byte, wantType string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("PEM block type %q; want %q", block.Type, wantType)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after the PEM block")
	}
	return block.Bytes, nil
}
