package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/agenthof/agenthof/internal/agentcard"
	"github.com/agenthof/agenthof/internal/config"
)

const (
	curatorKeyName = "curator.key"
	curatorPubName = "curator.pub"
)

// cmdCard is `card`: the curator's side of the agent-card trust relationship.
// keygen makes a curator signing pair; sign signs a card with it. Both are
// local file operations: neither reads or edits a configuration, and neither
// talks to a ledger. The operator who enrolls the card decides separately to
// trust the printed public key by adding it to trusted_signers.
func cmdCard(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(stderr, "usage: agenthof card keygen [--dir <dir>] | agenthof card sign --key <curator.key> --kid <kid> [--out <path>] <card.json>")
		return 2
	}
	switch args[0] {
	case "keygen":
		return cmdCardKeygen(args[1:], stdout, stderr)
	case "sign":
		return cmdCardSign(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "card: unknown subcommand %q (want keygen or sign)\n", args[0])
	return 2
}

// cmdCardKeygen writes a new curator Ed25519 pair (curator.key, 0600, and
// curator.pub) under --dir and prints the public key in the form a
// trusted_signers entry takes: the raw 32 bytes in standard base64. It never
// overwrites: if either file exists it refuses and writes nothing. The
// private key is never printed.
func cmdCardKeygen(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("card keygen", flag.ContinueOnError)
	dir := flags.String("dir", ".", "directory to write curator.key and curator.pub into")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "card keygen: takes no arguments")
		return 2
	}
	keyPath, pubPath := filepath.Join(*dir, curatorKeyName), filepath.Join(*dir, curatorPubName)
	for _, p := range []string{keyPath, pubPath} {
		exists, err := fileExists(p)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
			return 1
		}
		if exists {
			_, _ = fmt.Fprintf(stderr, "card keygen: %s exists; refusing to overwrite — remove curator.key and curator.pub to start over\n", p)
			return 1
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	keyPEM, err := config.EncodeSigningKey(priv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	pubPEM, err := config.EncodeSigningPub(pub)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	if err := writeExclusive(keyPath, keyPEM); err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	if err := writeExclusive(pubPath, pubPEM); err != nil {
		_ = os.Remove(keyPath)
		_, _ = fmt.Fprintf(stderr, "card keygen: %v; removed %s so no half-made pair is left\n", err, keyPath)
		return 1
	}
	key := base64.StdEncoding.EncodeToString(pub)
	kid := config.KeyID(pub)
	_, _ = fmt.Fprintf(stdout, "wrote %s (private key, 0600 — keep it with the curator)\n", keyPath)
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", pubPath)
	_, _ = fmt.Fprintf(stdout, "public_key: %s\n", key)
	_, _ = fmt.Fprintf(stdout, "kid: %s\n", kid)
	_, _ = fmt.Fprintf(stdout, "to trust cards signed with this key, add to the gateway configuration:\ntrusted_signers:\n  - {kid: %s, key: %s}\n", kid, key)
	return 0
}

// cmdCardSign signs a card file with a curator key and writes the signed card
// to stdout (or --out). The card must parse and carry exactly one valid
// agenthof extension; anything else, a bad key, or a bad kid is refused with
// nothing written.
func cmdCardSign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("card sign", flag.ContinueOnError)
	keyFile := flags.String("key", "", "curator private key file (from card keygen)")
	kid := flags.String("kid", "", "key id the signature names; must match a trusted_signers kid at the enrolling gateway")
	outPath := flags.String("out", "", "write the signed card here instead of stdout (never overwrites)")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 || *keyFile == "" || *kid == "" {
		_, _ = fmt.Fprintln(stderr, "usage: agenthof card sign --key <curator.key> --kid <kid> [--out <path>] <card.json>")
		return 2
	}
	if len(*kid) > config.MaxSignerKIDLen {
		_, _ = fmt.Fprintf(stderr, "card sign: kid is %d bytes, over the %d byte limit\n", len(*kid), config.MaxSignerKIDLen)
		return 1
	}
	cardBytes, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
		return 1
	}
	card, err := agentcard.Parse(cardBytes)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
		return 1
	}
	if _, err := card.Extension(); err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
		return 1
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
		return 1
	}
	priv, err := config.ParseSigningKey(keyPEM)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %s: %v\n", *keyFile, err)
		return 1
	}
	if len(priv) != ed25519.PrivateKeySize {
		_, _ = fmt.Fprintf(stderr, "card sign: %s: %v\n", *keyFile, errors.New("private key has the wrong length"))
		return 1
	}
	signed, err := agentcard.Sign(cardBytes, *kid, priv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
		return 1
	}
	signed = append(signed, '\n')
	if *outPath != "" {
		if err := writeExclusive(*outPath, signed); err != nil {
			_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s\n", *outPath)
		return 0
	}
	_, _ = stdout.Write(signed)
	return 0
}
