package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
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
	keyExists, err := fileExists(keyPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	pubExists, err := fileExists(pubPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	switch {
	case keyExists && pubExists:
		_, _ = fmt.Fprintf(stderr, "card keygen: %s exists; refusing to overwrite — a new key means every gateway trusting the old one must be updated\n", keyPath)
		return 1
	case pubExists:
		_, _ = fmt.Fprintf(stderr, "card keygen: %s exists without its private key; remove it to generate a new pair (gateways trusting it must be updated)\n", pubPath)
		return 1
	case keyExists:
		// A lone private key is never discarded: re-derive the missing
		// public file from it.
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
			return 1
		}
		priv, err := config.ParseSigningKey(keyPEM)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "card keygen: %s: %v\n", keyPath, err)
			return 1
		}
		pub := priv.Public().(ed25519.PublicKey)
		pubPEM, err := config.EncodeSigningPub(pub)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
			return 1
		}
		if err := writeExclusive(pubPath, pubPEM); err != nil {
			removeIfPartial(pubPath, err)
			_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s already existed; wrote the missing %s\n", keyPath, pubPath)
		printCuratorKey(stdout, pub)
		return 0
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
		removeIfPartial(keyPath, err)
		_, _ = fmt.Fprintf(stderr, "card keygen: %v\n", err)
		return 1
	}
	if err := writeExclusive(pubPath, pubPEM); err != nil {
		removeIfPartial(pubPath, err)
		if rerr := os.Remove(keyPath); rerr != nil {
			_, _ = fmt.Fprintf(stderr, "card keygen: %v; could not remove %s: %v\n", err, keyPath, rerr)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "card keygen: %v; removed %s so no half-made pair is left\n", err, keyPath)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s (private key, 0600 — keep it with the curator)\n", keyPath)
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", pubPath)
	printCuratorKey(stdout, pub)
	return 0
}

// removeIfPartial removes path after a failed exclusive write, unless the
// failure was that it already existed (then it is not ours to remove).
func removeIfPartial(path string, writeErr error) {
	if errors.Is(writeErr, fs.ErrExist) {
		return
	}
	_ = os.Remove(path)
}

// printCuratorKey prints the public key and the kid in the form a
// trusted_signers entry takes.
func printCuratorKey(stdout io.Writer, pub ed25519.PublicKey) {
	key := base64.StdEncoding.EncodeToString(pub)
	kid := config.KeyID(pub)
	_, _ = fmt.Fprintf(stdout, "public_key: %s\n", key)
	_, _ = fmt.Fprintf(stdout, "kid: %s\n", kid)
	_, _ = fmt.Fprintf(stdout, "to trust cards signed with this key, add to the gateway configuration:\ntrusted_signers:\n  - {kid: %s, key: %s}\n", kid, key)
}

// cmdCardSign signs a card file with a curator key and writes the signed card
// to stdout (or --out). The card must parse and carry exactly one valid
// agenthof extension; anything else, a bad key, a kid that could not be a
// trusted_signers entry, or a signed card that does not parse and verify
// under the signer's own key is refused with nothing written.
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
	if !config.ValidSignerKID(*kid) {
		_, _ = fmt.Fprintf(stderr, "card sign: kid must be 1 to %d printable ASCII characters, no spaces: a trusted_signers entry cannot take any other\n", config.MaxSignerKIDLen)
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
	signed, err := agentcard.Sign(cardBytes, *kid, priv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
		return 1
	}
	// Check the result the way an enrolling gateway will, under this key's own
	// public half, so a card that cannot be enrolled is never written.
	signedCard, err := agentcard.Parse(signed)
	if err == nil {
		_, err = agentcard.Verify(signedCard, []agentcard.Anchor{{KID: *kid, Key: priv.Public().(ed25519.PublicKey)}})
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "card sign: the signed card would not enroll: %v\n", err)
		return 1
	}
	signed = append(signed, '\n')
	if *outPath != "" {
		if err := writeExclusive(*outPath, signed); err != nil {
			removeIfPartial(*outPath, err)
			_, _ = fmt.Fprintf(stderr, "card sign: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s\n", *outPath)
		return 0
	}
	_, _ = stdout.Write(signed)
	return 0
}
