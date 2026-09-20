// Package ledger implements a shared, raw-byte-verified hash-chain for
// JSONL ledgers. Each line is a JSON object embedding "prev": the
// lowercase-hex SHA-256 of the exact on-disk bytes of the previous
// line, EXCLUDING its trailing '\n' (genesis "prev" is ""). Hashing is
// always over the literal on-disk bytes, never a re-marshaled form, so
// even a stray '\r' from CRLF endings changes the hash and is caught.
// Records may also embed "seq": if the first record has one, every
// record must, contiguous from 1; if not, none may.
//
// Open and ReadVerify classify any damage into exactly one bucket.
// Torn (*TornError) is only ever the FINAL record: a missing trailing
// newline, a NUL byte in it, or a JSON syntax error (including a
// missing "prev", unparseable for chain purposes) — the tail of an
// apparently interrupted write. Broken (*ChainBrokenError) is any
// record, final or not, whose JSON parses but disagrees with the
// chain: a wrong "prev", a "seq" breaking contiguity or the chain's
// seq/no-seq mode, or (non-final only) a JSON syntax error. Either way
// the valid prefix verified before the problem is returned with its
// Head, so a caller can decide how to proceed (e.g. truncate a torn
// tail).
//
// Honesty limit: only damage leaving a structural or cryptographic
// trace is detectable. Deleting whole records off the END of the file
// is INVISIBLE here — the truncated file is a valid, shorter chain.
// Catching that needs a caller-held expected Head; this package keeps
// none itself.
//
// LockMode lets callers request Locked coordination across processes.
// Locked uses flock(2) (via syscall.Flock) to coordinate real,
// independent OS processes sharing a ledger file: Open takes an
// exclusive lock (LOCK_EX) and ReadVerify takes a shared lock
// (LOCK_SH), both non-blocking with a bounded retry loop, and Close
// releases the lock before closing the file. Because it depends on
// syscall.Flock, Locked mode is unix-only by design: this package
// does not build a Windows-compatible locking path, and a Windows
// compile failure here is the intended, recorded outcome, not a bug.
package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockTimeout bounds how long Open(Locked) and ReadVerify(path, Locked)
// will retry a contended flock before giving up. Unexported so tests can
// override it to keep contention tests fast.
var lockTimeout = 5 * time.Second

// lockRetryInterval is the sleep between non-blocking flock attempts.
const lockRetryInterval = 50 * time.Millisecond

// errLockHeld is the pinned error returned (wrapped with the failed
// operation's context) when a Locked Open/ReadVerify cannot acquire the
// flock within lockTimeout.
var errLockHeld = errors.New("another agenthof process holds the ledger lock")

// flockRetry attempts a non-blocking flock(fd, how) in a loop, sleeping
// lockRetryInterval between attempts, retrying EINTR indefinitely (it
// never indicates real contention), and giving up once lockTimeout has
// elapsed since the first attempt. This mirrors the retry pattern used by
// Go's own cmd/go/internal/lockedfile for non-blocking flock attempts.
func flockRetry(fd int, how int) error {
	deadline := time.Now().Add(lockTimeout)
	for {
		err := syscall.Flock(fd, how)
		if err == nil {
			return nil
		}
		if err == syscall.EINTR {
			continue
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		if time.Now().After(deadline) {
			return errLockHeld
		}
		time.Sleep(lockRetryInterval)
	}
}

// LockMode selects how Open coordinates access to the ledger file.
type LockMode int

const (
	// Unlocked performs no cross-process coordination.
	Unlocked LockMode = iota
	// Locked takes a flock(2) on the ledger file to coordinate real,
	// independent OS processes: exclusive (LOCK_EX) for Open, shared
	// (LOCK_SH) for ReadVerify. See the package doc for details.
	Locked
)

// Head describes the tip of a verified chain. Hash is "" for an empty
// (zero-record) ledger.
type Head struct {
	Hash  string
	Count int
}

// TornError reports that the final record looks like the tail of an
// interrupted write. Offset is where the incomplete tail begins (the
// end of the last fully verified record).
type TornError struct{ Offset int64 }

func (e *TornError) Error() string {
	return fmt.Sprintf("ledger torn at byte %d: last record incomplete", e.Offset)
}

// ChainBrokenError reports that the record at the given 1-based line
// disagrees with the hash chain.
type ChainBrokenError struct{ Line int }

func (e *ChainBrokenError) Error() string {
	return fmt.Sprintf("ledger chain broken at line %d", e.Line)
}

// Record is one verified line, exactly as it appears on disk, without
// its trailing newline.
type Record struct{ Raw []byte }

// Chain is a writable handle on an open ledger file.
type Chain struct {
	f              *os.File
	mode           LockMode
	prevHash       string
	count          int
	seqEstablished bool
	seqMode        bool
}

// lineFields is the minimal shape needed to verify the chain; every
// other field in a record is opaque to this package.
type lineFields struct {
	Prev *string `json:"prev"`
	Seq  *uint64 `json:"seq"`
}

// parseLineFields errors both on a JSON syntax error and on a
// syntactically valid object missing "prev" — both make the line
// unparseable for chain purposes (present-but-empty "prev" is fine;
// that is the genesis record).
func parseLineFields(raw []byte) (lineFields, error) {
	var p lineFields
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Prev == nil {
		return p, fmt.Errorf(`missing "prev" field`)
	}
	return p, nil
}

// Open opens (creating it if needed) the ledger at path and verifies
// it, resuming the chain from wherever it left off. If the file is
// torn or its chain is broken, Open returns the typed error and NO
// Chain.
func Open(path string, mode LockMode) (*Chain, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_, statErr := os.Stat(path)
	existed := statErr == nil
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if !existed {
		if d, derr := os.Open(dir); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	if mode == Locked {
		if lerr := flockRetry(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lerr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("ledger: open %s: %w", path, lerr)
		}
	}
	_, head, seqEstablished, seqMode, err := loadChain(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Chain{
		f: f, mode: mode,
		prevHash: head.Hash, count: head.Count,
		seqEstablished: seqEstablished, seqMode: seqMode,
	}, nil
}

// Prev returns the current chain head hash ("" for an empty chain).
func (c *Chain) Prev() string { return c.prevHash }

// Count returns the number of records verified/appended so far.
func (c *Chain) Count() int { return c.count }

// Append writes line (WITHOUT a trailing newline) to the ledger. It
// refuses (an anti-fork guard) if line's embedded "prev" does not
// match the current head, and, once the chain's seq mode is
// established, enforces contiguous "seq" values or their absence.
func (c *Chain) Append(line []byte) error {
	fields, err := parseLineFields(line)
	if err != nil {
		return fmt.Errorf("ledger: invalid record: %w", err)
	}
	// prev is checked first: a forged/forked probe must never reach the
	// seq logic, and a call wrong on both counts is reported as a fork.
	if *fields.Prev != c.prevHash {
		return fmt.Errorf("ledger: refusing append: line prev %q != chain head %q", *fields.Prev, c.prevHash)
	}
	// Decide seq mode into locals — a rejected call must never mutate
	// chain state, so c.seqEstablished/c.seqMode are only committed
	// below, alongside prevHash/count, once the write has succeeded.
	seqEstablished, seqMode := c.seqEstablished, c.seqMode
	if !seqEstablished {
		seqMode = fields.Seq != nil
	}
	if seqMode {
		if fields.Seq == nil || *fields.Seq != uint64(c.count+1) {
			return fmt.Errorf("ledger: invalid record: seq must be %d", c.count+1)
		}
	} else if fields.Seq != nil {
		return fmt.Errorf("ledger: invalid record: chain is not in seq mode")
	}

	buf := make([]byte, len(line)+1)
	copy(buf, line)
	buf[len(line)] = '\n'
	if _, err := c.f.Write(buf); err != nil {
		return err
	}
	if err := c.f.Sync(); err != nil {
		return err
	}
	sum := sha256.Sum256(line)
	c.prevHash = hex.EncodeToString(sum[:])
	c.count++
	c.seqEstablished = true
	c.seqMode = seqMode
	return nil
}

// Close releases the flock (if this Chain was opened Locked) and closes
// the underlying file. The lock is released before the file is closed.
func (c *Chain) Close() error {
	if c.mode == Locked {
		_ = syscall.Flock(int(c.f.Fd()), syscall.LOCK_UN)
	}
	return c.f.Close()
}

// ReadVerify loads and verifies the ledger at path read-only. On
// failure it still returns the valid prefix and its Head alongside the
// typed error — never just the bare error. With mode Locked, it takes a
// shared flock (LOCK_SH) first, so it blocks (up to lockTimeout) while
// another process holds the exclusive lock via Open(path, Locked), and
// releases it before returning.
func ReadVerify(path string, mode LockMode) ([]Record, Head, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, Head{}, err
	}
	defer f.Close()
	if mode == Locked {
		if lerr := flockRetry(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); lerr != nil {
			return nil, Head{}, fmt.Errorf("ledger: read %s: %w", path, lerr)
		}
		defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	}
	records, head, _, _, err := loadChain(f)
	return records, head, err
}

// loadChain reads r as newline-delimited records and verifies the
// chain per the torn/broken matrix documented above. It always returns
// the valid prefix found, that prefix's Head, and the resolved seq
// mode, even on error.
func loadChain(r io.Reader) (records []Record, head Head, seqEstablished, seqMode bool, err error) {
	type rawLine struct {
		raw        []byte
		terminated bool
	}
	var lines []rawLine
	br := bufio.NewReader(r)
	for {
		chunk, rerr := br.ReadBytes('\n')
		if len(chunk) == 0 && rerr != nil {
			break
		}
		terminated := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
		raw := chunk
		if terminated {
			raw = chunk[:len(chunk)-1]
		}
		lines = append(lines, rawLine{raw: raw, terminated: terminated})
		if rerr != nil {
			break
		}
	}
	if len(lines) == 0 {
		return nil, Head{}, false, false, nil
	}

	var prevHash string
	var count int
	var byteOffset int64
	fail := func(e error) ([]Record, Head, bool, bool, error) {
		return records, Head{Hash: prevHash, Count: count}, seqEstablished, seqMode, e
	}
	n := len(lines)
	for i, ln := range lines {
		isFinal := i == n-1
		// A torn write can only ever leave the tail short, so
		// structural damage is attributed only to the final record.
		if isFinal && (!ln.terminated || bytes.IndexByte(ln.raw, 0) >= 0) {
			return fail(&TornError{Offset: byteOffset})
		}
		fields, perr := parseLineFields(ln.raw)
		if perr != nil {
			if isFinal {
				return fail(&TornError{Offset: byteOffset})
			}
			return fail(&ChainBrokenError{Line: i + 1})
		}
		if !seqEstablished {
			seqMode = fields.Seq != nil
			seqEstablished = true
		} else if seqMode != (fields.Seq != nil) {
			return fail(&ChainBrokenError{Line: i + 1})
		}
		if seqMode && *fields.Seq != uint64(i+1) {
			return fail(&ChainBrokenError{Line: i + 1})
		}
		if *fields.Prev != prevHash {
			return fail(&ChainBrokenError{Line: i + 1})
		}
		sum := sha256.Sum256(ln.raw)
		prevHash = hex.EncodeToString(sum[:])
		count++
		byteOffset += int64(len(ln.raw)) + 1
		records = append(records, Record{Raw: ln.raw})
	}
	return records, Head{Hash: prevHash, Count: count}, seqEstablished, seqMode, nil
}
