package config

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// verify.floor is an execution point's memory of the highest (log_id,
// version) whose operator signature it has verified: one line, two fields,
// "\n"-terminated, nothing else —
//
//	<log_id> <version>\n
//
// log_id is the control ledger's genesis id (32 lowercase hex, logIDRE);
// version is the installing event's seq as the shortest decimal ≥ 1
// (versionRE: never 07, +7, 7.0 or 0); one ASCII space between; no CR, no
// surrounding whitespace, no second line. Self-describing enough to cat. The
// CLI derives the file's path and names the file in its errors; this package
// only encodes and parses, and reports the bare fault.

// VerifyFloorBytes renders the floor line. logID and version are the SIGNED
// values the caller just verified, so they already satisfy the grammar.
func VerifyFloorBytes(logID string, version int) []byte {
	return []byte(logID + " " + strconv.Itoa(version) + "\n")
}

// ParseVerifyFloor reads what VerifyFloorBytes wrote. Any deviation is an
// error naming the fault — a corrupt floor is never read as "no floor" (that
// would make truncating the file a rollback enabler); the caller fails closed.
func ParseVerifyFloor(data []byte) (logID string, version int, err error) {
	if bytes.Contains(data, []byte("\r")) {
		return "", 0, errors.New("carriage return; the line ends with \\n only")
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		return "", 0, errors.New("missing trailing newline")
	}
	line := strings.TrimSuffix(string(data), "\n")
	if strings.Contains(line, "\n") {
		return "", 0, errors.New("more than one line; want exactly one")
	}
	fields := strings.Split(line, " ")
	if len(fields) != 2 {
		return "", 0, fmt.Errorf("%d fields; want <log_id> <version>", len(fields))
	}
	if !logIDRE.MatchString(fields[0]) {
		return "", 0, errors.New("malformed log_id (want 32 lowercase hex)")
	}
	if !versionRE.MatchString(fields[1]) {
		return "", 0, errors.New("malformed version (want the shortest decimal, at least 1)")
	}
	version, err = strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, fmt.Errorf("malformed version: %w", err)
	}
	return fields[0], version, nil
}
