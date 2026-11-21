package main

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // UUIDv5 is defined over SHA-1; this is an identifier, not a security primitive.
	"fmt"
)

// idNamespace is the fixed namespace for UUIDv5 derivation. Changing it
// changes every derived id, so it is a constant of the store's contract.
var idNamespace = [16]byte{
	0x6a, 0x1d, 0x4c, 0x52, 0x9b, 0x7e, 0x4f, 0x0a,
	0x8d, 0x33, 0xa1, 0x5c, 0x07, 0xe2, 0x90, 0x4b,
}

// deriveID returns a UUIDv5 of (collection, callerID) when callerID is set,
// so re-upserting the same logical id in a collection overwrites, and the
// same id in another collection does not collide. With no callerID it
// returns a random UUIDv4.
func deriveID(collection, callerID string) (string, error) {
	if callerID != "" {
		h := sha1.New() //nolint:gosec // see import.
		h.Write(idNamespace[:])
		h.Write([]byte(collection + "\x00" + callerID))
		var u [16]byte
		copy(u[:], h.Sum(nil))
		return formatUUID(u, 5), nil
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return formatUUID(u, 4), nil
}

func formatUUID(u [16]byte, version byte) string {
	u[6] = u[6]&0x0f | version<<4
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
