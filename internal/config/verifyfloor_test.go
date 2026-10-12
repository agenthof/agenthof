package config

import (
	"strings"
	"testing"
)

const floorLogID = "00112233445566778899aabbccddeeff"

func TestVerifyFloorBytesRoundTrip(t *testing.T) {
	b := VerifyFloorBytes(floorLogID, 7)
	if string(b) != floorLogID+" 7\n" {
		t.Fatalf("bytes %q", b)
	}
	logID, version, err := ParseVerifyFloor(b)
	if err != nil || logID != floorLogID || version != 7 {
		t.Fatalf("round trip: %q %d %v", logID, version, err)
	}
	if _, v, err := ParseVerifyFloor(VerifyFloorBytes(floorLogID, 1)); err != nil || v != 1 {
		t.Fatalf("version 1: %d %v", v, err)
	}
}

func TestParseVerifyFloorRefusals(t *testing.T) {
	for name, c := range map[string]struct{ in, fault string }{
		"CR anywhere":      {floorLogID + " 7\r\n", "carriage return"},
		"no trailing LF":   {floorLogID + " 7", "missing trailing newline"},
		"one field":        {floorLogID + "\n", "fields"},
		"three fields":     {floorLogID + " 7 x\n", "fields"},
		"leading space":    {" " + floorLogID + " 7\n", "fields"},
		"trailing space":   {floorLogID + " 7 \n", "fields"},
		"tab separator":    {floorLogID + "\t7\n", "fields"},
		"log_id uppercase": {strings.ToUpper(floorLogID) + " 7\n", "malformed log_id"},
		"log_id short":     {floorLogID[:31] + " 7\n", "malformed log_id"},
		"version 07":       {floorLogID + " 07\n", "malformed version"},
		"version +7":       {floorLogID + " +7\n", "malformed version"},
		"version 7.0":      {floorLogID + " 7.0\n", "malformed version"},
		"version 0":        {floorLogID + " 0\n", "malformed version"},
		"version empty":    {floorLogID + " \n", "malformed version"},
		"second line":      {floorLogID + " 7\n" + floorLogID + " 8\n", "one line"},
		"empty":            {"", "missing trailing newline"},
		"only newline":     {"\n", "fields"},
	} {
		t.Run(name, func(t *testing.T) {
			logID, version, err := ParseVerifyFloor([]byte(c.in))
			if err == nil {
				t.Fatalf("%q parsed as (%q, %d); want a refusal", c.in, logID, version)
			}
			if !strings.Contains(err.Error(), c.fault) {
				t.Fatalf("%q: error %q must name the fault %q", c.in, err, c.fault)
			}
			if strings.Contains(err.Error(), "verify floor") || strings.Contains(err.Error(), "verify.floor") {
				t.Fatalf("the codec reports the bare fault; the CLI names the file: %q", err)
			}
		})
	}
}
