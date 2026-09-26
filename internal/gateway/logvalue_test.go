package gateway

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRouteLogValueRedacts(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	l.Info("resolved", "route", Route{Endpoint: "https://gw.example/v1", Model: "gpt-x", APIKey: "sk-secretvalue123"})
	out := buf.String()
	if strings.Contains(out, "sk-secretvalue123") || strings.Contains(out, "sk-secre") {
		t.Fatalf("Route.APIKey leaked through slog:\n%s", out)
	}
	if !strings.Contains(out, "route=REDACTED") {
		t.Fatalf("Route must render as REDACTED:\n%s", out)
	}
}

func TestProvisionerLogValueRedacts(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("provisioning", slog.Any("provisioner", Provisioner{AdminBase: "http://localhost:4000", MasterKey: "mastersecret456"}))
	out := buf.String()
	if strings.Contains(out, "mastersecret456") || strings.Contains(out, "masterse") {
		t.Fatalf("Provisioner.MasterKey leaked through slog:\n%s", out)
	}
	if !strings.Contains(out, `"provisioner":"REDACTED"`) {
		t.Fatalf("Provisioner must render as REDACTED:\n%s", out)
	}
}
