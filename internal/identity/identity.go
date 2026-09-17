package identity

import "os"

type Invoker struct {
	Subject string   `json:"subject"`
	Issuer  string   `json:"issuer"`
	Method  string   `json:"method"`
	Groups  []string `json:"groups,omitempty"`
}

func Static(as string) Invoker {
	subject := as
	if subject == "" {
		subject = os.Getenv("USER")
	}
	if subject == "" {
		subject = "unknown"
	}
	return Invoker{Subject: subject, Issuer: "local", Method: "asserted"}
}
