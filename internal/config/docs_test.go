package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestConfigReferenceCoversAllYAMLFields fails when a yaml-tagged config
// field exists that docs/reference/config.md does not document as `tag`.
// Adding a config field therefore forces a docs update in the same PR.
func TestConfigReferenceCoversAllYAMLFields(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference", "config.md"))
	if err != nil {
		t.Fatalf("config reference missing: %v", err)
	}
	var missing []string
	var walk func(rt reflect.Type, owner string)
	walk = func(rt reflect.Type, owner string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			if !strings.Contains(string(doc), "`"+tag+"`") {
				missing = append(missing, fmt.Sprintf("%s.%s (yaml %q)", owner, f.Name, tag))
			}
			ft := f.Type
			for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Map {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, owner+"."+f.Name)
			}
		}
	}
	for _, root := range []any{AgentDef{}, Step{}, WorkflowDef{}, RoleDef{}, ModelRoute{}, GatewayConfig{}} {
		rt := reflect.TypeOf(root)
		walk(rt, rt.Name())
	}
	if len(missing) > 0 {
		t.Fatalf("undocumented config fields in docs/reference/config.md:\n  %s",
			strings.Join(missing, "\n  "))
	}
}
