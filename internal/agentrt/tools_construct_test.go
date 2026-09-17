package agentrt

import "testing"

// TestTools_ConstructsCatalog guards against ADK's jsonschema-tag fatality:
// functiontool.New fails at construction time if an arg struct's
// `jsonschema` tags use the `required,description=...` dialect instead of
// ADK's bare description dialect. If any tool's arg struct regresses to
// that dialect, this test fails immediately rather than only at run time.
func TestTools_ConstructsCatalog(t *testing.T) {
	j, err := NewJail(t.TempDir())
	if err != nil {
		t.Fatalf("NewJail: %v", err)
	}

	all := []string{"list_files", "search_files", "read_file", "edit_file", "write_file"}
	tools, err := Tools(j, all)
	if err != nil {
		t.Fatalf("Tools(%v): %v", all, err)
	}
	if len(tools) != len(all) {
		t.Fatalf("got %d tools, want %d", len(tools), len(all))
	}
	for i, name := range all {
		if got := tools[i].Name(); got != name {
			t.Errorf("tools[%d].Name() = %q, want %q", i, got, name)
		}
	}
}

func TestTools_UnknownNameErrors(t *testing.T) {
	j, err := NewJail(t.TempDir())
	if err != nil {
		t.Fatalf("NewJail: %v", err)
	}

	_, err = Tools(j, []string{"list_files", "shell_exec"})
	if err == nil {
		t.Fatal("Tools with an unknown name: got nil error, want one")
	}
	const want = `tool "shell_exec" is not in the catalog`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}
