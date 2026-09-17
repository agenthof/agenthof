// Tools built from a Jail, exposed to ADK agents as function-call tools.
//
// Every arg struct here uses ADK's bare jsonschema description dialect
// (`jsonschema:"some description"`). The `required,description=...` dialect
// used by some other jsonschema libraries makes functiontool.New fail at
// construction time; see tools_construct_test.go for the regression guard.
package agentrt

import (
	"fmt"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
)

type listFilesArgs struct{}

type fileEntry struct {
	Path string `json:"path" jsonschema:"slash-separated path relative to the workspace root"`
	Size int64  `json:"size" jsonschema:"file size in bytes"`
}

type listFilesResult struct {
	Files     []fileEntry `json:"files" jsonschema:"files under the jailed workspace, sorted by path"`
	Truncated bool        `json:"truncated" jsonschema:"true if more eligible files exist beyond the returned list"`
}

func listFilesTool(j *Jail) (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:        "list_files",
		Description: "Lists files under the jailed workspace, sorted by path (capped at 300 entries).",
	}, func(_ agent.Context, _ listFilesArgs) (listFilesResult, error) {
		files, truncated, err := j.List()
		if err != nil {
			return listFilesResult{}, err
		}
		entries := make([]fileEntry, len(files))
		for i, f := range files {
			entries[i] = fileEntry{Path: f.Path, Size: f.Size}
		}
		return listFilesResult{Files: entries, Truncated: truncated}, nil
	})
}

type searchFilesArgs struct {
	Pattern    string `json:"pattern" jsonschema:"Go regular expression to search for in file contents"`
	MaxResults int    `json:"max_results" jsonschema:"maximum number of matching lines to return; 0 or omitted uses the default"`
}

type searchFilesResult struct {
	Matches string `json:"matches" jsonschema:"formatted \"path:line: text\" rows, one per matching line"`
	Count   int    `json:"count" jsonschema:"number of matching rows returned"`
}

func searchFilesTool(j *Jail) (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:        "search_files",
		Description: "Searches jailed workspace file contents for lines matching a regular expression.",
	}, func(_ agent.Context, args searchFilesArgs) (searchFilesResult, error) {
		matches, count, err := j.Search(args.Pattern, args.MaxResults)
		if err != nil {
			return searchFilesResult{}, err
		}
		return searchFilesResult{Matches: matches, Count: count}, nil
	})
}

type readFileArgs struct {
	Path      string `json:"path" jsonschema:"repo-relative file path"`
	StartLine int    `json:"start_line" jsonschema:"1-based start line; 0 or omitted means the beginning of the file"`
	EndLine   int    `json:"end_line" jsonschema:"1-based end line, inclusive; 0 or omitted means the end of the file"`
}

type readFileResult struct {
	Content   string `json:"content" jsonschema:"file content for the requested line range"`
	StartLine int    `json:"start_line" jsonschema:"actual first line returned"`
	EndLine   int    `json:"end_line" jsonschema:"actual last line returned"`
	Total     int    `json:"total_lines" jsonschema:"total number of lines in the file"`
	Truncated bool   `json:"truncated" jsonschema:"true if the content was cut short by the size cap"`
}

func readFileTool(j *Jail) (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:        "read_file",
		Description: "Reads a line range from a file in the jailed workspace.",
	}, func(_ agent.Context, args readFileArgs) (readFileResult, error) {
		content, start, end, total, truncated, err := j.Read(args.Path, args.StartLine, args.EndLine)
		if err != nil {
			return readFileResult{}, err
		}
		return readFileResult{Content: content, StartLine: start, EndLine: end, Total: total, Truncated: truncated}, nil
	})
}

type editFileArgs struct {
	Path       string `json:"path" jsonschema:"repo-relative file path"`
	OldString  string `json:"old_string" jsonschema:"exact existing text to replace"`
	NewString  string `json:"new_string" jsonschema:"replacement text"`
	ReplaceAll bool   `json:"replace_all" jsonschema:"replace every occurrence instead of requiring a single unique match"`
}

type editFileResult struct {
	Replacements int `json:"replacements" jsonschema:"number of replacements made"`
}

func editFileTool(j *Jail) (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:        "edit_file",
		Description: "Replaces exact text in a file in the jailed workspace.",
	}, func(_ agent.Context, args editFileArgs) (editFileResult, error) {
		n, err := j.Edit(args.Path, args.OldString, args.NewString, args.ReplaceAll)
		if err != nil {
			return editFileResult{}, err
		}
		return editFileResult{Replacements: n}, nil
	})
}

type writeFileArgs struct {
	Path    string `json:"path" jsonschema:"repo-relative file path"`
	Content string `json:"content" jsonschema:"content to write; creates the file or overwrites it entirely"`
}

type writeFileResult struct {
	Written bool `json:"written" jsonschema:"true once the file has been written"`
}

func writeFileTool(j *Jail) (tool.Tool, error) {
	return functiontool.New(functiontool.Config{
		Name:        "write_file",
		Description: "Creates or overwrites a file in the jailed workspace.",
	}, func(_ agent.Context, args writeFileArgs) (writeFileResult, error) {
		if err := j.Write(args.Path, args.Content); err != nil {
			return writeFileResult{}, err
		}
		return writeFileResult{Written: true}, nil
	})
}

// Tools builds the tool catalog for names, wrapping j's jailed filesystem
// operations. Each name must be one of: list_files, search_files, read_file,
// edit_file, write_file. An unknown name fails the whole build rather than
// being silently skipped, so a typo in an agent's `tools:` list is caught at
// startup instead of showing up as a missing capability at run time.
func Tools(j *Jail, names []string) ([]tool.Tool, error) {
	out := make([]tool.Tool, 0, len(names))
	for _, name := range names {
		var (
			t   tool.Tool
			err error
		)
		switch name {
		case "list_files":
			t, err = listFilesTool(j)
		case "search_files":
			t, err = searchFilesTool(j)
		case "read_file":
			t, err = readFileTool(j)
		case "edit_file":
			t, err = editFileTool(j)
		case "write_file":
			t, err = writeFileTool(j)
		default:
			return nil, fmt.Errorf("tool %q is not in the catalog", name)
		}
		if err != nil {
			return nil, fmt.Errorf("build tool %q: %w", name, err)
		}
		out = append(out, t)
	}
	return out, nil
}
