package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrResourceExists is returned by InsertToolResource when the gateway's
// tools: map already has that id. The file is left untouched.
var ErrResourceExists = errors.New("tool resource already exists")

// ErrGrantExists is returned by InsertGrant when the agent already holds a
// grant for that resource. The file is left untouched.
var ErrGrantExists = errors.New("tool grant already exists")

// InsertToolResource adds res under tools.<id> in the gateway file at
// gatewayPath, preserving every existing comment and key order. A missing
// file is created holding only this resource. An id already present is
// refused with ErrResourceExists, never overwritten.
func InsertToolResource(gatewayPath, id string, res ToolResource) error {
	val, err := toNode(res)
	if err != nil {
		return err
	}
	return editYAML(gatewayPath, true, func(root *yaml.Node) error {
		tools, err := childOfKind(root, "tools", yaml.MappingNode)
		if err != nil {
			return fmt.Errorf("%s: %w", gatewayPath, err)
		}
		for i := 0; i+1 < len(tools.Content); i += 2 {
			if tools.Content[i].Value == id {
				return fmt.Errorf("%w: %q in %s", ErrResourceExists, id, gatewayPath)
			}
		}
		tools.Content = append(tools.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: id}, val)
		return nil
	})
}

// InsertGrant appends grant to the tools: list of the agent file at
// agentPath, preserving comments. A grant for the same resource already in
// the list is refused with ErrGrantExists. The agent file must exist.
func InsertGrant(agentPath string, grant ToolGrant) error {
	val, err := toNode(grant)
	if err != nil {
		return err
	}
	return editYAML(agentPath, false, func(root *yaml.Node) error {
		tools, err := childOfKind(root, "tools", yaml.SequenceNode)
		if err != nil {
			return fmt.Errorf("%s: %w", agentPath, err)
		}
		for _, item := range tools.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(item.Content); i += 2 {
				if item.Content[i].Value == "resource" && item.Content[i+1].Value == grant.Resource {
					return fmt.Errorf("%w: %q in %s", ErrGrantExists, grant.Resource, agentPath)
				}
			}
		}
		tools.Content = append(tools.Content, val)
		return nil
	})
}

// toNode serializes v with its struct tags and re-parses it into a Node, so
// the inserted subtree keeps the struct's field order.
func toNode(v any) (*yaml.Node, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("internal: unexpected serialized node shape")
	}
	return doc.Content[0], nil
}

// childOfKind returns the value node of key in the top-level mapping root,
// creating it (empty, of the given kind) when absent or null. An existing
// value of another kind is an error.
func childOfKind(root *yaml.Node, key string, kind yaml.Kind) (*yaml.Node, error) {
	tag := "!!map"
	if kind == yaml.SequenceNode {
		tag = "!!seq"
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != key {
			continue
		}
		v := root.Content[i+1]
		switch {
		case v.Kind == yaml.AliasNode:
			return nil, fmt.Errorf("%q is a YAML alias; edit it by hand", key)
		case v.Kind == yaml.ScalarNode && v.Tag == "!!null":
			// "tools:" with no value: replace the null with an empty container,
			// keeping any comment attached to it.
			v.Kind, v.Tag, v.Value, v.Style = kind, tag, "", 0
		case v.Kind != kind:
			return nil, fmt.Errorf("%q is not a %s", key, tag[2:])
		}
		if len(v.Content) == 0 {
			v.Style &^= yaml.FlowStyle // "{}" / "[]": grow as block style
		}
		return v, nil
	}
	v := &yaml.Node{Kind: kind, Tag: tag}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	return v, nil
}

// editYAML loads path into a yaml.Node, applies mutate to the top-level
// mapping, and atomically writes the result. With create set, a missing (or
// empty) file starts as an empty mapping; otherwise a missing file is an
// error. mutate failing leaves the file untouched.
func editYAML(path string, create bool, mutate func(root *yaml.Node) error) error {
	var doc yaml.Node
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist) && create:
	default:
		return err
	}
	if doc.Kind == 0 { // missing or empty file
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: top level is not a mapping", path)
	}
	if err := mutate(doc.Content[0]); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return writeFileAtomic(path, buf.Bytes())
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// synced and renamed into place, mode 0644.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".edit-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	tmpPath = ""
	return nil
}
