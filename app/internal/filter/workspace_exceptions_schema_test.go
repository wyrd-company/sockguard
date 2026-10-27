// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions, ../../../docs/public/workspace-exceptions.schema.json]
package filter

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type schemaNode struct {
	Required             []string              `json:"required"`
	Properties           map[string]schemaNode `json:"properties"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
	Items                *schemaNode           `json:"items"`
	Enum                 []string              `json:"enum"`
	AnyOf                []schemaNode          `json:"anyOf"`
	Ref                  string                `json:"$ref"`
	Defs                 map[string]schemaNode `json:"$defs"`
}

func loadWorkspaceExceptionsSchema(t *testing.T) schemaNode {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/public/workspace-exceptions.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var root schemaNode
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func (root schemaNode) def(t *testing.T, n schemaNode) schemaNode {
	t.Helper()
	if n.Ref == "" {
		return n
	}
	d, ok := root.Defs[strings.TrimPrefix(n.Ref, "#/$defs/")]
	if !ok {
		t.Fatalf("unresolved $ref %q", n.Ref)
	}
	return d
}

func sortedKeys(m map[string]schemaNode) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// The published schema names the same keys, required keys and closed sets
// the parser enforces.
func TestWorkspaceExceptionsSchemaAgreesWithParser(t *testing.T) {
	root := loadWorkspaceExceptionsSchema(t)
	entry := root.def(t, *root.Properties["exceptions"].Items)
	grants := root.def(t, entry.Properties["grants"])
	approval := root.def(t, entry.Properties["approval"])
	by := approval.Properties["by"]
	for _, tc := range []struct {
		name             string
		node             schemaNode
		fields, required []string
	}{
		{"document", root, workspaceTopFields, workspaceTopFields},
		{"entry", entry, workspaceEntryFields, workspaceEntryFields},
		{"grants", grants, workspaceGrantFields, nil},
		{"approval", approval, workspaceApprovalFields, workspaceApprovalRequiredFields},
		{"approval.by", by, workspaceApprovalByFields, workspaceApprovalByRequired},
	} {
		if got := sortedKeys(tc.node.Properties); !sameSet(got, tc.fields) {
			t.Errorf("%s: schema keys %v, parser keys %v", tc.name, got, tc.fields)
		}
		if !sameSet(tc.node.Required, tc.required) {
			t.Errorf("%s: schema required %v, parser required %v", tc.name, tc.node.Required, tc.required)
		}
		if tc.node.AdditionalProperties == nil || *tc.node.AdditionalProperties {
			t.Errorf("%s: schema must set additionalProperties: false", tc.name)
		}
	}
	if got := grants.Properties["namespaces"].Items.Enum; !sameSet(got, workspaceExceptionNamespaces) {
		t.Errorf("namespaces: schema %v, parser %v", got, workspaceExceptionNamespaces)
	}
	if got := grants.Properties["restartPolicy"].Items.Enum; !sameSet(got, workspaceExceptionRestartPolicies) {
		t.Errorf("restartPolicy: schema %v, parser %v", got, workspaceExceptionRestartPolicies)
	}
	if got := grants.Properties["securityOpt"].Items.AnyOf[0].Enum; !sameSet(got, workspaceSecurityOptValues) {
		t.Errorf("securityOpt: schema %v, parser %v", got, workspaceSecurityOptValues)
	}
}

// Every closed-set value the parser lists is accepted, and opens its own
// grant.
func TestWorkspaceExceptionsClosedSetsParse(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	parse := func(key string, values []string) workspaceGrants {
		t.Helper()
		entries, err := parseWorkspaceExceptions(mustJSON(t, workspaceDoc(workspaceEntryDoc(f.alpha, map[string]any{key: values}))), f.root)
		if err != nil {
			t.Fatalf("%s %v: %v", key, values, err)
		}
		return entries[f.alpha].grants
	}
	none := fmt.Sprintf("%+v", workspaceGrants{})
	seen := map[string]bool{none: true}
	distinct := func(kind, v string, g workspaceGrants) {
		t.Helper()
		key := fmt.Sprintf("%+v", g)
		if seen[key] {
			t.Fatalf("%s %q does not open its own grant", kind, v)
		}
		seen[key] = true
	}
	for _, v := range workspaceSecurityOptValues {
		distinct("securityOpt", v, parse("securityOpt", []string{v}))
	}
	for _, v := range workspaceExceptionNamespaces {
		distinct("namespace", v, parse("namespaces", []string{v}))
	}
	for _, v := range workspaceExceptionRestartPolicies {
		if g := parse("restartPolicy", []string{v}); !slices.Equal(g.restartPolicies, []string{v}) {
			t.Fatalf("restartPolicy %q not recorded", v)
		}
	}
}

// The example on the contract page is a valid file.
func TestWorkspaceExceptionsDocExampleParses(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/content/docs/workspace-exceptions.mdx")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```json\n(.*?)```").FindAllStringSubmatch(string(raw), -1)
	if len(blocks) != 1 {
		t.Fatalf("want one json example, found %d", len(blocks))
	}
	entries, err := parseWorkspaceExceptions([]byte(blocks[0][1]), "/srv/workspaces")
	if err != nil {
		t.Fatalf("doc example: %v", err)
	}
	if len(entries) != 1 || !entries["/srv/workspaces/alpha"].grants.privileged {
		t.Fatalf("doc example decoded as %+v", entries)
	}
}
