// relationships:
//
//	references: [../../../tests/acceptance/testdata/candidate.yaml, ../../../tests/acceptance/testdata/profile-input.json]
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// This hermetic gate reads the actual portable reviewed profile bytes. The
// strict test-only decoder detects otherwise silently ignored YAML keys;
// translated option assertions pin the config-to-runtime boundary separately
// from the live acceptance cases and existing composed field regressions.
func TestForkAcceptanceProfileConfigEffects(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "tests", "acceptance", "testdata")
	raw, e := os.ReadFile(filepath.Join(dir, "candidate.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	meta, e := os.ReadFile(filepath.Join(dir, "profile-input.json"))
	if e != nil {
		t.Fatal(e)
	}
	var input struct {
		Candidate string `json:"candidate_sha256"`
		Readme    string `json:"readme_sha256"`
	}
	if e = json.Unmarshal(meta, &input); e != nil {
		t.Fatal(e)
	}
	hash := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	if hash(raw) != input.Candidate {
		t.Fatal("reviewed candidate bytes drift from input hash")
	}
	readme, e := os.ReadFile(filepath.Join(dir, "profile.md"))
	if e != nil {
		t.Fatal(e)
	}
	if hash(readme) != input.Readme {
		t.Fatal("reviewed README bytes drift from input hash")
	}
	t.Run("EveryAuthoredKeyRecognized", func(t *testing.T) {
		authoredInput := viper.New()
		authoredInput.SetConfigType("yaml")
		if e := authoredInput.ReadConfig(bytes.NewReader(raw)); e != nil {
			t.Fatal(e)
		}
		var strict Config
		decoder, e := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: &strict, TagName: "mapstructure", ErrorUnused: true})
		if e != nil {
			t.Fatal(e)
		}
		if e = decoder.Decode(authoredInput.AllSettings()); e != nil {
			t.Fatalf("profile contains an ignored/invalid key: %v", e)
		}
	})
	c, e := LoadBytes(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateStructural(c); e != nil {
		t.Fatal(e)
	}
	if len(c.Clients.Profiles) != 1 {
		t.Fatal("profile count differs")
	}
	body := c.Clients.Profiles[0].RequestBody
	opts := body.ToFilterOptions()
	build := body.Buildkit.ToPolicy(body.Build)
	checks := []struct {
		name      string
		got, want any
	}{
		{"ArchiveRoot", opts.ContainerArchive.AllowedPaths, []string{"/"}},
		{"ArchiveAbsoluteLinks", opts.ContainerArchive.AllowEscapingLinks, true},
		{"ArchiveSetID", opts.ContainerArchive.AllowSetID, false},
		{"ArchiveDevices", opts.ContainerArchive.AllowDeviceNodes, false},
		{"ExecAnyCommand", opts.Exec.AllowAnyCommand, true},
		{"ExecRootActualProfile", opts.Exec.AllowRootUser, true},
		{"ExecPrivileged", opts.Exec.AllowPrivileged, false},
		{"WorkspaceOptIn", body.ContainerCreate.ApplyWorkspaceExceptions, true},
		{"NoRestartPolicy", opts.ContainerCreate.RequireNoRestartPolicy, true},
		{"NetworkDriver", opts.ContainerCreate.NetworkDrivers.AllowedDrivers, []string{"bridge"}},
		{"PrivilegedBase", opts.ContainerCreate.AllowPrivileged, false},
		{"BindRoots", opts.ContainerCreate.AllowedBindMounts, []string{"/srv/workspaces", "/srv/compose-staging", "/srv/workspace-sockets"}},
		{"PerWorkspaceRoots", c.WorkspaceExceptions.PerWorkspaceRoots, []string{"/srv/workspaces", "/srv/workspace-sockets", "/srv/compose-staging"}},
		{"LLBBridge", build.LLBBridge.AllowUninspectedPassthrough, true},
		{"Solve", build.Control.Solve.Allow, true},
		{"Exporter", build.Control.Solve.AllowedExporters, []string{"moby"}},
		{"BuildRun", build.Control.Solve.AllowRunInstructions, true},
		{"BuildHostNetwork", build.Control.Solve.AllowHostNetwork, false},
		{"BuildRemoteContext", build.Control.Solve.AllowRemoteContext, false},
		{"ReadExfiltrationAcknowledgment", c.InsecureAllowReadExfiltration, true},
		{"MountPathRedaction", c.Response.RedactMountPaths, false},
		{"EnvironmentRedaction", c.Response.RedactContainerEnv, true},
		{"DenialReason", c.Response.DenyVerbosity, "verbose"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if !reflect.DeepEqual(check.got, check.want) {
				t.Fatalf("field effect=%#v want=%#v", check.got, check.want)
			}
		})
	}
	if len(c.Clients.UnixPeerProfiles) != 1 || len(c.Clients.UnixPeerProfiles[0].GIDs) != 0 {
		t.Fatal("peer profile must match UID only")
	}
	if len(c.Clients.Profiles[0].Rules) != 31 {
		t.Fatalf("ordered profile rule count=%d want31", len(c.Clients.Profiles[0].Rules))
	}
	for _, r := range c.Clients.Profiles[0].Rules {
		if r.Match.Path == "/containers/*/restart" {
			t.Fatal("baseline restart route must stay omitted")
		}
	}
}
