//go:build sockguardacceptance

// relationships:
//
//	references: [suite_test.go, consumer_test.go, boundary_test.go]
package acceptance

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/moby/buildkit/util/grpcerrors"
)

const composeObjectRootLabel = "devcontainer.compose.objects"
const ownershipArchiveMessage = "owner policy denied access to container"
const llbPingDenial = "moby.buildkit.v1.frontend.LLBBridge/Ping is denied by sockguard's BuildKit mediation policy"

// These validators are shared by real observations and non-Docker negative
// inputs. They validate acceptance evidence, not product configuration.
func deploymentPrivilege(c container.InspectResponse) error {
	if c.HostConfig.Privileged {
		return fmt.Errorf("deployment privileged mode must be false")
	}
	return nil
}

func foreignArchiveDenial(status int, body []byte) error {
	if status != 403 {
		return fmt.Errorf("foreign archive read must return ownership 403: status=%d body=%s", status, body)
	}
	var response struct{ Message string }
	if json.Unmarshal(body, &response) != nil || response.Message != ownershipArchiveMessage {
		return fmt.Errorf("foreign archive read must name the ownership denial: %s", body)
	}
	return nil
}

func workspaceLookupIDs(workspace string, got, want []string) error {
	got, want = slices.Clone(got), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("populated workspace lookup selected wrong containers for %s: got=%v want=%v", workspace, got, want)
	}
	return nil
}

func composeServiceIDs(primary string, services map[string]string) ([]string, error) {
	if len(services) != 2 || primary == "" || services["primary"] != primary || services["sidecar"] == "" || services["sidecar"] == primary {
		return nil, fmt.Errorf("Compose fixture must contain distinct populated primary and sidecar IDs")
	}
	return []string{primary, services["sidecar"]}, nil
}

func mountedConfigLedger(volumes []*volume.Volume, mounts []container.MountPoint, run, workspace, staging, owner string) (string, error) {
	if len(volumes) != 1 {
		return "", fmt.Errorf("expected one owned materialized ledger, got %d", len(volumes))
	}
	v := volumes[0]
	if v.Labels[runLabel] != run || v.Labels[primaryLabel] != workspace || v.Labels["com.sockguard.owner"] != owner {
		return "", fmt.Errorf("materialized ledger ownership does not match the run/workspace")
	}
	root := v.Labels[composeObjectRootLabel]
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) != staging || !strings.HasPrefix(filepath.Base(root), "objects-") || v.Name != "dcb-"+filepath.Base(root) {
		return "", fmt.Errorf("materialized ledger name/root is not the owned staging record")
	}
	for _, m := range mounts {
		if m.Type == "bind" && m.Destination == "/generated.txt" && !m.RW && strings.HasPrefix(m.Source, root+string(filepath.Separator)) {
			return v.Name, nil
		}
	}
	return "", fmt.Errorf("materialized ledger root is not consumed by the read-only inline config mount")
}

var dockerVersionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+/`)

func exactAPICall(c call, method, path string, status int) bool {
	return c.Method == method && dockerVersionPrefix.ReplaceAllString(c.Path, "/") == path && c.Status == status
}

func ledgerRetirementDuringUp(calls []call, start, end int, ledger string) error {
	for i, c := range calls {
		if i < start || i >= end {
			continue
		}
		if exactAPICall(c, "DELETE", "/volumes/"+ledger, 204) && c.Force {
			return nil
		}
	}
	return fmt.Errorf("second Up did not retire the exact owned ledger %q with DELETE/force=1/status204", ledger)
}

func retiredLedgerAbsent(err error) error {
	if !dockerclient.IsErrNotFound(err) {
		return fmt.Errorf("retired owned ledger still exists or inspect failed unexpectedly: %v", err)
	}
	return nil
}

func llbOffBuildDenial(err error, calls []call) error {
	if err == nil {
		return fmt.Errorf("LLBBridge-off build unexpectedly succeeded")
	}
	if grpcerrors.Code(err).String() != "PermissionDenied" {
		return fmt.Errorf("LLB-off failure is not gRPC PermissionDenied: %v", err)
	}
	if !strings.Contains(err.Error(), llbPingDenial) {
		return fmt.Errorf("LLB-off failure does not name the LLBBridge/Ping policy boundary: %v", err)
	}
	for _, c := range calls {
		if exactAPICall(c, "POST", "/grpc", 101) && !c.Header {
			return nil
		}
	}
	return fmt.Errorf("LLB-off control did not reach an admitted headerless grpc upgrade")
}

func TestAcceptanceAssertions(t *testing.T) {
	t.Run("DeploymentPrivileged", func(t *testing.T) {
		for _, privileged := range []bool{false, true} {
			// All other deployment inputs stay valid and identical. This pure
			// counterfactual never creates a privileged proxy container.
			c := container.InspectResponse{ContainerJSONBase: &container.ContainerJSONBase{HostConfig: &container.HostConfig{
				Privileged: privileged, ReadonlyRootfs: true, NetworkMode: "none", CapDrop: []string{"ALL"}, CapAdd: []string{"DAC_READ_SEARCH"},
				GroupAdd: []string{"20001"}, SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"},
			}}, Config: &container.Config{User: "0:0"}}
			for _, root := range []string{"workspaces", "workspace-sockets", "compose-staging", "exceptions"} {
				c.Mounts = append(c.Mounts, container.MountPoint{Type: "bind", Source: "/fixture/" + root, Destination: "/fixture/" + root, RW: false})
			}
			err := deploymentPrivilege(c)
			if (err != nil) != privileged {
				t.Fatalf("privileged deployment assertion accepted=%v privileged=%v", err == nil, privileged)
			}
		}
	})
	t.Run("ForeignArchiveDenial", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			status int
			body   string
			valid  bool
		}{
			{"Ownership403", 403, `{"message":"owner policy denied access to container"}`, true},
			{"NotFound404", 404, `{"message":"owner policy denied access to container"}`, false},
			{"Upstream500", 500, `{"message":"owner policy denied access to container"}`, false},
			{"Success200", 200, `{"message":"owner policy denied access to container"}`, false},
			{"WrongReason403", 403, `{"message":"route policy denied access"}`, false},
			{"Malformed403", 403, `not-json`, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := foreignArchiveDenial(tc.status, []byte(tc.body)); (err == nil) != tc.valid {
					t.Fatalf("foreign archive assertion accepted=%v want=%v: %v", err == nil, tc.valid, err)
				}
			})
		}
	})
	t.Run("PopulatedWorkspaceLookups", func(t *testing.T) {
		ids := [][]string{{"primary-a", "sidecar-a"}, {"primary-b", "sidecar-b"}}
		for i, workspace := range []string{"/fixture/alpha", "/fixture/beta"} {
			t.Run(filepath.Base(workspace), func(t *testing.T) {
				for _, size := range []int{1, 2} {
					want := ids[i][:size]
					if err := workspaceLookupIDs(workspace, slices.Clone(want), want); err != nil {
						t.Fatal(err)
					}
					if err := workspaceLookupIDs(workspace, ids[1-i][:size], want); err == nil {
						t.Fatal("populated lookup accepted the other populated workspace")
					}
				}
				for _, bad := range [][]string{nil, {"primary-a", "primary-b"}, {"primary-a", "primary-a"}, {"primary-a", "sidecar-a", "sidecar-b"}} {
					if err := workspaceLookupIDs(workspace, bad, ids[i]); err == nil {
						t.Fatalf("populated lookup accepted wrong membership: %v", bad)
					}
				}
			})
		}
	})
	t.Run("ComposeServiceIdentity", func(t *testing.T) {
		for _, name := range []string{"Valid", "MissingSidecar", "EmptySidecar", "DuplicateID", "WrongPrimary", "EmptyPrimary", "ExtraService"} {
			t.Run(name, func(t *testing.T) {
				services := map[string]string{"primary": "primary-a", "sidecar": "sidecar-a"}
				primary := "primary-a"
				switch name {
				case "MissingSidecar":
					delete(services, "sidecar")
				case "EmptySidecar":
					services["sidecar"] = ""
				case "DuplicateID":
					services["sidecar"] = "primary-a"
				case "WrongPrimary":
					services["primary"] = "primary-b"
				case "EmptyPrimary":
					primary = ""
					services["primary"] = ""
				case "ExtraService":
					services["other"] = "other-id"
				}
				_, err := composeServiceIDs(primary, services)
				if (err == nil) != (name == "Valid") {
					t.Fatalf("Compose service identity accepted=%v scenario=%s err=%v", err == nil, name, err)
				}
			})
		}
	})
	t.Run("ExactAPICall", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			c     call
			valid bool
		}{
			{"Versioned", call{Method: "DELETE", Path: "/v1.51/volumes/owned-ledger", Status: 204}, true},
			{"Unversioned", call{Method: "DELETE", Path: "/volumes/owned-ledger", Status: 204}, true},
			{"WrongMethod", call{Method: "GET", Path: "/v1.51/volumes/owned-ledger", Status: 204}, false},
			{"WrongPath", call{Method: "DELETE", Path: "/v1.51/volumes/unrelated", Status: 204}, false},
			{"ChildPath", call{Method: "DELETE", Path: "/v1.51/volumes/owned-ledger/unrelated", Status: 204}, false},
			{"WrongStatus", call{Method: "DELETE", Path: "/v1.51/volumes/owned-ledger", Status: 500}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := exactAPICall(tc.c, "DELETE", "/volumes/owned-ledger", 204); got != tc.valid {
					t.Fatalf("exact API call accepted=%v want=%v", got, tc.valid)
				}
			})
		}
	})
	t.Run("MaterializedLedgerIdentity", testMaterializedLedgerIdentity)
	t.Run("LedgerRetirementBoundary", testLedgerRetirementBoundary)
	t.Run("RetiredLedgerAbsent", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			err   error
			valid bool
		}{
			{"Missing", errdefs.NotFound(fmt.Errorf("owned volume absent")), true},
			{"StillExists", nil, false},
			{"InspectFailure", fmt.Errorf("upstream inspect failed"), false},
			{"UntypedNotFound", fmt.Errorf("not found"), false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := retiredLedgerAbsent(tc.err)
				if (err == nil) != tc.valid {
					t.Fatalf("retired ledger absence assertion accepted=%v want=%v err=%v", err == nil, tc.valid, err)
				}
			})
		}
	})
	t.Run("LLBOffBoundary", testLLBOffBoundary)
}

func ledgerInputs() ([]*volume.Volume, []container.MountPoint) {
	root := "/fixture/staging/alpha/objects-one"
	return []*volume.Volume{{Name: "dcb-objects-one", Labels: map[string]string{runLabel: "run-a", primaryLabel: "/fixture/alpha", "com.sockguard.owner": "owner-a", composeObjectRootLabel: root}}},
		[]container.MountPoint{{Type: "bind", Source: root + "/configs/generated", Destination: "/generated.txt", RW: false}}
}
func testMaterializedLedgerIdentity(t *testing.T) {
	for _, name := range []string{"Valid", "Empty", "Multiple", "WrongRun", "WrongWorkspace", "WrongOwner", "WrongName", "WrongRoot", "WrongPrefix", "Noncanonical", "Unconsumed", "Writable", "WrongType", "WrongDestination"} {
		t.Run(name, func(t *testing.T) {
			v, m := ledgerInputs()
			switch name {
			case "Empty":
				v = nil
			case "Multiple":
				other := &volume.Volume{Name: "dcb-objects-two", Labels: map[string]string{runLabel: "run-a", primaryLabel: "/fixture/alpha", "com.sockguard.owner": "owner-a", composeObjectRootLabel: "/fixture/staging/alpha/objects-two"}}
				v = append(v, other)
			case "WrongRun":
				v[0].Labels[runLabel] = "other-run"
			case "WrongWorkspace":
				v[0].Labels[primaryLabel] = "/fixture/beta"
			case "WrongOwner":
				v[0].Labels["com.sockguard.owner"] = "other-owner"
			case "WrongName":
				v[0].Name = "unrelated-volume"
			case "WrongRoot":
				v[0].Labels[composeObjectRootLabel] = "/fixture/staging/beta/objects-one"
				m[0].Source = "/fixture/staging/beta/objects-one/configs/generated"
			case "WrongPrefix":
				v[0].Labels[composeObjectRootLabel] = "/fixture/staging/alpha/cache-one"
				v[0].Name = "dcb-cache-one"
				m[0].Source = "/fixture/staging/alpha/cache-one/configs/generated"
			case "Noncanonical":
				v[0].Labels[composeObjectRootLabel] = "/fixture/staging/alpha/./objects-one"
				m[0].Source = "/fixture/staging/alpha/./objects-one/configs/generated"
			case "Unconsumed":
				m[0].Source = "/fixture/staging/alpha/objects-other/configs/generated"
			case "Writable":
				m[0].RW = true
			case "WrongType":
				m[0].Type = "volume"
			case "WrongDestination":
				m[0].Destination = "/other.txt"
			}
			got, err := mountedConfigLedger(v, m, "run-a", "/fixture/alpha", "/fixture/staging/alpha", "owner-a")
			if (err == nil) != (name == "Valid") || err == nil && got != "dcb-objects-one" {
				t.Fatalf("ledger identity assertion accepted=%v name=%s result=%q err=%v", err == nil, name, got, err)
			}
		})
	}
}
func testLedgerRetirementBoundary(t *testing.T) {
	valid := call{Method: "DELETE", Path: "/v1.51/volumes/dcb-objects-one", Status: 204, Force: true}
	for _, name := range []string{"Valid", "BeforeUp", "AfterUpTeardown", "WrongVolume", "SubstringOnly", "WrongMethod", "MissingForce", "WrongStatus"} {
		t.Run(name, func(t *testing.T) {
			calls := []call{{}, valid, {}}
			switch name {
			case "BeforeUp":
				calls = []call{valid, {}, {}}
			case "AfterUpTeardown":
				calls = []call{{}, {}, valid}
			case "WrongVolume":
				calls[1].Path = "/v1.51/volumes/named-data"
			case "SubstringOnly":
				calls[1].Path += "/unrelated"
			case "WrongMethod":
				calls[1].Method = "GET"
			case "MissingForce":
				calls[1].Force = false
			case "WrongStatus":
				calls[1].Status = 500
			}
			err := ledgerRetirementDuringUp(calls, 1, 2, "dcb-objects-one")
			if (err == nil) != (name == "Valid") {
				t.Fatalf("ledger retirement assertion accepted=%v scenario=%s err=%v", err == nil, name, err)
			}
		})
	}
}
func testLLBOffBoundary(t *testing.T) {
	for _, name := range []string{"Valid", "NoError", "WrongCode", "UntypedPermissionText", "OtherPermission", "OtherMethod", "NoTunnel", "WrongTunnel", "RejectedTunnel", "HeaderOnTunnel"} {
		t.Run(name, func(t *testing.T) {
			//7 is the gRPC PermissionDenied wire code;13 is Internal.
			err := grpcerrors.WrapCode(fmt.Errorf("%s", llbPingDenial), 7)
			calls := []call{{Method: "POST", Path: "/v1.51/grpc", Status: 101}}
			switch name {
			case "NoError":
				err = nil
			case "WrongCode":
				err = grpcerrors.WrapCode(fmt.Errorf("%s", llbPingDenial), 13)
			case "UntypedPermissionText":
				err = fmt.Errorf("PermissionDenied: %s", llbPingDenial)
			case "OtherPermission":
				err = grpcerrors.WrapCode(fmt.Errorf("Control/Status ref is denied"), 7)
			case "OtherMethod":
				err = grpcerrors.WrapCode(fmt.Errorf("moby.buildkit.v1.frontend.LLBBridge/Solve is denied by sockguard's BuildKit mediation policy"), 7)
			case "NoTunnel":
				calls = nil
			case "WrongTunnel":
				calls[0].Path = "/v1.51/session"
			case "RejectedTunnel":
				calls[0].Status = 403
			case "HeaderOnTunnel":
				calls[0].Header = true
			}
			check := llbOffBuildDenial(err, calls)
			if (check == nil) != (name == "Valid") {
				t.Fatalf("LLB-off boundary assertion accepted=%v scenario=%s err=%v", check == nil, name, check)
			}
		})
	}
}
