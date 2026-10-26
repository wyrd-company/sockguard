// relationships:
//
//	references: [../../../docs/fork-endpoints]
package buildkitproxy

import (
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	"testing"
)

func TestForkEndpointsBuilderGatewayDenied(t *testing.T) {
	policy := Policy{Control: ControlPolicy{AllowInfo: true, AllowListWorkers: true, AllowStatus: true, Solve: SolvePolicy{Allow: true}},
		Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: true}, Auth: AuthPolicy{Allow: true}}}
	for _, endpoint := range []Endpoint{EndpointGRPC, EndpointSession} {
		for _, method := range []string{"Ping", "ResolveImageConfig", "ResolveSourceMeta", "Solve", "Return"} {
			t.Run(endpoint.String()+"/"+method, func(t *testing.T) {
				const service = "moby.buildkit.v1.frontend.LLBBridge"
				if got := Classify(endpoint, service, method); got != Deny {
					t.Fatalf("classification=%s; want deny", got)
				}
				if policy.Allowed(endpoint, service, method) {
					t.Fatal("policy admitted gateway method")
				}
			})
		}
	}
	if got := Classify(EndpointGRPC, "moby.buildkit.v1.Control", "FutureMethod"); got != Deny {
		t.Fatalf("unknown method classification=%s; want deny", got)
	}
}

// v0.18.2 mirrors its first exporter into the deprecated fields. The mirror
// is admitted; a mirror that differs from Exporters[0] is still rejected.
// The modern-only form is the positive control.
func TestForkEndpointsBuilderExporterWireShape(t *testing.T) {
	policy := Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true, AllowedExporters: []string{"moby"}}}}
	request := &control.SolveRequest{Ref: "sample-build", Session: testBuildkitSessionID,
		Exporters: []*control.Exporter{{Type: "moby", Attrs: map[string]string{"name": "sample"}}}}
	if _, denial := evaluateSolveRequest(mustMarshal(t, request), policy); denial != nil {
		t.Fatalf("modern-only control rejected: %+v", denial)
	}
	request.ExporterDeprecated = "moby"
	request.ExporterAttrsDeprecated = map[string]string{"name": "sample"}
	if _, denial := evaluateSolveRequest(mustMarshal(t, request), policy); denial != nil {
		t.Fatalf("SDK mirror of Exporters[0] rejected: %+v", denial)
	}
	request.ExporterAttrsDeprecated = map[string]string{"name": "other"}
	_, denial := evaluateSolveRequest(mustMarshal(t, request), policy)
	if denial == nil || denial.reasonCode != "buildkit_schema_unsupported" || denial.code != grpcCodeFailedPrecondition {
		t.Fatalf("mismatched deprecated fields: got %+v; want schema unsupported", denial)
	}
}
