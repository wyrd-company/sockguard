// relationships:
//
//	references: [../../../docs/fork-endpoints]
package buildkitproxy

import (
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	"testing"
)

// With llb_bridge left at its default, the gateway methods the builder
// calls stay denied on both tunnels, even with the Control and session
// switches the build needs turned on.
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
				if llbBridgePassthroughAdmitted(endpoint, service, method, policy) {
					t.Fatal("passthrough admitted gateway method with llb_bridge off")
				}
			})
		}
	}
	if got := Classify(EndpointGRPC, "moby.buildkit.v1.Control", "FutureMethod"); got != Deny {
		t.Fatalf("unknown method classification=%s; want deny", got)
	}
}

// With llb_bridge.allow_uninspected_passthrough on, the same gateway
// methods are forwarded on /grpc only. The compile-time registry is
// unchanged, /session stays denied, and an unknown method stays denied.
func TestForkEndpointsBuilderGatewayPassthroughOnGRPC(t *testing.T) {
	policy := Policy{Control: ControlPolicy{AllowInfo: true, AllowListWorkers: true, AllowStatus: true, Solve: SolvePolicy{Allow: true}},
		Session:   SessionPolicy{FileSync: FileSyncPolicy{Allow: true}, Auth: AuthPolicy{Allow: true}},
		LLBBridge: LLBBridgePolicy{AllowUninspectedPassthrough: true}}
	const service = "moby.buildkit.v1.frontend.LLBBridge"
	for _, method := range []string{"Ping", "ResolveImageConfig", "ResolveSourceMeta", "Solve", "Return"} {
		t.Run(method, func(t *testing.T) {
			if got := Classify(EndpointGRPC, service, method); got != Deny {
				t.Fatalf("registry classification=%s; want deny (the registry is not changed)", got)
			}
			if !llbBridgePassthroughAdmitted(EndpointGRPC, service, method, policy) {
				t.Fatal("/grpc gateway method not passed through")
			}
			if llbBridgePassthroughAdmitted(EndpointSession, service, method, policy) {
				t.Fatal("/session gateway method passed through")
			}
		})
	}
	if llbBridgePassthroughAdmitted(EndpointGRPC, service, "FutureMethod", policy) {
		t.Fatal("unknown gateway method passed through")
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
