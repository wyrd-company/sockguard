package buildkitproxy

import (
	"testing"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
)

// sdkMirroredSolveRequest reconstructs the outer Control/Solve the BuildKit
// SDK (client/solve.go:254-282, v0.18.2) sends for client.Build with one
// exporter: Frontend cleared, no Definition, an empty CacheOptions, the
// modern Exporters list, and the first exporter mirrored into the
// deprecated fields.
func sdkMirroredSolveRequest() *control.SolveRequest {
	attrs := map[string]string{"name": "sample-image:latest"}
	return &control.SolveRequest{
		Ref:                     "sample-build-ref",
		Session:                 testBuildkitSessionID,
		Cache:                   &control.CacheOptions{},
		Exporters:               []*control.Exporter{{Type: "moby", Attrs: attrs}},
		ExporterDeprecated:      "moby",
		ExporterAttrsDeprecated: map[string]string{"name": "sample-image:latest"},
	}
}

func exporterCompatPolicy() Policy {
	return Policy{Control: ControlPolicy{Solve: SolvePolicy{Allow: true, AllowedExporters: []string{"moby", "image"}}}}
}

func TestSolveDeprecatedExporterSDKWireShapeAdmitted(t *testing.T) {
	req, denial := evaluateSolveRequest(mustMarshal(t, sdkMirroredSolveRequest()), exporterCompatPolicy())
	if denial != nil {
		t.Fatalf("SDK wire shape denied: %+v", denial)
	}
	if req.GetRef() != "sample-build-ref" {
		t.Fatalf("ref = %q; want sample-build-ref", req.GetRef())
	}
}

func TestSolveDeprecatedExporterSDKWireShapeMismatchDenied(t *testing.T) {
	request := sdkMirroredSolveRequest()
	request.ExporterAttrsDeprecated = map[string]string{"name": "other-image:latest"}
	_, denial := evaluateSolveRequest(mustMarshal(t, request), exporterCompatPolicy())
	if denial == nil || denial.reasonCode != "buildkit_schema_unsupported" || denial.code != grpcCodeFailedPrecondition {
		t.Fatalf("mismatched SDK wire shape: got %+v; want buildkit_schema_unsupported", denial)
	}
}

func TestCheckSolveDeprecatedExporter(t *testing.T) {
	modern := func(typ string, attrs map[string]string) []*control.Exporter {
		return []*control.Exporter{{Type: typ, Attrs: attrs}}
	}
	cases := []struct {
		name      string
		req       *control.SolveRequest
		wantAdmit bool
	}{
		{
			name:      "no deprecated fields",
			req:       &control.SolveRequest{Exporters: modern("moby", map[string]string{"name": "sample"})},
			wantAdmit: true,
		},
		{
			name: "equal type and attrs",
			req: &control.SolveRequest{
				Exporters:               modern("moby", map[string]string{"name": "sample"}),
				ExporterDeprecated:      "moby",
				ExporterAttrsDeprecated: map[string]string{"name": "sample"},
			},
			wantAdmit: true,
		},
		{
			name: "equal type with no attrs on either side",
			req: &control.SolveRequest{
				Exporters:          modern("moby", nil),
				ExporterDeprecated: "moby",
			},
			wantAdmit: true,
		},
		{
			name: "equal to the first of several exporters",
			req: &control.SolveRequest{
				Exporters: []*control.Exporter{
					{Type: "moby", Attrs: map[string]string{"name": "sample"}},
					{Type: "image", Attrs: map[string]string{"name": "other"}},
				},
				ExporterDeprecated:      "moby",
				ExporterAttrsDeprecated: map[string]string{"name": "sample"},
			},
			wantAdmit: true,
		},
		{
			name: "type mismatch",
			req: &control.SolveRequest{
				Exporters:               modern("moby", map[string]string{"name": "sample"}),
				ExporterDeprecated:      "image",
				ExporterAttrsDeprecated: map[string]string{"name": "sample"},
			},
		},
		{
			name: "type equals a later exporter, not the first",
			req: &control.SolveRequest{
				Exporters: []*control.Exporter{
					{Type: "moby", Attrs: map[string]string{"name": "sample"}},
					{Type: "image", Attrs: map[string]string{"name": "sample"}},
				},
				ExporterDeprecated:      "image",
				ExporterAttrsDeprecated: map[string]string{"name": "sample"},
			},
		},
		{
			name: "attrs value mismatch",
			req: &control.SolveRequest{
				Exporters:               modern("image", map[string]string{"name": "sample", "push": "false"}),
				ExporterDeprecated:      "image",
				ExporterAttrsDeprecated: map[string]string{"name": "sample", "push": "true"},
			},
		},
		{
			name: "attrs extra key in deprecated",
			req: &control.SolveRequest{
				Exporters:               modern("moby", map[string]string{"name": "sample"}),
				ExporterDeprecated:      "moby",
				ExporterAttrsDeprecated: map[string]string{"name": "sample", "push": "true"},
			},
		},
		{
			name: "attrs missing in deprecated",
			req: &control.SolveRequest{
				Exporters:          modern("moby", map[string]string{"name": "sample"}),
				ExporterDeprecated: "moby",
			},
		},
		{
			name: "deprecated type without modern exporters",
			req:  &control.SolveRequest{ExporterDeprecated: "moby"},
		},
		{
			name: "deprecated attrs without modern exporters",
			req:  &control.SolveRequest{ExporterAttrsDeprecated: map[string]string{"name": "sample"}},
		},
		{
			name: "deprecated attrs only, with modern exporters",
			req: &control.SolveRequest{
				Exporters:               modern("moby", map[string]string{"name": "sample"}),
				ExporterAttrsDeprecated: map[string]string{"name": "sample"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			denial := checkSolveDeprecatedExporter(tc.req)
			if tc.wantAdmit {
				if denial != nil {
					t.Fatalf("denied: %+v", denial)
				}
				return
			}
			if denial == nil || denial.reasonCode != "buildkit_schema_unsupported" || denial.code != grpcCodeFailedPrecondition {
				t.Fatalf("got %+v; want buildkit_schema_unsupported FailedPrecondition", denial)
			}
		})
	}
}

// The deprecated cache-ref fields keep their outright denial even when the
// exporter mirror is admitted.
func TestSolveDeprecatedCacheFieldsStillDeniedWithExporterMirror(t *testing.T) {
	request := sdkMirroredSolveRequest()
	request.Cache = &control.CacheOptions{ExportRefDeprecated: "example.com/cache"}
	_, denial := evaluateSolveRequest(mustMarshal(t, request), exporterCompatPolicy())
	if denial == nil || denial.reasonCode != "buildkit_schema_unsupported" {
		t.Fatalf("got %+v; want buildkit_schema_unsupported", denial)
	}
}
