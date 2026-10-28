package buildkitproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/auth"
	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
)

// llbBridgePassthroughPolicy is allowAllPolicy with the fork's LLBBridge
// passthrough turned on.
func llbBridgePassthroughPolicy() Policy {
	p := allowAllPolicy
	p.LLBBridge = LLBBridgePolicy{AllowUninspectedPassthrough: true}
	return p
}

func sortedLLBBridgeMethods() []string {
	methods := make([]string, 0, len(llbBridgeMethods))
	for m := range llbBridgeMethods {
		methods = append(methods, m)
	}
	sort.Strings(methods)
	return methods
}

// requireDeniedBeforeDaemon sends one call through a live bridge and
// asserts PermissionDenied with the daemon never reached.
func requireDeniedBeforeDaemon(t *testing.T, endpoint Endpoint, policy Policy, path, body string) {
	t.Helper()
	var daemonCalled atomic.Bool
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
	tb := newTestBridge(t, endpoint, policy, DefaultLimits(), daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, path, body))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, msg := grpcStatusOf(t, resp)
	if code != grpcCodePermissionDenied {
		t.Fatalf("Grpc-Status = %d, want %d (PERMISSION_DENIED); message = %q", code, grpcCodePermissionDenied, msg)
	}
	if daemonCalled.Load() {
		t.Fatalf("%s on %s reached the daemon", path, endpoint)
	}
}

// With the setting at its default (off), LLBBridge stays denied on both
// tunnels, even with every other BuildKit switch on.
func TestLLBBridgePassthroughDefaultOffDeniesBothTunnels(t *testing.T) {
	if (Policy{}).LLBBridge.AllowUninspectedPassthrough {
		t.Fatal("zero-value Policy turns the LLBBridge passthrough on")
	}
	for _, endpoint := range []Endpoint{EndpointGRPC, EndpointSession} {
		for _, method := range sortedLLBBridgeMethods() {
			t.Run(endpoint.String()+"/"+method, func(t *testing.T) {
				requireDeniedBeforeDaemon(t, endpoint, allowAllPolicy, "/"+llbBridgeService+"/"+method, "payload")
			})
		}
	}
}

// With the setting on, every known LLBBridge method on POST /grpc reaches
// the daemon byte for byte, and the daemon's reply comes back unchanged.
func TestLLBBridgePassthroughForwardsOnGRPC(t *testing.T) {
	for _, method := range sortedLLBBridgeMethods() {
		t.Run(method, func(t *testing.T) {
			tb := newTestBridge(t, EndpointGRPC, llbBridgePassthroughPolicy(), DefaultLimits(), echoDaemonHandler())
			path := "/" + llbBridgeService + "/" + method
			payload := "\x00\x00\x00\x00\x05opaque-llb-bytes"

			resp, err := tb.driver.RoundTrip(newGRPCRequest(t, path, payload))
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("X-Daemon-Saw-Path"); got != path {
				t.Fatalf("daemon saw path %q, want %q", got, path)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading response body: %v", err)
			}
			if string(body) != payload {
				t.Fatalf("response body = %q, want the daemon's exact echo %q", body, payload)
			}
			if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
				t.Fatalf("Grpc-Status trailer = %q, want 0", got)
			}
		})
	}
}

// The passthrough keeps the per-stream size cap.
func TestLLBBridgePassthroughKeepsSizeCap(t *testing.T) {
	var daemonCalled atomic.Bool
	daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		daemonCalled.Store(true)
		_, _ = io.ReadAll(r.Body)
	})
	limits := DefaultLimits()
	limits.MaxMessageBytes = 4
	tb := newTestBridge(t, EndpointGRPC, llbBridgePassthroughPolicy(), limits, daemon)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/"+llbBridgeService+"/Solve", "longer-than-four-bytes"))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	code, _ := grpcStatusOf(t, resp)
	if code != grpcCodeResourceExhausted {
		t.Fatalf("Grpc-Status = %d, want %d (RESOURCE_EXHAUSTED)", code, grpcCodeResourceExhausted)
	}
}

// The passthrough marks its audit line, so that an uninspected call can be
// told from a mediated one.
func TestLLBBridgePassthroughAuditMarksUninspected(t *testing.T) {
	logs := &syncLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tb := newTestBridgeWithLogger(t, EndpointGRPC, llbBridgePassthroughPolicy(), DefaultLimits(), echoDaemonHandler(), logger)

	resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/"+llbBridgeService+"/Ping", ""))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	out := logs.String()
	for _, want := range []string{`"service":"` + llbBridgeService + `"`, `"disposition":"passthrough"`, `"uninspected":true`} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit log lacks %s:\n%s", want, out)
		}
	}
}

// With the setting on, LLBBridge on POST /session stays denied.
func TestLLBBridgePassthroughSessionStaysDenied(t *testing.T) {
	for _, method := range sortedLLBBridgeMethods() {
		t.Run(method, func(t *testing.T) {
			requireDeniedBeforeDaemon(t, EndpointSession, llbBridgePassthroughPolicy(), "/"+llbBridgeService+"/"+method, "payload")
		})
	}
}

// With the setting on, unknown LLBBridge methods and every other denied
// service and method stay denied.
func TestLLBBridgePassthroughUnknownMethodsStayDenied(t *testing.T) {
	cases := []struct {
		endpoint Endpoint
		path     string
	}{
		{EndpointGRPC, "/" + llbBridgeService + "/FutureMethod"},
		{EndpointGRPC, "/" + llbBridgeService + "/solve"},
		{EndpointGRPC, "/moby.buildkit.v1.frontend.LLBBridgeX/Solve"},
		{EndpointGRPC, "/moby.buildkit.v1.Control/Prune"},
		{EndpointGRPC, "/moby.buildkit.v1.Control/FutureMethod"},
		{EndpointGRPC, "/moby.exporter.v1.Exporter/FindExporters"},
		{EndpointSession, "/moby.filesync.v1.FileSync/TarStream"},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint.String()+tc.path, func(t *testing.T) {
			requireDeniedBeforeDaemon(t, tc.endpoint, llbBridgePassthroughPolicy(), tc.path, "payload")
		})
	}
}

// llbBridgePassthroughAdmitted is false for each part of the triple and
// for the policy on its own, so that the caller's gates decide those.
func TestLLBBridgePassthroughAdmittedPredicate(t *testing.T) {
	on := llbBridgePassthroughPolicy()
	cases := []struct {
		name     string
		endpoint Endpoint
		service  string
		method   string
		policy   Policy
		want     bool
	}{
		{"admitted", EndpointGRPC, llbBridgeService, "Solve", on, true},
		{"setting off", EndpointGRPC, llbBridgeService, "Solve", allowAllPolicy, false},
		{"session endpoint", EndpointSession, llbBridgeService, "Solve", on, false},
		{"other service", EndpointGRPC, "moby.buildkit.v1.Control", "Solve", on, false},
		{"unknown method", EndpointGRPC, llbBridgeService, "FutureMethod", on, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := llbBridgePassthroughAdmitted(tc.endpoint, tc.service, tc.method, tc.policy); got != tc.want {
				t.Fatalf("llbBridgePassthroughAdmitted = %v, want %v", got, tc.want)
			}
		})
	}
}

// The passthrough's method set is exactly the LLBBridge methods
// DeniedExamples names, so that the two lists cannot drift apart.
func TestLLBBridgeMethodsMatchDeniedExamples(t *testing.T) {
	var denied []string
	for _, ex := range DeniedExamples {
		if ex.Service == llbBridgeService {
			denied = append(denied, ex.Method)
		}
	}
	sort.Strings(denied)
	if got := sortedLLBBridgeMethods(); strings.Join(got, ",") != strings.Join(denied, ",") {
		t.Fatalf("llbBridgeMethods = %v\nDeniedExamples LLBBridge = %v", got, denied)
	}
}

func TestPolicyConfiguredLLBBridgePassthroughOnly(t *testing.T) {
	if !(Policy{LLBBridge: LLBBridgePolicy{AllowUninspectedPassthrough: true}}).Configured() {
		t.Fatal("Policy with only the LLBBridge passthrough: Configured() = false, want true")
	}
}

// Every outer Control/Solve check still applies with the setting on.
func TestLLBBridgePassthroughKeepsOuterSolveChecks(t *testing.T) {
	const solvePath = "/moby.buildkit.v1.Control/Solve"
	base := func() *control.SolveRequest {
		return &control.SolveRequest{Ref: "sample-ref", Session: testBuildkitSessionID}
	}
	withSolve := func(mut func(*SolvePolicy)) Policy {
		p := llbBridgePassthroughPolicy()
		mut(&p.Control.Solve)
		return p
	}
	cases := []struct {
		name   string
		policy Policy
		req    func() *control.SolveRequest
		code   int
	}{
		{
			name:   "security.insecure denied",
			policy: llbBridgePassthroughPolicy(),
			req: func() *control.SolveRequest {
				r := base()
				r.Entitlements = []string{"security.insecure"}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "security.insecure denied even with allow_host_network",
			policy: withSolve(func(s *SolvePolicy) { s.AllowHostNetwork = true }),
			req: func() *control.SolveRequest {
				r := base()
				r.Entitlements = []string{"security.insecure"}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "network.host denied without allow_host_network",
			policy: llbBridgePassthroughPolicy(),
			req: func() *control.SolveRequest {
				r := base()
				r.Entitlements = []string{"network.host"}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "cache type not allowed",
			policy: llbBridgePassthroughPolicy(),
			req: func() *control.SolveRequest {
				r := base()
				r.Cache = &control.CacheOptions{Imports: []*control.CacheOptionsEntry{{Type: "local"}}}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "cache registry not allowed",
			policy: withSolve(func(s *SolvePolicy) { s.AllowedCacheImportTypes = []string{"registry"} }),
			req: func() *control.SolveRequest {
				r := base()
				r.Cache = &control.CacheOptions{Imports: []*control.CacheOptionsEntry{{Type: "registry", Attrs: map[string]string{"ref": "example.com/cache"}}}}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "deprecated cache ref denied",
			policy: llbBridgePassthroughPolicy(),
			req: func() *control.SolveRequest {
				r := base()
				r.Cache = &control.CacheOptions{ExportRefDeprecated: "example.com/cache"}
				return r
			},
			code: grpcCodeFailedPrecondition,
		},
		{
			name:   "exporter type not allowed",
			policy: llbBridgePassthroughPolicy(),
			req: func() *control.SolveRequest {
				r := base()
				r.Exporters = []*control.Exporter{{Type: "moby"}}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "exporter push registry not allowed",
			policy: withSolve(func(s *SolvePolicy) { s.AllowedExporters = []string{"image"} }),
			req: func() *control.SolveRequest {
				r := base()
				r.Exporters = []*control.Exporter{{Type: "image", Attrs: map[string]string{"name": "example.com/sample", "push": "true"}}}
				return r
			},
			code: grpcCodePermissionDenied,
		},
		{
			name:   "gateway.v0 frontend denied",
			policy: llbBridgePassthroughPolicy(),
			req: func() *control.SolveRequest {
				r := base()
				r.Frontend = "gateway.v0"
				return r
			},
			code: grpcCodePermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var daemonCalled atomic.Bool
			daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { daemonCalled.Store(true) })
			tb := newTestBridge(t, EndpointGRPC, tc.policy, DefaultLimits(), daemon)

			resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, tc.req()))
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			code, msg := grpcStatusOf(t, resp)
			if code != tc.code {
				t.Fatalf("Grpc-Status = %d, want %d; message = %q", code, tc.code, msg)
			}
			if daemonCalled.Load() {
				t.Fatal("a denied Solve reached the daemon")
			}
		})
	}

	// Positive control: the same base request is admitted, so each denial
	// above comes from the field it changes.
	t.Run("base request admitted", func(t *testing.T) {
		var daemonCalled atomic.Bool
		daemon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			daemonCalled.Store(true)
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		})
		tb := newTestBridge(t, EndpointGRPC, llbBridgePassthroughPolicy(), DefaultLimits(), daemon)
		resp, err := tb.driver.RoundTrip(newFramedGRPCRequest(t, solvePath, base()))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if code, msg := grpcStatusOf(t, resp); code != 0 {
			t.Fatalf("Grpc-Status = %d, want 0; message = %q", code, msg)
		}
		if !daemonCalled.Load() {
			t.Fatal("admitted Solve did not reach the daemon")
		}
	})
}

// The session-side checks still apply with the setting on: FileSync with
// its switch off, TarStream, and an Auth host outside the allowlist.
func TestLLBBridgePassthroughKeepsSessionChecks(t *testing.T) {
	t.Run("FileSync switch off", func(t *testing.T) {
		p := llbBridgePassthroughPolicy()
		p.Session.FileSync.Allow = false
		requireDeniedBeforeDaemon(t, EndpointSession, p, "/moby.filesync.v1.FileSync/DiffCopy", "payload")
	})
	t.Run("Auth host not allowed", func(t *testing.T) {
		p := llbBridgePassthroughPolicy()
		p.Session.Auth = AuthPolicy{Allow: true, AllowedRegistries: []string{"registry.example.com"}}
		frame := grpcFrame(mustMarshal(t, &auth.CredentialsRequest{Host: "other.example.com"}))
		requireDeniedBeforeDaemon(t, EndpointSession, p, "/moby.filesync.v1.Auth/Credentials", string(frame))
	})
	t.Run("Auth host allowed (positive control)", func(t *testing.T) {
		p := llbBridgePassthroughPolicy()
		p.Session.Auth = AuthPolicy{Allow: true, AllowedRegistries: []string{"registry.example.com"}}
		tb := newTestBridge(t, EndpointSession, p, DefaultLimits(), echoDaemonHandler())
		frame := grpcFrame(mustMarshal(t, &auth.CredentialsRequest{Host: "registry.example.com"}))
		resp, err := tb.driver.RoundTrip(newGRPCRequest(t, "/moby.filesync.v1.Auth/Credentials", string(frame)))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !bytes.Equal(body, frame) {
			t.Fatalf("admitted Credentials body = %q, want the echoed frame", body)
		}
	})
}
