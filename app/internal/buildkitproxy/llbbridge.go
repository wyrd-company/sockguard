// Fork: wyrd-company/sockguard. This file holds the fork's opt-in,
// uninspected passthrough for moby.buildkit.v1.frontend.LLBBridge on
// POST /grpc. Kept out of registry.go, policy.go and bridge.go so upstream
// security releases rebase cleanly; bridge.go's handleStream consults
// llbBridgePassthroughAdmitted before Classify.
//
// The BuildKit SDK's client.Build (client/build.go, v0.18.2) runs the build
// function in the client and opens an LLBBridge client on the same gRPC
// connection as Control (POST /grpc), not on the session tunnel. The
// registry stays the compile-time default for every operator: LLBBridge is
// absent from it on both endpoints, so Classify still returns Deny. This
// passthrough is the only path that admits it, and only on POST /grpc, only
// for the method names below, and only for a policy that opts in.
//
// Nothing inside an LLBBridge message is inspected: inner LLB ops,
// frontends and their options, mounts, sources, and ExecOp network and
// security modes all reach the daemon as sent. What bounds them is the
// outer Control/Solve that started the build job, which is still mediated
// (evaluateSolveRequest): BuildKit checks every inner op and every gateway
// container against that job's entitlements (solver/llbsolver/bridge.go's
// ValidateEntitlements and validateEntitlements), and the mediator never
// admits security.insecure, nor network.host without allow_host_network,
// on the outer Solve.
package buildkitproxy

import "log/slog"

// llbBridgeService is the LLBBridge gRPC service full name.
const llbBridgeService = "moby.buildkit.v1.frontend.LLBBridge"

// LLBBridgePolicy is the runtime translation of
// request_body.buildkit.llb_bridge (internal/config, client profiles only).
type LLBBridgePolicy struct {
	// AllowUninspectedPassthrough forwards llbBridgeMethods on POST /grpc
	// byte for byte, with the per-stream size cap and no inner inspection.
	AllowUninspectedPassthrough bool
}

// llbBridgeMethods is the LLBBridge method set the passthrough admits: the
// service's methods as DeniedExamples names them (BuildKit's
// frontend/gateway/pb/gateway.proto). Any other method name on the service
// stays denied, so a method added by a later BuildKit release needs a
// reviewed change here.
var llbBridgeMethods = map[string]bool{
	"ResolveImageConfig": true,
	"ResolveSourceMeta":  true,
	"Solve":              true,
	"ReadFile":           true,
	"ReadDir":            true,
	"StatFile":           true,
	"Evaluate":           true,
	"Ping":               true,
	"Return":             true,
	"Inputs":             true,
	"NewContainer":       true,
	"ReleaseContainer":   true,
	"ExecProcess":        true,
	"ReadFileContainer":  true,
	"ReadDirContainer":   true,
	"StatFileContainer":  true,
	"Warn":               true,
}

// llbBridgePassthroughAdmitted reports whether the call is an LLBBridge
// method on POST /grpc that policy opts into passing through uninspected.
// It is false for every other endpoint, service or method, so the caller's
// Classify and Policy.Allowed gates decide those exactly as before.
func llbBridgePassthroughAdmitted(endpoint Endpoint, service, method string, policy Policy) bool {
	return policy.LLBBridge.AllowUninspectedPassthrough &&
		endpoint == EndpointGRPC &&
		service == llbBridgeService &&
		llbBridgeMethods[method]
}

// llbBridgeUninspectedAttr marks a passthrough's buildkit_rpc audit line,
// so that operators can tell an uninspected call from a mediated one.
func llbBridgeUninspectedAttr() slog.Attr {
	return slog.Bool("uninspected", true)
}
