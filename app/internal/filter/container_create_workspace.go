package filter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// Fork-owned (wyrd-company/sockguard): workspace exceptions and the
// restart-policy gate on Docker-compat POST /containers/create.
//
// inspectWithWorkspaceExceptions wraps containerCreatePolicy.inspect. With
// neither apply_workspace_exceptions nor require_no_restart_policy set it is
// inspect, unchanged. Otherwise it decodes the body once more to:
//
//   - take one exceptions snapshot at admission and match the request to a
//     workspace entry (MatchWorkspaceException);
//   - on a match, run inspect with the base policy plus that entry's grants
//     (withWorkspaceGrants), which only opens gates;
//   - deny a restart policy the base block refuses and the matched entry
//     does not grant.
//
// A request that matches no entry is inspected with the base policy alone.

// restartPolicyNoRestart holds the RestartPolicy.Name values that need no grant:
// both leave the daemon without a reason to start the container by itself.
var restartPolicyNoRestart = []string{"", "no"}

type containerCreateRestartPolicyBody struct {
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

func (p containerCreatePolicy) inspectWithWorkspaceExceptions(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !p.applyWorkspaceExceptions && !p.requireNoRestartPolicy {
		return p.inspect(logger, r, normalizedPath)
	}
	if r == nil || r.Method != http.MethodPost || normalizedPath != "/containers/create" {
		return p.inspect(logger, r, normalizedPath)
	}
	// The snapshot is taken before the body is read, so a replace that
	// lands while the body streams in does not change this request.
	snap := p.workspaceExceptions.Load()
	// The workspace comes from the request headers, before the body is
	// read: a create without a valid workspace is denied whatever it
	// carries, an empty or unreadable body included.
	identity := WorkspaceIdentity{Kind: WorkspaceIdentityNone}
	if p.applyWorkspaceExceptions {
		var reason string
		if identity, reason = workspaceHeaderDenyReason(r.Header, snap, "container create"); reason != "" {
			return reason, nil
		}
	}
	if r.Body == nil {
		return p.inspect(logger, r, normalizedPath)
	}

	// On every read or decode failure, inspect reads the restored body
	// again and gives its own refusal (size, ambiguous keys, malformed
	// JSON), exactly as without this wrapper.
	body, err := readBoundedBody(r, maxContainerCreateBodyBytes)
	if err != nil || len(body) == 0 {
		return p.inspect(logger, r, normalizedPath)
	}
	var req containerCreateRequest
	var restart containerCreateRestartPolicyBody
	if json.Unmarshal(body, &req) != nil || json.Unmarshal(body, &restart) != nil {
		return p.inspect(logger, r, normalizedPath)
	}

	match := WorkspaceExceptionMatch{Outcome: WorkspaceExceptionNone}
	matchReq := workspaceExceptionRequestFromCreate(&req)
	if p.applyWorkspaceExceptions {
		if reason := workspaceLabelDenyReason(req.Labels, identity, "container create"); reason != "" {
			return reason, nil
		}
		// Only the devcontainer header can match an exception; the
		// throwaway header scopes binds and never grants.
		if identity.Kind == WorkspaceIdentityDevcontainer {
			match = MatchWorkspaceException(snap, identity.Workspace, matchReq)
		}
	}
	reason, err := p.inspectMatched(logger, r, normalizedPath, &req, restart.HostConfig.RestartPolicy.Name, match)
	if err != nil {
		return "", err
	}
	if reason == "" && p.applyWorkspaceExceptions {
		allowed := p.allowedBindMounts
		if match.Applied() {
			allowed = unionStrings(allowed, match.entry.grants.extraBindSources)
		}
		reason = DenyWorkspaceScopeReason(snap, identity, matchReq, allowed)
	}
	if reason != "" && match.Outcome == WorkspaceExceptionNotApplied {
		reason += "; " + match.Detail
	}
	if identity.Kind == WorkspaceIdentityDevcontainer {
		logWorkspaceExceptionDecision(logger, r, match, reason)
	}
	return reason, nil
}

// inspectMatched evaluates the request with the policy match selects.
func (p containerCreatePolicy) inspectMatched(logger *slog.Logger, r *http.Request, normalizedPath string, req *containerCreateRequest, restartPolicy string, match WorkspaceExceptionMatch) (string, error) {
	effective := p
	var grants workspaceGrants
	if match.Applied() {
		grants = match.entry.grants
		// A namespace gate opened only by a grant admits "host" and
		// nothing more: "ns:<path>" is held to the base policy's gates.
		if reason := p.denyNamespacePathReason(req.HostConfig); reason != "" {
			return reason, nil
		}
		effective = p.withWorkspaceGrants(grants, req)
	}
	if reason := p.denyRestartPolicyReason(restartPolicy, grants.restartPolicies); reason != "" {
		return reason, nil
	}
	return effective.inspect(logger, r, normalizedPath)
}

// denyRestartPolicyReason is require_no_restart_policy. A policy other than
// "" or "no" lets the daemon start the container without a request through
// the proxy, so the start-time bind re-check never sees that start. granted
// is the matched entry's restartPolicy grant.
func (p containerCreatePolicy) denyRestartPolicyReason(name string, granted []string) string {
	if !p.requireNoRestartPolicy || slices.Contains(restartPolicyNoRestart, name) {
		return ""
	}
	if slices.Contains(granted, name) {
		return ""
	}
	return fmt.Sprintf("container create denied: restart policy %q is not allowed", name)
}

// withWorkspaceGrants returns p with g's gates opened for req. Booleans are
// ORed and lists are unioned, so the result admits everything p admits. An
// allowlist whose empty form means "anything" (seccomp, AppArmor) is only
// extended when p already constrains it.
func (p containerCreatePolicy) withWorkspaceGrants(g workspaceGrants, req *containerCreateRequest) containerCreatePolicy {
	e := p
	e.allowPrivileged = p.allowPrivileged || g.privileged
	e.allowAllCapabilities = p.allowAllCapabilities || g.allCapabilities
	e.allowedCapabilities = unionStrings(p.allowedCapabilities, g.capabilities)
	e.allowHostPID = p.allowHostPID || g.hostPID
	e.allowHostIPC = p.allowHostIPC || g.hostIPC
	e.allowHostNetwork = p.allowHostNetwork || g.hostNetwork
	e.allowHostUserNS = p.allowHostUserNS || g.hostUserNS
	e.allowHostCgroupNS = p.allowHostCgroupNS || g.hostCgroupNS
	e.allowedDevices = unionStrings(p.allowedDevices, g.devices)
	e.allowedDeviceCgroupRules = unionStrings(p.allowedDeviceCgroupRules, g.deviceCgroupRules)
	e.allowDeviceRequests = p.allowDeviceRequests || g.gpus
	e.allowedBindMounts = unionStrings(p.allowedBindMounts, g.extraBindSources)
	e.allowedRuntimes = unionStrings(p.allowedRuntimes, g.runtimes)
	if g.seccompUnconfined {
		e.denyUnconfinedSeccomp = false
		if len(p.allowedSeccompProfiles) > 0 {
			e.allowedSeccompProfiles = unionStrings(p.allowedSeccompProfiles, []string{"unconfined"})
		}
	}
	if g.appArmorUnconfined {
		e.denyUnconfinedAppArmor = false
		if len(p.allowedAppArmorProfiles) > 0 {
			e.allowedAppArmorProfiles = unionStrings(p.allowedAppArmorProfiles, []string{"unconfined"})
		}
	}
	if len(g.appArmorProfiles) > 0 && len(p.allowedAppArmorProfiles) > 0 {
		e.allowedAppArmorProfiles = unionStrings(e.allowedAppArmorProfiles, g.appArmorProfiles)
	}
	if g.selinuxDisable {
		e.denySelinuxDisable = false
	}
	if g.systemPathsUnconfined {
		e.denyUnconfinedSystemPaths = false
	}
	if !p.allowSysctls && len(req.HostConfig.Sysctls) > 0 && sysctlKeysGranted(req.HostConfig.Sysctls, g.sysctls) {
		e.allowSysctls = true
	}
	return e
}

// sysctlKeysGranted reports whether every requested sysctl key is granted.
// Values are not compared.
func sysctlKeysGranted(requested map[string]string, granted []string) bool {
	for key := range requested {
		if !slices.Contains(granted, key) {
			return false
		}
	}
	return true
}

// unionStrings returns a new slice holding base and then the entries of add
// that base lacks. base is never written to.
func unionStrings(base, add []string) []string {
	if len(add) == 0 {
		return base
	}
	out := slices.Clone(base)
	for _, v := range add {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func logWorkspaceExceptionDecision(logger *slog.Logger, r *http.Request, match WorkspaceExceptionMatch, reason string) {
	if logger == nil {
		return
	}
	decision := "allow"
	if reason != "" {
		decision = "deny"
	}
	attrs := []any{
		"workspace_exception", match.LogValue(),
		"workspace", logging.SafeString(match.Workspace),
		"decision", decision,
		"method", logging.SafeString(r.Method),
		"path", logging.SafeString(r.URL.Path),
	}
	if match.Applied() {
		approval := match.Approval()
		attrs = append(attrs,
			"approval_by_issuer", logging.SafeString(approval.Issuer),
			"approval_by_subject", logging.SafeString(approval.Subject),
			"approval_at", logging.SafeString(approval.At),
		)
	}
	logger.Log(r.Context(), slog.LevelInfo, "container create workspace exception", attrs...)
}
