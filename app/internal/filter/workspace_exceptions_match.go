package filter

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Fork-owned (wyrd-company/sockguard): matching a container to one entry of
// the workspace exceptions file.
//
// MatchWorkspaceException is the one matcher; the create inspector calls it
// with the workspace the request's header names.

// WorkspaceExceptionOutcome is the result class of a match. It is the value
// of the workspace_exception log field.
type WorkspaceExceptionOutcome string

const (
	// WorkspaceExceptionNone: no entry has the request's workspace.
	WorkspaceExceptionNone WorkspaceExceptionOutcome = "none"
	// WorkspaceExceptionApplied: the entry matched; its grants apply.
	WorkspaceExceptionApplied WorkspaceExceptionOutcome = "applied"
	// WorkspaceExceptionNotApplied: an entry has the label's value, or the
	// file is invalid, but a match rule failed. Cause says which.
	WorkspaceExceptionNotApplied WorkspaceExceptionOutcome = "not_applied"
)

// Causes of a WorkspaceExceptionNotApplied outcome.
const (
	WorkspaceCausePolicyFileInvalid     = "policy_file_invalid"
	WorkspaceCauseWorkspaceUnresolvable = "workspace_unresolvable"
	WorkspaceCauseWorkspaceNotCanonical = "workspace_not_canonical"
	WorkspaceCauseWorkspaceNotDirectory = "workspace_not_directory"
	WorkspaceCauseBindSourceOutside     = "bind_source_outside_workspace"
	WorkspaceCauseNoWorkspaceMount      = "no_workspace_mount"
)

// WorkspaceExceptionMount is one HostConfig.Mounts entry as matching reads
// it.
type WorkspaceExceptionMount struct {
	Type   string
	Source string
	// VolumeDriver and VolumeDriverOptions are
	// VolumeOptions.DriverConfig.Name and .Options. A local driver's bind
	// device is a host path and must agree with the workspace too.
	VolumeDriver        string
	VolumeDriverOptions map[string]string
}

// WorkspaceExceptionRequest is the part of a container create request (or of
// an inspected container, for a start re-check) that matching reads.
type WorkspaceExceptionRequest struct {
	// Binds is HostConfig.Binds.
	Binds []string
	// Mounts is HostConfig.Mounts.
	Mounts []WorkspaceExceptionMount
	// Volumes is the key set of Config.Volumes.
	Volumes []string
}

// WorkspaceExceptionMatch is the result of MatchWorkspaceException.
type WorkspaceExceptionMatch struct {
	Outcome WorkspaceExceptionOutcome
	// Workspace is W when an entry has it (or, for an invalid file, when it
	// is a direct child of the workspace root).
	Workspace string
	// Cause is one of the WorkspaceCause* values for a not-applied outcome.
	Cause string
	// Detail is a sentence naming the failure, for deny reasons.
	Detail string

	entry *workspaceExceptionEntry
}

// Applied reports whether the entry's grants apply.
func (m WorkspaceExceptionMatch) Applied() bool {
	return m.Outcome == WorkspaceExceptionApplied && m.entry != nil
}

// ExtraBindSources is the matched entry's extraBindSources grant: the paths
// added to allowed_bind_mounts for this container. Nil unless Applied.
func (m WorkspaceExceptionMatch) ExtraBindSources() []string {
	if !m.Applied() {
		return nil
	}
	return slices.Clone(m.entry.grants.extraBindSources)
}

// RestartPolicies is the matched entry's restartPolicy grant. Nil unless
// Applied.
func (m WorkspaceExceptionMatch) RestartPolicies() []string {
	if !m.Applied() {
		return nil
	}
	return slices.Clone(m.entry.grants.restartPolicies)
}

// Approval is the matched entry's approval. Zero unless Applied.
func (m WorkspaceExceptionMatch) Approval() WorkspaceApproval {
	if !m.Applied() {
		return WorkspaceApproval{}
	}
	return m.entry.approval
}

// LogValue is the workspace_exception log field value:
// "applied", "none" or "not_applied:<cause>".
func (m WorkspaceExceptionMatch) LogValue() string {
	if m.Outcome == WorkspaceExceptionNotApplied {
		return string(m.Outcome) + ":" + m.Cause
	}
	return string(m.Outcome)
}

// MatchWorkspaceException matches a request for workspace W (from the
// X-Sockguard-Workspace header, already checked by the caller together with
// apply_workspace_exceptions and the identity labels) to snap's entry for W:
//
//  1. snap has an entry whose workspace is byte-equal to W.
//  2. W resolves to itself (no symlink on its path) and is a directory, in
//     the proxy's mount namespace.
//  3. Every host path the request mounts (bind sources, host-path Volumes
//     keys, local volume bind devices, overlay directories) resolves inside
//     W or one of the entry's extraBindSources, by the same checks the bind
//     allowlist uses, symlink resolution included.
//  4. At least one bind source resolves to W or inside it.
//
// Details never quote W, which comes from a request header.
func MatchWorkspaceException(snap *WorkspaceExceptionSnapshot, workspace string, req WorkspaceExceptionRequest) WorkspaceExceptionMatch {
	if workspace == "" {
		return WorkspaceExceptionMatch{Outcome: WorkspaceExceptionNone}
	}
	if snap.State() == WorkspaceExceptionsInvalid {
		// No entry can be read. A workspace that could be a key is told why
		// it gets nothing.
		if checkWorkspaceKey(workspace, snap.root) == nil {
			return WorkspaceExceptionMatch{
				Outcome:   WorkspaceExceptionNotApplied,
				Workspace: workspace,
				Cause:     WorkspaceCausePolicyFileInvalid,
				Detail:    "workspace exceptions unavailable: policy file invalid",
			}
		}
		return WorkspaceExceptionMatch{Outcome: WorkspaceExceptionNone}
	}
	if snap.State() != WorkspaceExceptionsLoaded {
		return WorkspaceExceptionMatch{Outcome: WorkspaceExceptionNone}
	}
	entry, ok := snap.entries[workspace]
	if !ok {
		return WorkspaceExceptionMatch{Outcome: WorkspaceExceptionNone}
	}
	notApplied := func(cause, detail string) WorkspaceExceptionMatch {
		return WorkspaceExceptionMatch{
			Outcome:   WorkspaceExceptionNotApplied,
			Workspace: entry.workspace,
			Cause:     cause,
			Detail:    "workspace exception not applied: " + detail,
		}
	}
	if cause, detail := checkWorkspaceFolder(entry.workspace); cause != "" {
		return notApplied(cause, detail)
	}
	hostConfig, volumes := req.containerCreateShape()
	agreement := containerCreatePolicy{allowedBindMounts: workspaceAgreementAllowlist(entry)}
	if reason := agreement.denyBindMountReason(hostConfig); reason != "" {
		return notApplied(WorkspaceCauseBindSourceOutside, outsideWorkspaceDetail(reason))
	}
	if reason := agreement.denyVolumeSpecReason(volumes); reason != "" {
		return notApplied(WorkspaceCauseBindSourceOutside, outsideWorkspaceDetail(reason))
	}
	if !hasWorkspaceMount(entry.workspace, hostConfig, volumes) {
		return notApplied(WorkspaceCauseNoWorkspaceMount, "no bind source is the workspace or inside it")
	}
	return WorkspaceExceptionMatch{Outcome: WorkspaceExceptionApplied, Workspace: entry.workspace, entry: entry}
}

// checkWorkspaceFolder applies the match-time rules for the workspace path.
func checkWorkspaceFolder(workspace string) (cause, detail string) {
	resolved, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return WorkspaceCauseWorkspaceUnresolvable, "the workspace cannot be resolved"
	}
	if resolved != workspace {
		return WorkspaceCauseWorkspaceNotCanonical, "the workspace path has a symlink on it"
	}
	info, err := os.Stat(workspace)
	if err != nil || !info.IsDir() {
		return WorkspaceCauseWorkspaceNotDirectory, "the workspace is not a directory"
	}
	return "", ""
}

// workspaceAgreementAllowlist is the allowlist the agreement rule checks
// every host path against: the workspace and the entry's extra bind sources.
func workspaceAgreementAllowlist(entry *workspaceExceptionEntry) []string {
	return append([]string{entry.workspace}, entry.grants.extraBindSources...)
}

// outsideWorkspaceDetail rewords a bind check's deny reason, which was
// computed against the workspace allowlist, for the not-applied message.
func outsideWorkspaceDetail(reason string) string {
	reason = strings.TrimPrefix(reason, "container create denied: ")
	return "a host path is outside the workspace and its extra bind sources (" + reason + ")"
}

// hasWorkspaceMount reports whether a bind source resolves to the workspace
// or inside it.
func hasWorkspaceMount(workspace string, hostConfig containerCreateHostConfig, volumes map[string]struct{}) bool {
	var sources []string
	for _, bind := range hostConfig.Binds {
		sources = append(sources, bindSpecHostSource(bind))
	}
	for spec := range volumes {
		if strings.Contains(spec, ":/") {
			sources = append(sources, bindSpecHostSource(spec))
		}
	}
	for _, mount := range hostConfig.Mounts {
		if strings.EqualFold(mount.Type, "bind") {
			sources = append(sources, mount.Source)
		}
	}
	for _, source := range sources {
		cleaned, ok := normalizeBindMount(source)
		if !ok {
			continue
		}
		resolved, err := resolveBindSource(cleaned)
		if err == nil && bindPathAllowed(resolved, []string{workspace}) {
			return true
		}
	}
	return false
}

// bindSpecHostSource is the first ":" field of a bind spec; "" when the spec
// has none.
func bindSpecHostSource(spec string) string {
	source, _, ok := strings.Cut(spec, ":")
	if !ok || !path.IsAbs(source) {
		return ""
	}
	return source
}

// containerCreateShape converts req to the decode shapes the bind checks
// take.
func (req WorkspaceExceptionRequest) containerCreateShape() (containerCreateHostConfig, map[string]struct{}) {
	hostConfig := containerCreateHostConfig{Binds: req.Binds}
	for _, m := range req.Mounts {
		mount := containerCreateMount{Type: m.Type, Source: m.Source}
		if m.VolumeDriver != "" || m.VolumeDriverOptions != nil {
			mount.VolumeOptions = &containerCreateMountVolumeOptions{
				DriverConfig: &containerCreateMountVolumeDriverConfig{Name: m.VolumeDriver, Options: m.VolumeDriverOptions},
			}
		}
		hostConfig.Mounts = append(hostConfig.Mounts, mount)
	}
	var volumes map[string]struct{}
	if len(req.Volumes) > 0 {
		volumes = make(map[string]struct{}, len(req.Volumes))
		for _, v := range req.Volumes {
			volumes[v] = struct{}{}
		}
	}
	return hostConfig, volumes
}

// workspaceExceptionRequestFromCreate builds the matcher input from a decoded
// create request.
func workspaceExceptionRequestFromCreate(req *containerCreateRequest) WorkspaceExceptionRequest {
	out := WorkspaceExceptionRequest{Binds: req.HostConfig.Binds}
	for _, m := range req.HostConfig.Mounts {
		mount := WorkspaceExceptionMount{Type: m.Type, Source: m.Source}
		if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
			mount.VolumeDriver = m.VolumeOptions.DriverConfig.Name
			mount.VolumeDriverOptions = m.VolumeOptions.DriverConfig.Options
		}
		out.Mounts = append(out.Mounts, mount)
	}
	for v := range req.Volumes {
		out.Volumes = append(out.Volumes, v)
	}
	slices.Sort(out.Volumes)
	return out
}
