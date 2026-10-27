package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// Fork-owned (wyrd-company/sockguard): bind-source re-check at container start
// and restart.
//
// The create check (symlink_bind_resolve.go) sees the filesystem as it is at
// create time. The daemon resolves each bind source again at every start and
// follows symlinks, and container inspect keeps the source as it was written
// at create. A real directory that is replaced with a symlink after create is
// therefore mounted through the symlink at the next start. Before a start or
// restart is forwarded, this policy inspects the container through the daemon,
// resolves each bind source again and applies the create check to the result.
//
// The re-check holds a source only to an allowlist that admits it as written.
// A source that no allowlist admits was not created under this policy (another
// client, a host tool, a wider profile, an allowlist changed since), and its
// start passes as before, so the re-check narrows nothing that create allowed.
// See docs/content/docs/symlink-bind-sources.mdx for the gaps that remain.

// Reason codes of the start re-check. They are distinct from the create
// check's request_body_policy_denied so an alert can tell the two apart.
const (
	forkStartRecheckReasonCodeBindSourceDenied = "container_start_bind_source_denied"
	forkStartRecheckReasonCodeInspectFailed    = "container_start_inspect_failed"
)

// ForkStartRecheckInspectFunc reads the bind sources of the container id
// through the upstream daemon. Any error makes the start fail closed.
type ForkStartRecheckInspectFunc func(ctx context.Context, id string) (ForkStartRecheckContainer, error)

// ForkStartRecheckOptions configures the bind-source re-check on container
// start and restart. The allowlists are the active policy's
// ContainerCreate.AllowedBindMounts and LibpodContainerCreate.AllowedBindMounts;
// this only carries the runtime inspector, which the serve chain attaches.
type ForkStartRecheckOptions struct {
	InspectContainer ForkStartRecheckInspectFunc
}

// ForkStartRecheckContainer is the part of GET /containers/{id}/json the
// re-check reads.
type ForkStartRecheckContainer struct {
	HostConfig ForkStartRecheckHostConfig `json:"HostConfig"`
	// Mounts holds the mount points the daemon mounts at start, with the
	// source it stored at create.
	Mounts []ForkStartRecheckMount `json:"Mounts"`
}

// ForkStartRecheckHostConfig holds the bind specs as the create request wrote
// them.
type ForkStartRecheckHostConfig struct {
	Binds  []string                `json:"Binds"`
	Mounts []ForkStartRecheckMount `json:"Mounts"`
}

// ForkStartRecheckMount is one mount entry; only bind entries are read.
type ForkStartRecheckMount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}

// NewForkStartRecheckInspectorWithRoundTripper returns an inspector that issues
// GET /containers/{id}/json through the shared upstream RoundTripper, so the
// inspect follows the same active endpoint as the start it guards and uses the
// transport's existing timeouts. Podman serves the same Docker-compatible
// route, so the inspector covers libpod starts too.
func NewForkStartRecheckInspectorWithRoundTripper(rt http.RoundTripper) ForkStartRecheckInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, id string) (ForkStartRecheckContainer, error) {
		target, _ := dockerresource.InspectPath(dockerresource.KindContainer, id)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil) // #nosec G704 -- the injected transport targets the local container-engine socket, and InspectPath path-escapes the identifier.
		if err != nil {
			return ForkStartRecheckContainer{}, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected transport targets the local container-engine socket, not the URL host.
		if err != nil {
			return ForkStartRecheckContainer{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return ForkStartRecheckContainer{}, fmt.Errorf("upstream returned %s", resp.Status)
		}
		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ForkStartRecheckContainer{}, err
		}
		var container ForkStartRecheckContainer
		if err := json.Unmarshal(body, &container); err != nil {
			return ForkStartRecheckContainer{}, fmt.Errorf("decode container inspect: %w", err)
		}
		return container, nil
	}
}

type forkStartRecheckPolicy struct {
	// allowlists holds each create allowlist that is set and does not hold
	// "/". It is empty when no allowlist needs the re-check.
	allowlists       [][]string
	inspectContainer ForkStartRecheckInspectFunc
}

func newForkStartRecheckPolicy(cfg PolicyConfig) forkStartRecheckPolicy {
	p := forkStartRecheckPolicy{inspectContainer: cfg.ForkStartRecheck.InspectContainer}
	for _, entries := range [][]string{cfg.ContainerCreate.AllowedBindMounts, cfg.LibpodContainerCreate.AllowedBindMounts} {
		allowed := forkStartRecheckAllowlist(entries)
		if slices.Contains(allowed, "/") {
			// "/" admits every source and the create check resolves none, so
			// no start can fail the re-check.
			return forkStartRecheckPolicy{}
		}
		if len(allowed) > 0 {
			p.allowlists = append(p.allowlists, allowed)
		}
	}
	return p
}

// forkStartRecheckAllowlist normalizes entries the way newContainerCreatePolicy
// and newLibpodContainerCreatePolicy do.
func forkStartRecheckAllowlist(entries []string) []string {
	allowed := make([]string, 0, len(entries))
	for _, entry := range entries {
		normalized, ok := normalizeBindMount(entry)
		if !ok || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return allowed
}

func matchesForkStartRecheckInspection(normalizedPath string) bool {
	_, _, ok := forkStartRecheckTarget(normalizedPath)
	return ok
}

// forkStartRecheckTarget returns the container identifier of a start or
// restart path and the subject its deny reasons name. Docker registers
// /containers/{name:.*}/start, so the identifier is everything between the
// prefix and the last segment.
func forkStartRecheckTarget(normalizedPath string) (id, subject string, ok bool) {
	prefix, family := "/containers/", "container"
	if strings.HasPrefix(normalizedPath, libpodPathPrefix+"containers/") {
		prefix, family = libpodPathPrefix+"containers/", "libpod container"
	}
	rest, found := strings.CutPrefix(normalizedPath, prefix)
	if !found {
		return "", "", false
	}
	for _, action := range []string{"start", "restart"} {
		if id, found := strings.CutSuffix(rest, "/"+action); found && id != "" {
			return id, family + " " + action, true
		}
	}
	return "", "", false
}

func (p forkStartRecheckPolicy) inspect(logger *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if r == nil || r.Method != http.MethodPost || len(p.allowlists) == 0 {
		return "", nil
	}
	id, subject, ok := forkStartRecheckTarget(normalizedPath)
	if !ok {
		return "", nil
	}
	if p.inspectContainer == nil {
		return "", forkStartRecheckInspectFailed(subject, id)
	}
	container, err := p.inspectContainer(r.Context(), id)
	if err != nil {
		logRequestError(logger, r, slog.LevelWarn, "container start re-check: inspect failed; denying", err)
		return "", forkStartRecheckInspectFailed(subject, id)
	}
	if reason := p.denyReason(subject, container); reason != "" {
		return "", newRequestRejectionErrorWithCode(http.StatusForbidden, forkStartRecheckReasonCodeBindSourceDenied, reason)
	}
	return "", nil
}

func forkStartRecheckInspectFailed(subject, id string) error {
	return newRequestRejectionErrorWithCode(http.StatusForbidden, forkStartRecheckReasonCodeInspectFailed,
		fmt.Sprintf("%s denied: container %q could not be inspected to re-check its bind sources", subject, id))
}

func (p forkStartRecheckPolicy) denyReason(subject string, container ForkStartRecheckContainer) string {
	for _, source := range forkStartRecheckSources(container) {
		if reason := p.denySourceReason(subject, source); reason != "" {
			return reason
		}
	}
	return ""
}

// denySourceReason applies the create check to one source under each
// allowlist that admits it as written. The source passes when one such
// allowlist also admits it after resolution, or when none admits it at all.
func (p forkStartRecheckPolicy) denySourceReason(subject string, source forkStartRecheckSource) string {
	first := ""
	for _, allowed := range p.allowlists {
		if !bindPathAllowed(source.clean, allowed) {
			continue
		}
		reason := denySymlinkedBindSourceReason(subject, "bind mount source", source.raw, source.clean, allowed)
		if reason == "" {
			return ""
		}
		if first == "" {
			first = reason
		}
	}
	return first
}

type forkStartRecheckSource struct {
	// raw is the source as stored, clean its lexically cleaned form.
	raw, clean string
}

// forkStartRecheckSources returns every absolute bind source of the container:
// the mount points the daemon mounts and the create request's Binds and bind
// Mounts as written, which can spell the same source with "..".
func forkStartRecheckSources(container ForkStartRecheckContainer) []forkStartRecheckSource {
	var out []forkStartRecheckSource
	add := func(raw string) {
		clean, ok := normalizeBindMount(raw)
		if !ok || slices.ContainsFunc(out, func(s forkStartRecheckSource) bool { return s.raw == raw }) {
			return
		}
		out = append(out, forkStartRecheckSource{raw: raw, clean: clean})
	}
	for _, mount := range container.Mounts {
		if strings.EqualFold(mount.Type, "bind") {
			add(mount.Source)
		}
	}
	for _, bind := range container.HostConfig.Binds {
		if raw, _, ok := strings.Cut(bind, ":"); ok {
			add(raw)
		}
	}
	for _, mount := range container.HostConfig.Mounts {
		if strings.EqualFold(mount.Type, "bind") {
			add(mount.Source)
		}
	}
	return out
}
