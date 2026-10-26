---
relationships:
  references:
    - ../app/internal/buildkitproxy/registry.go
    - ../app/internal/buildkitproxy/solve.go
    - ../app/internal/filter/fork_endpoints_policy_test.go
    - ../app/internal/buildkitproxy/fork_endpoints_builder_test.go
---

# Menagerie Engine endpoint compatibility

## Finding and evidence boundary

Container start, stop, inspect, remove and exec can use narrow HTTP rules with
explicit body settings. **The normal devcontainer build does not work through
Sockguard's mediated BuildKit connection.** It needs LLBBridge, which is denied
on both tunnels. A second independent incompatibility is the builder SDK's
legacy exporter fields. Adding HTTP rules cannot fix either incompatibility.

This is a source audit and a set of local policy tests, not a successful live
build through a deployed Menagerie policy. No Menagerie proxy configuration or
Go implementation is present in the inspected Menagerie tree. The rule set in
the test is a candidate minimum, not an approved deployment configuration.
The research does not change proxy code or the Menagerie design.

Evidence inputs:

- Sockguard base: `3854e684db275985b9f9d2e7a4f5962a1cd7d6e5`.
- devcontainer-builder (DCB): `5ca13fc5c200417801b3dff2635cc83c5cec8df8`,
  `/workspaces/shared/tools/devcontainer-builder`.
- Menagerie `epic/0.1.0`: `10f93203173b0352ef2be644855cb65c7c219ebb`,
  `/workspaces/tools/menagerie`; design `docker-boundary`,
  `container-operations`, `template-hooks`, `initialize-command`, and risk
  `docs/risks/buildkit-traffic-not-inspectable.yml`.
- DCB `go.mod:11,15`: Docker SDK `v28.5.2+incompatible`, BuildKit `v0.18.2`.
  SDK paths below are relative to those versions in `/go/pkg/mod`.

## Engine calls

Paths below omit the optional `/v1.xx` prefix. Sockguard normalizes that prefix
before matching. `{id}` means one identifier; `{name}` can contain registry and
repository slashes. Query parameters are not part of rule path matching.
“Needs rule” means denied by the unconfigured default; a candidate allow rule
admits the route, subject to the listed content checks. This does not grant
cross-container ownership or read visibility: deployment must configure those
separately if required.

The Menagerie design also requires bind-source revalidation at every start and
restart. Route admission in this report does not prove that lifecycle guard;
the fork's bind-policy work and acceptance tests must supply that evidence.

| Method and path | DCB caller | Upgrade or inspected input | Policy result / requirement |
| --- | --- | --- | --- |
| `HEAD /_ping`, fallback `GET /_ping` | SDK version negotiation; `pkg/buildkit/connect.go:60`, caller-supplied Docker client for host operations; SDK `client/ping.go` | No body; negotiation reads API headers | Needs both rules for SDK negotiation and fallback |
| `GET /containers/json` | `pkg/host/docker/spawn.go:90` (`findLabeled`), used by up, inspect, stop and remove | `all=1`, label filters | Needs rule; filter comes from client and is not an authorization boundary |
| `GET /containers/{id}/json` | `pkg/host/docker/up.go:161,230,263`, `manage.go:42` | No body | Needs rule; discovers mount, user, environment and state data |
| `GET /images/{name}/json` | `pkg/host/docker/image.go:18`, `up.go:193,363`, `pkg/builder/metadata.go:78`, `internal/dockerimage/image.go:73,109` | No body; inspect path must allow slash-bearing names | Needs rule; `GET /images/**/json` covers registry/repository names |
| `POST /images/create` | `internal/dockerimage/image.go:34`, called by host image ensure and builder metadata resolution | `fromImage`, `tag`, `X-Registry-Auth`; image-pull inspector | Needs rule and approved registry allowlist; no import grant needed |
| `POST /containers/create` | `pkg/host/docker/up.go:371` | Config, HostConfig, mounts, labels, user, env; create inspector | Needs rule and workspace bind grants; exception-sensitive fields remain denied without an exception. This audit does not prove the complete HostConfig contract |
| `POST /containers/{id}/start` | `pkg/host/docker/up.go:257` | SDK sends no body | Needs rule |
| `POST /containers/{id}/stop` | `pkg/host/docker/manage.go:86` | `t` is the host's existing stop grace period; no body | Needs rule |
| `DELETE /containers/{id}` | `pkg/host/docker/manage.go:117` | `force=1&v=1`; remove query inspector | Needs rule plus `request_body.container_remove.allow_force` and `allow_remove_volumes` for RemoveByID/rebuild |
| `POST /containers/{id}/exec` | `pkg/host/docker/exec.go:81`, lifecycle adapter `lifecycle.go` | Cmd, User, Env, Privileged; exec-create inspector | Needs rule, commands and root-user grant where required; default empty command allowlist denies |
| `POST /exec/{id}/start` | `pkg/host/docker/exec.go:95` (`ContainerExecAttach`) | HTTP hijack; Detach, Tty, ConsoleSize; inspector re-reads stored exec metadata | Needs rule, same exec policy and wired upstream inspect callback; keep hijacked streams working |
| `GET /exec/{id}/json` | `pkg/host/docker/exec.go:144` | No body; exit code | Needs rule |
| `POST /grpc` | `pkg/buildkit/connect.go:100` (`DialHijack`) | `Connection: Upgrade`, `Upgrade: h2c`; terminated HTTP/2 gRPC mediator | Needs HTTP rule and configured `request_body.buildkit`; build still denied as described below |
| `POST /session` | `pkg/buildkit/connect.go:103` | Upgrade with session metadata; reverse-direction callbacks, mediated file/auth traffic | Needs HTTP rule, correlated session and enabled service switches; does not admit LLBBridge |
| `POST /images/{name}/push` | `pkg/buildkit/export.go:221` | Registry auth and destination; daemon-side artifact exfiltration | Optional, deny in minimum policy; enabling rule also needs global `insecure_allow_read_exfiltration` startup acknowledgment |
| `GET /images/get?names=...` | `pkg/buildkit/export.go:238` (`ImageSave`); SDK `client/image_save.go:40` | Image archive download | Optional, deny in minimum policy; enabling needs read-exfiltration acknowledgment |
| `GET /images/{name}/get` | No caller found in DCB production `pkg/`, `internal/`, `cmd/` or the used SDK ImageSave implementation | Alternate single-image archive endpoint | Not used by audited paths; keep denied |
| `POST /images/load` | `pkg/buildkit/export.go:171` (`engineLoad.run`) | Docker/OCI archive; `image_load.go` parses tag/registry metadata and bounds archive inspection | Optional, deny in minimum policy; external worker load needs rule and `request_body.image_load` tag/registry grants |

Menagerie's design uses DCB as a library. `Host.Up` accepts an image; it does not
itself build one. The embedder must build/tag/load before calling Up when a
derived image is needed. DCB CLI `pkg/cli/host.go:106` illustrates this sequence;
it is evidence of library orchestration, not an instruction to spawn that CLI.
Rebuild needs RemoveByID followed by the build/Up path. Command containers for
hooks and initialize commands use the same create/exec/remove surface.

No calls to Engine `POST /build`, container archive, attach, logs, wait,
container restart, networks or volume-create appear in `pkg/host/docker`,
`pkg/builder`, `pkg/buildkit`, or `internal/dockerimage` production code. Named
volume mounts in a create do not imply an explicit VolumeCreate request. SDK
transport upgrades used for exec and BuildKit must not be replaced with ordinary
buffered HTTP requests. The library's `Host.Client()` allows arbitrary embedder
calls; those are outside this inventory and remain default-denied.

## Push, save and load conditions

These are supported library features, not mandatory steps for the daemon's
normal image export:

- `exportsFor` (`pkg/buildkit/export.go:40`) uses exporter `moby` for the host
  daemon with `Load=true`: the result enters the daemon image store directly;
  there is no Engine `/images/load` request.
- `Push=true` on the daemon schedules Engine `ImagePush` after the solve.
  `specifiedExport` (`pkg/buildkit/output.go:97`) also maps registry output or
  image output with `push=true` to this path. A separate worker pushes directly
  to the registry, outside Sockguard's host Engine traffic.
- `Load=true` with `LoadWriter` on the daemon schedules `saveTags` and SDK
  `ImageSave`. `--output type=docker,dest=...` on the daemon also saves through
  Engine. The SDK requests **`/images/get`**, not `/images/{name}/get`.
- `Load=true` on a separate worker, without `LoadWriter`, streams a Docker
  archive to `ImageLoad`. `Output=type=docker` without a destination on a
  separate worker also loads; a destination instead writes the archive there.
- A cache-only build has no exporter and cannot supply a new runnable image.

Thus the minimum proposed host-daemon policy omits push/save/load. This is a
recommendation, not a finding that DCB lacks these capabilities. Menagerie's
actual library option selection and deployed configuration need acceptance
validation after the build-path decision.

## BuildKit methods and wire payloads

DCB `Builder.runBuildKit` (`pkg/builder/builder.go:326,366`) calls
`SolveDevcontainer` (`pkg/buildkit/gateway.go:53,81`). BuildKit
`client/build.go:17,30,68` first calls Control/ListWorkers, then creates an
LLBBridge client on **the same control gRPC connection** (`c.conn`). It does not
put this gateway on the reverse session connection. `grpcclient.New`
(`frontend/gateway/grpcclient/client.go:45,49`) sends LLBBridge/Ping before the
build callback can execute.

| Tunnel / service | Methods reached or offered by these paths | Sockguard treatment |
| --- | --- | --- |
| `/grpc`, `moby.buildkit.v1.Control` | ListWorkers for Build; Solve and Status for all solves; Info when SDK Wait is explicitly used (not called by audited DCB solve path) | Known, mediated; each has its own policy switch. Worker/info replies are filtered |
| `/grpc`, `moby.buildkit.v1.frontend.LLBBridge` | Ping; ResolveImageConfig for base metadata; ResolveSourceMeta during LLB source resolution when used; Solve for upstream Dockerfile and authored graph; Return for result/error | All denied, independent of HTTP rule or policy switches |
| `/session`, `moby.filesync.v1.FileSync` | DiffCopy for local contexts; SDK also advertises TarStream | DiffCopy mediated if enabled; TarStream denied and stripped from advertisement |
| `/session`, `moby.filesync.v1.Auth` | Credentials, FetchToken, GetTokenAuthority, VerifyTokenAuthority advertised by `pkg/buildkit/auth.go`; daemon selects calls for registry auth | Mediated; enable auth and registry/realm/scope constraints |
| `/session`, `moby.filesync.v1.FileSend` | DiffCopy when local/archive exporter output is requested | Optional, mediated if enabled; not needed for daemon moby export |
| health service | SDK session registers health; Sockguard registers health Check/Watch on the `/grpc` side | Session health is not a separately admitted session service; advertisement is narrowed. No live daemon-health compatibility claim is made here |

DCB does not attach BuildKit Secrets or SSH providers in `runSolve`; it attaches
registry auth and the SDK adds configured filesystem providers. No new
Control/Prune, DiskUsage or build-history RPC is needed by the audited path.
Unknown services/methods fail closed. Source-level method lists describe possible
calls, not a packet capture of every branch taken by a particular build.

### Why an HTTP rule cannot admit the gateway

Sockguard `app/internal/buildkitproxy/registry.go:170` returns Deny for any
unregistered `(endpoint, service, method)` triple. The registry has no LLBBridge
entry for **either** EndpointGRPC or EndpointSession; the explicit denied
examples at `registry.go:214` document the session side but are not the registry.
`policy.go:101` (`Allowed`) also has no LLBBridge branch under either endpoint.
`bridge.go:226` classifies before forwarding and its default branch returns
gRPC PermissionDenied (`buildkit_method_denied`); no operator setting overrides
that branch. HTTP rules only admit the outer upgrade. Literal gRPC HTTP paths
also cannot substitute for it (`app/internal/filter/buildkit.go:92`).

`TestForkEndpointsBuilderGatewayDenied` proves both classifications and policy
denials with supported Control/session switches enabled, using the unmodified
epic-base implementation. `TestForkEndpointsCandidatePolicy` proves only the
outer HTTP admission. No production guard is added or weakened.

### What the gateway carries and what inspection would require

The normal DCB build uses a **client-side gateway build function**, not
Control/Solve with `Frontend="gateway.v0"`. BuildKit `client/build.go:26` clears
the outer Frontend to `""`. In `client/solve.go:269`, the outer Control/Solve
carries Ref, Session, export/cache options, Entitlements (from
`SolveOpt.AllowedEntitlements`), FrontendAttrs and any outer Definition. DCB
`pkg/buildkit/client.go:182` does not set AllowedEntitlements; these entitlements
are empty. The outer Definition is nil for client.Build. The useful operations
arrive later over LLBBridge:

- For a Dockerfile base, `pkg/buildkit/dockerfile.go:122` sends
  LLBBridge/Solve with `Frontend="dockerfile.v0"` and `FrontendOpt` containing
  filename, platform, build arguments, target and image-resolution options.
- For the final devcontainer image, `pkg/buildkit/gateway.go:252` sends
  LLBBridge/Solve with the marshaled `pb.Definition` and `Evaluate=true`.
  Feature installs and server staging become LLB file/exec/source operations.
  It has no Dockerfile frontend on that inner solve.
- Ping negotiates capabilities; image/source resolution carries references,
  platforms and source options; Return carries image config metadata and result
  references or an error. SDK may use further reference operations as its graph
  resolves; a new allowlist must derive these from real wire tests rather than
  allow the entire service.

The BuildKit gateway proto `frontend/gateway/pb/gateway.proto:150` has
Definition, Frontend, FrontendOpt, frontend inputs, cache imports and source
policies in its SolveRequest, **no Entitlements field**. Inspection must bind
these calls to the admitted outer Control/Solve's entitlements, session and
build reference. It must decode nested `pb.Op` values and validate ExecOp
network/security modes, mounts, source identifiers and nested definitions.
A local source names a session context; it is not proof of a host directory.
FileSync sees client-sent bytes and paths relative to that context; it cannot
prove the client's original absolute directory was inside the workspace root.
That needs trusted context construction or a separate authority, in addition
to path-traversal and symlink checks on streamed entries.

The fork already inspects Control/Solve, file sync, auth and selected other
streams. It does not vendor/inspect LLBBridge payloads. Outer Solve inspection
alone cannot cover these inner operations.

### Independent exporter incompatibility

BuildKit SDK `client/solve.go:258-275` sends both modern Exporters and the first
exporter's deprecated fields. Sockguard `solve.go:428` rejects nonempty
ExporterDeprecated/ExporterAttrsDeprecated with FailedPrecondition and
`buildkit_schema_unsupported`. `TestForkEndpointsBuilderExporterWireShape`
reconstructs the daemon moby-export shape and proves that denial, with the
same request's modern-only form as an admitted control. This affects even
`SolveDockerfile` with an exporter; bypassing LLBBridge alone is insufficient.

### Entitlements

Menagerie must keep daemon BuildKit `security.insecure` and `network.host`
entitlements disabled. Keep proxy `request_body.build.allow_host_network`
false too. Sockguard always rejects `security.insecure`; network.host is
conditional on that proxy flag (`solve.go:298`). DCB does not request either
through its current SolveOptions. Container exception approval must not enable
BuildKit host-network or insecure entitlements. A daemon configuration check
and a live rejection probe remain acceptance work; this report does not claim
to have read or changed the daemon configuration.

## Build-path options

These options require orchestrator/architect disposition. None is implemented
or approved by this report.

1. **Inspect a narrow LLBBridge subset in the fork.** Highest implementation
   and security-review cost; largest fork blast radius: new vendored messages,
   method registry, payload mediation, reference/session ownership, capability
   rewriting and operation/source validation. Must inspect outer entitlements,
   inner frontend/attrs and nested LLB ops before forwarding, prohibit host
   networking and insecure execution, and establish trusted context authority.
   Also resolve exporter wire compatibility. It can reduce the documented risk
   if complete, but a method allow without that work leaves it open. Maintaining
   this protocol against SDK/daemon changes increases fork divergence.
2. **DCB classic `POST /build` backend when selected for this proxy.** Medium
   builder implementation cost: reuse generated Dockerfile/context, implement
   Engine ImageBuild archive streaming, progress, auth, tags and cancellation;
   document unsupported BuildKit-only features rather than silently downgrade.
   Small fork blast radius (rules/body configuration, no new gRPC service).
   Prefer explicit caller backend selection to inferring safety from a proxy
   address. Sockguard inspects the Dockerfile/archive/query through
   `app/internal/filter/build.go`. Keep daemon entitlements disabled and use the
   classic builder mode if opaque BuildKit/session behavior would otherwise
   return. This reduces the uninspectable-tunnel risk for that path. It needs
   Docker-version compatibility and feature-parity tests; it is not a switch
   already exposed by DCB.
3. **Separate unprivileged/rootless BuildKit; registry pull or inspected load
   to the host.** Medium deployment cost, small DCB API blast radius:
   `SolveOptions.Address` already selects a separate worker. Add service
   lifecycle/isolation, registry credentials/storage and image handoff.
   Rootless is not by itself proof of isolation: give the worker neither host
   Docker/proxy sockets, host namespaces nor sensitive bind mounts. Registry
   push from that worker then an allowlisted host pull keeps host push/save/load
   denied. Loading instead needs `/images/load` plus tag/registry archive
   inspection; that does not inspect the image's build history or make it safe
   to run privileged. No fork LLBBridge change is needed. This removes this
   build tunnel from the rootful host boundary, reducing the cited host-root
   risk, while moving build-context/credential trust to the worker boundary.
4. **DCB generated Dockerfile through plain Control/Solve.** Medium builder
   change, small-to-medium compatibility change: use `SolveDockerfile` for the
   full generated devcontainer Dockerfile instead of the gateway graph and
   normalize the SDK's duplicate exporter wire fields in a narrowly tested
   client adaptation or reviewed proxy compatibility path. Keep the built-in
   dockerfile.v0 frontend, inspect contexts through FileSync, strip external
   syntax frontends (`OmitSyntaxDirective`), and test feature contexts, cache,
   multi-platform and metadata parity. No LLBBridge admission is needed. It
   uses existing mediation but retains host-daemon BuildKit execution and its
   residual frontend/context risks; it is not proven compatible by this audit.

**Recommendation:** use a separate isolated rootless worker and registry-pull
handoff if the deployment can host it. It preserves the existing builder's
LLB graph and keeps new gateway inspection out of the small security fork.
If the host-daemon requirement is fixed, validate the generated-Dockerfile
Control/Solve route first, including exporter compatibility, before adding a
classic backend. Do not enable opaque tunneling to get a green build.

## Compose path

The Menagerie design does not explicitly select or exclude Compose, and no
Menagerie Go caller exists in the audited tree. **Menagerie Compose use is
unconfirmed**; treating it as unused is an assumption requiring disposition.
The single-container candidate policy is insufficient for Compose.

DCB Compose has additional Engine calls: `pkg/host/dockercompose/network.go:49,59`
creates/lists networks; `volume.go:35,50` creates/lists volumes;
`object_state.go:46,60,79,113` persists state in volume metadata and lists/removes
those records; `manage.go:266,278` removes networks/volumes; `watch.go:218` can
restart a container. The up/manage/exec files also use container endpoints
listed above. Compose build still reaches the shared builder. If selected,
inventory the intended watch/recovery/service lifecycle and configure inspected
network/volume rules; do not add broad `/networks/**` or `/volumes/**` grants to
this minimum policy on the strength of single-container tests.

## Menagerie must avoid

- Treating HTTP `/grpc` and `/session` admission as proof builds work or are
  constrained; treating the unsupported client gateway as `gateway.v0` is also
  inaccurate.
- `insecure_accept_opaque_buildkit_tunnels`, broad wildcard write rules or
  blind-write acknowledgment as a build compatibility fix.
- Enabling host BuildKit `security.insecure` or `network.host`, including when
  a workspace has a privileged-container exception.
- Push/save/archive exports or external-worker load without an explicit image
  handoff decision and corresponding allow rules/inspection. Do not enable
  global read-exfiltration acknowledgment for operations Menagerie does not need.
- Assuming arbitrary lifecycle argv fit the test's one `/bin/sh -c` command
  template. DCB supports argv arrays and variable argument counts; enumerate
  approved invocation shapes, root-user needs and env policy. Broadly allowing
  a shell permits arbitrary commands inside the target container and must be
  assessed with container capabilities and mounts.
- Assuming a local BuildKit context name authenticates its original host path.
- Enabling Compose templates without a Compose contract and tests.
- Exposing the proxy/host Docker/SSH-agent sockets inside workspaces or hook
  containers, or treating caller-supplied labels/list filters as isolation.

## Verification scope

`TestForkEndpointsCandidatePolicy` asserts HTTP status and whether the downstream
handler ran for the candidate routes, version normalization, slash-bearing image
names, optional exports and negative create/pull cases. It uses a stored-exec
lookup stub and does not test a real hijack, daemon ownership or exceptions.
`TestForkEndpointsBuilderGatewayDenied` pins the gateway/unknown-method denial
on both tunnels. `TestForkEndpointsBuilderExporterWireShape` pins the SDK wire
incompatibility with an isolated positive control. Existing mediation and body
suites supply deeper protocol tests. These tests add no production guard, so
no new guard mutation battery applies.

A successful build/up/stop/rebuild through the selected deployed policy,
registry/auth behavior, daemon entitlements, Compose disposition and the
workspace exception/bind contract remain epic acceptance evidence.
