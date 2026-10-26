---
relationships:
  references:
    - ../app/internal/buildkitproxy/registry.go
    - ../app/internal/buildkitproxy/solve.go
    - ../app/internal/ownership/middleware.go
    - ../app/internal/filter/fork_endpoints_policy_test.go
    - ../app/internal/filter/fork_endpoints_compose_test.go
    - ../app/internal/ownership/fork_endpoints_compose_test.go
    - ../app/internal/buildkitproxy/fork_endpoints_builder_test.go
---

# Menagerie Engine endpoint compatibility

## Finding and evidence boundary

Container start, stop, inspect, remove and exec can use narrow HTTP rules with
explicit body settings. Compose bring-up, stop and teardown work through narrow
network and volume rules. A real Compose project was driven through a local
Sockguard build with those rules.

Three results limit that:

- **The devcontainer build does not work through Sockguard's mediated BuildKit
  connection at this base.** It needs LLBBridge, which is denied on both
  tunnels. The builder SDK's legacy exporter fields are a second, independent
  incompatibility. Adding HTTP rules cannot fix either. The build-path decision
  below addresses both.
- **With ownership enabled, every devcontainer-builder container lookup
  matches the wrong containers.** Ownership replaces the client's `label`
  list filters with the owner label. devcontainer-builder finds a workspace's
  containers only by those filters and does not check the labels of the
  result. A measured Compose `Up` through an ownership-enabled proxy stopped and
  removed the primary container in place of a sidecar. See
  [Ownership and label lookups](#ownership-and-label-lookups).
- **Default mount-path redaction hides the object roots Compose tracks.**
  See [Compose inventory](#compose-inventory).

This is a source audit, a set of local policy tests and one local Compose run.
It is not a successful build through a deployed Menagerie policy. The rule sets
in the tests are candidate minimums, not an approved deployment configuration.
The research does not change proxy code or the Menagerie design.

Evidence inputs:

- Sockguard base: `e34354de79023070a29fa5d23f65d42e4ca76eff`.
- devcontainer-builder (DCB): tag `0.2.0`
  (`c432d28f97ce18f07f8e032187ab7c211e8a6595`), the version Menagerie pins in
  `go.mod`. Paths below are relative to that tree.
- Menagerie `main`: `d28e490f2f6f8c208923632f8d31d8aa0bb78e86`,
  `/workspaces/tools/menagerie`; caller `backend/internal/devcontainer/runtime.go`;
  risk `docs/risks/buildkit-traffic-not-inspectable.yml`.
- DCB `go.mod`: Docker SDK `v28.5.2+incompatible`, BuildKit `v0.18.2`. SDK paths
  below are relative to those versions in `/go/pkg/mod`.
- Docker Engine 29.9.2 (API 1.56) for the measured Compose run.

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
| `HEAD /_ping`, fallback `GET /_ping` | SDK version negotiation; `pkg/buildkit/connect.go:57`, caller-supplied Docker client for host operations; SDK `client/ping.go` | No body; negotiation reads API headers | Needs both rules for SDK negotiation and fallback |
| `GET /info` | `internal/dockerimage/image.go:83` (image not local and no platform given), `pkg/host/gpu/availability.go:35` (`hostRequirements.gpu` with detect mode) | No body; reads OS, architecture and runtimes | Conditional; needs rule when either branch runs. Response redaction applies |
| `GET /containers/json` | `pkg/host/docker/spawn.go:90` (`findLabeled`), used by up, inspect, stop and remove | `all=1`, label filters | Needs rule; ownership drops the label filters (see below) |
| `GET /containers/{id}/json` | `pkg/host/docker/up.go:161,230,263`, `manage.go:42` | No body | Needs rule; discovers mount, user, environment and state data |
| `GET /images/{name}/json` | `pkg/host/docker/image.go:18`, `up.go:193,363`, `pkg/builder/metadata.go:79`, `internal/dockerimage/image.go:73,109` | No body; inspect path must allow slash-bearing names | Needs rule; `GET /images/**/json` covers registry/repository names |
| `POST /images/create` | `internal/dockerimage/image.go:34`, called by host image ensure and builder metadata resolution | `fromImage`, `tag`, `X-Registry-Auth`; image-pull inspector | Needs rule and approved registry allowlist; no import grant needed |
| `POST /containers/create` | `pkg/host/docker/up.go:371` | Config, HostConfig, mounts, labels, user, env; create inspector | Needs rule and workspace bind grants; exception-sensitive fields remain denied without an exception. This audit does not prove the complete HostConfig contract |
| `POST /containers/{id}/start` | `pkg/host/docker/up.go:257` | SDK sends no body | Needs rule |
| `POST /containers/{id}/stop` | `pkg/host/docker/manage.go:86` | `t` is the host's existing stop grace period; no body | Needs rule |
| `DELETE /containers/{id}` | `pkg/host/docker/manage.go:117` | `force=1&v=1`; remove query inspector | Needs rule plus `request_body.container_remove.allow_force` and `allow_remove_volumes` for RemoveByID/rebuild |
| `POST /containers/{id}/exec` | `pkg/host/docker/exec.go:81`, lifecycle adapter `lifecycle.go` | Cmd, User, Env, Privileged; exec-create inspector | Needs rule and an exec setting. At this base only argv templates exist and an empty list denies. Menagerie uses the `allow_any_command` exec setting with `allow_root_user`, `allow_privileged=false` and owner-label isolation |
| `POST /exec/{id}/start` | `pkg/host/docker/exec.go:95` (`ContainerExecAttach`) | HTTP hijack; Detach, Tty, ConsoleSize; inspector re-reads stored exec metadata | Needs rule, the same exec setting and wired upstream inspect callback; keep hijacked streams working |
| `GET /exec/{id}/json` | `pkg/host/docker/exec.go:144` | No body; exit code | Needs rule |
| `POST /grpc` | `pkg/buildkit/connect.go:92` (`DialHijack`) | `Connection: Upgrade`, `Upgrade: h2c`; terminated HTTP/2 gRPC mediator | Needs HTTP rule and configured `request_body.buildkit`; build needs the LLBBridge passthrough described below |
| `POST /session` | `pkg/buildkit/connect.go:95` | Upgrade with session metadata; reverse-direction callbacks, mediated file/auth traffic | Needs HTTP rule, correlated session and enabled service switches; does not admit LLBBridge |
| `POST /images/{name}/push` | `pkg/buildkit/export.go:221` | Registry auth and destination; daemon-side artifact exfiltration | Optional; stays denied for Menagerie. Enabling it would also need the global `insecure_allow_read_exfiltration` startup acknowledgment |
| `GET /images/get?names=...` | `pkg/buildkit/export.go:238` (`ImageSave`); SDK `client/image_save.go:40` | Image archive download | Optional; stays denied for Menagerie. Enabling it would need the read-exfiltration acknowledgment |
| `GET /images/{name}/get` | No caller found in DCB production `pkg/`, `internal/`, `cmd/` or the used SDK ImageSave implementation | Alternate single-image archive endpoint | Not used by audited paths; keep denied |
| `POST /images/load` | `pkg/buildkit/export.go:171` (`engineLoad.run`) | Docker/OCI archive; `image_load.go` parses tag/registry metadata and bounds archive inspection | Optional; stays denied for Menagerie. External worker load would need a rule and `request_body.image_load` tag/registry grants |

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

Menagerie's builder options (`runtime.go:334`) set `Load=true` with no
`LoadWriter`, no `Push` and no `Output`, against the host daemon. That selects
the moby exporter with no Engine push, save or load. Push, save and load stay
denied for Menagerie.

## BuildKit methods and wire payloads

DCB `Builder.runBuildKit` (`pkg/builder/builder.go:326,351`) calls
`SolveDevcontainer` (`pkg/buildkit/gateway.go:53,78`). BuildKit
`client/build.go:17,30,68` first calls Control/ListWorkers, then creates an
LLBBridge client on **the same control gRPC connection** (`c.conn`). It does not
put this gateway on the reverse session connection. `grpcclient.New`
(`frontend/gateway/grpcclient/client.go:45,49`) sends LLBBridge/Ping before the
build callback can execute.

| Tunnel / service | Methods reached or offered by these paths | Sockguard treatment at this base |
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
`pkg/buildkit/client.go:180` does not set AllowedEntitlements; these entitlements
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
  resolves.

The BuildKit gateway proto `frontend/gateway/pb/gateway.proto:150` has
Definition, Frontend, FrontendOpt, frontend inputs, cache imports and source
policies in its SolveRequest, **no Entitlements field**. Inspection would have
to bind these calls to the admitted outer Control/Solve's entitlements, session
and build reference. It would have to decode nested `pb.Op` values and validate
ExecOp network/security modes, mounts, source identifiers and nested
definitions. A local source names a session context; it is not proof of a host
directory. FileSync sees client-sent bytes and paths relative to that context;
it cannot prove the client's original absolute directory was inside the
workspace root.

The fork inspects Control/Solve, file sync, auth and selected other streams. It
does not vendor or inspect LLBBridge payloads. Outer Solve inspection alone
cannot cover these inner operations.

### Independent exporter incompatibility

BuildKit SDK `client/solve.go:258-275` sends both modern Exporters and the first
exporter's deprecated fields. Sockguard `solve.go:428` rejects nonempty
ExporterDeprecated/ExporterAttrsDeprecated with FailedPrecondition and
`buildkit_schema_unsupported`. `TestForkEndpointsBuilderExporterWireShape`
reconstructs the daemon moby-export shape and proves that denial, with the
same request's modern-only form as an admitted control. This affects every
`SolveDockerfile` with an exporter, including Compose service builds;
bypassing LLBBridge alone is insufficient.

### Entitlements

Menagerie must keep daemon BuildKit `security.insecure` and `network.host`
entitlements disabled. Keep proxy `request_body.build.allow_host_network`
false too. Sockguard always rejects `security.insecure`; network.host is
conditional on that proxy flag (`solve.go:298`). DCB does not request either
through its current SolveOptions. Container exception approval must not enable
BuildKit host-network or insecure entitlements. A daemon configuration check
and a live rejection probe remain acceptance work; this report does not claim
to have read or changed the daemon configuration.

## Build-path decision

The fork adds two changes:

1. **An opt-in LLBBridge passthrough on `/grpc`.** A new setting, default off
   and set per client profile, forwards LLBBridge methods on the control
   connection without inner inspection. Every outer Control/Solve check stays:
   `security.insecure` is always denied and host networking is denied.
2. **A narrow exporter compatibility fix.** Control/Solve accepts the
   deprecated exporter fields only when they equal `Exporters[0]`, and rejects
   them otherwise.

DCB stays at `0.2.0`; the build uses its normal client gateway graph.

Residual risk (`buildkit-traffic-not-inspectable`, recorded by Menagerie): a
client profile with the passthrough enabled can send any LLB graph to the
host daemon's BuildKit. The proxy sees the outer solve but not the inner
operations, sources, mounts or nested definitions listed in
[What the gateway carries](#what-the-gateway-carries-and-what-inspection-would-require).
The outer entitlement checks bound what that graph can request from the
daemon; they do not inspect it. Enable the passthrough only on the Menagerie
profile.

`TestForkEndpointsBuilderGatewayDenied` and
`TestForkEndpointsBuilderExporterWireShape` pin the denials at this base. The
LLBBridge passthrough and exporter-compatibility task (#1814) updates them when
it merges.

## Compose inventory

Compose is in scope for Menagerie. Menagerie calls three DCB Compose entry
points (`backend/internal/devcontainer/runtime.go`):
`dockercompose.BuildPrimaryImage` (`:244`), `Host.Up` (`:265`) and `Host.Stop`
(`:290`). Rebuild removes the primary through the single-container
`RemoveByID` (`:312`); the next `Up` recreates sidecars whose config hash
changed. Menagerie does not call `Host.Remove`, `RemoveRuntime`, `Watch` or
`Exec` directly.

Evidence column:

- **Measured**: driven through a local Sockguard build on a private socket,
  against Docker 29.9.2, with a DCB `0.2.0` program calling `Up`, `Stop`, `Up`
  and `Remove` on a test-owned two-service project (busybox primary, alpine
  sidecar, one network, one named volume, one file config). Access log
  decision and status were read per request. The candidate rule set is
  `fork_endpoints_compose_test.go`'s narrow rows plus the exec rows.
- **Inferred**: from reading the DCB `0.2.0` code; the branch did not run in
  the measured project.

All paths are relative to `pkg/host/dockercompose/` unless stated.

| Method and path | Caller (`file:line`) | Inspected input | Candidate result | Evidence |
| --- | --- | --- | --- | --- |
| `GET /networks` | `network.go:59` (`findNetwork`, from `ensureNetworks` in Up); `manage.go:261` (Remove) | `filters={"name":...}` | Needs rule `GET /networks`. Ownership adds the owner label filter | Measured |
| `POST /networks/create` | `network.go:49` (`ensureNetworks`) | Driver, Internal, Attachable, Labels, Options (`driver_opts`), EnableIPv4/IPv6; network inspector. No IPAM sent | Needs rule. Default inspector denies Attachable, driver options, custom (plugin) drivers, swarm scope, ingress, config-only/from, IPAM config. `bridge`, `host`, `ipvlan`, `macvlan`, `overlay` drivers are built-in and admitted | Measured (default driver); denials pinned by test |
| `DELETE /networks/{id}` | `manage.go:266` (`removeProject`, from `Remove`) | No body | Needs rule only for teardown. Menagerie does not call `Remove` | Measured |
| `GET /volumes` | `volume.go:50` (`findVolume`); `object_state.go:60` (`objectRecords`, from Up and Remove); `manage.go:270` (Remove) | Name filter, or label filters `devcontainer.compose.objects` + `devcontainer.local_folder=<workspace>` | Needs rule `GET /volumes`. Ownership drops the label filters (see below) | Measured |
| `POST /volumes/create` | `volume.go:35` (`ensureVolumes`); `object_state.go:46` (`publishObjectOwnership`, first config/secret materialization in Up) | Name, Driver, DriverOpts, Labels; volume inspector | Needs rule. Default inspector denies custom drivers and any DriverOpts (including local bind devices) | Measured; bind-device denial pinned by test |
| `DELETE /volumes/{name}?force=1` | `object_state.go:79` (`removeObjectRecords`, from Up's `removeRetiredObjects` at `up.go:347` and from Remove); `manage.go:278` (Remove) | No body | Needs rule `DELETE /volumes/*`: **Up** can call it, not only teardown | Measured (Remove); Up branch inferred |
| `GET /containers/json` | `existing.go:22` (`FindExisting`, per service in Up); `manage.go:93,310,347` (primary and project lookup, Stop, Remove); `object_state.go:113` (unfiltered, `removeRetiredObjects`) | `all=1`, label filters on project, service, local folder, primary | Same rule as single container. Ownership drops the label filters. Default redaction replaces `Mounts[].Source` | Measured |
| `GET /containers/{id}/json` | `up.go:413,437,505`, `wait.go:72` (`depends_on` conditions), `manage.go:118` | No body | Same rule as single container | Measured |
| `GET /images/{name}/json` | `entrypoint.go:45`, `up.go:225` (`dockerimage.InspectConfig`); `up.go:398` (`dockerimage.Ensure`) | No body | Same rule as single container | Measured |
| `GET /info` | `internal/dockerimage/image.go:83` via `InspectConfig`; `gpu.go:26` via `gpu.Requested` | No body | Conditional; needs rule when an image is not local and has no platform, or when `hostRequirements.gpu` is set with detect mode | Inferred |
| `POST /images/create` | `up.go:398` (`Ensure` for image-only services and the primary), `InspectConfig` registry fallback | `fromImage`, `X-Registry-Auth`; image-pull inspector | Same rule and registry allowlist as single container; every service image needs an allowlisted registry | Inferred (images were local) |
| `POST /containers/create` | `up.go:402` (`bringUp`, once per service; translation in `spawn.go:41`) | Config, HostConfig (binds, mounts, network/IPC/PID mode, caps, security options, ports, `extra_hosts`, `group_add`, sysctls, tmpfs, device requests, restart policy), NetworkingConfig (aliases, static addresses, MAC); create inspector | Same rule and inspector as single container; see the field notes below | Measured (primary and sidecar); field denials pinned by test |
| `POST /containers/{id}/start` | `up.go:419` | No body | Same rule as single container | Measured |
| `POST /containers/{id}/stop` | `manage.go:167` (Stop), `up.go:451` (recreate on config-hash change) | `t` | Same rule as single container | Measured |
| `DELETE /containers/{id}` | `up.go:456` (recreate, `force=1`); `manage.go:248` (Remove) | `force`, `v` query | Same rule and `allow_force` as single container | Measured |
| `POST /containers/{id}/exec`, `POST /exec/{id}/start`, `GET /exec/{id}/json` | `exec.go:65,79,125` (`Host.Exec`), via `Execer` at `up.go:530`: `DetectHome`, `DetectContainerEnv` (`/bin/sh -c "cat /proc/1/environ"`), `PatchSystemEnv` (`/bin/sh -c <script>` as root, with stdin), user-env probe (`<login shell> -lic|-lc|-ic|-c ...`), lifecycle commands | Same as the single-container exec rows | Same exec setting as single container. Every Compose `Up` execs in the primary, including as root | Measured (10 exec sequences over two Ups, with wildcard argv templates as a stand-in for `allow_any_command`); denied without exec rules |
| `POST /grpc`, `POST /session` | `composebuild.go:113` (`SolveDockerfile` per service with `build:`); `build.go:159` (`builder.Build` for a derived primary) | Control/Solve with `dockerfile.v0` and moby export (`Load=true`, no `LoadWriter`); derived primary uses LLBBridge | Service builds need only the exporter fix; a derived primary also needs the LLBBridge passthrough | Inferred (measured project had no builds) |
| `POST /containers/{id}/restart` | `watch.go:218` (`Watch` restart actions) | `t` | Denied; no rule. Menagerie does not call `Watch` | Inferred; denial pinned by test |
| `PUT /containers/{id}/archive` | `watch.go:260` (`Watch` sync actions) | Tar archive | Denied; no rule. Menagerie does not call `Watch` | Inferred; denial pinned by test |

Sweep: every method call on the package's Docker client
(`h.client`, `s.host.client`, `cli`) in non-test files of
`pkg/host/dockercompose` at `0.2.0`, plus each helper that receives the client
(`dockerimage.InspectConfig`, `dockerimage.Ensure`, `gpu.Requested`,
`FindExisting`, `BuildServiceImages`, `builder.Build`).

### Container create field notes

`translateService` (`spawn.go:41`) passes Compose service fields straight into
the create body. The create inspector applies to each service as it does to the
single-container create:

- `extra_hosts` and `group_add` set `ExtraHosts` and `GroupAdd`, which the
  inspector always denies. Compose templates for Menagerie must not use them.
- `networks.<name>.ipv4_address`, `ipv6_address` and `mac_address` set
  endpoint static addressing and MAC pinning, denied by default. Aliases are
  admitted.
- `privileged`, `cap_add`, `security_opt`, `network_mode: host`, `pid`, `ipc`,
  `sysctls` and device requests go through the same gates and exceptions as
  the primary.
- `restart:` sets `HostConfig.RestartPolicy`. The fork's restart-policy rule
  (base denial, per-workspace grant) applies to every service.
- Configs and secrets become read-only bind `Mounts` under the object root
  (`UserDataFolder`, default `$TMPDIR/dcb-compose`, `object_state.go:25`). The
  object root must be inside `allowed_bind_mounts` and must be a path the
  daemon host and Menagerie both see. Menagerie does not set `UserDataFolder`.
- Only the primary carries `devcontainer.local_folder` (`labels.go:39`). A
  sidecar has it only when the Compose file sets it under `labels:`
  (`up.go:308` merges service labels that DCB does not manage). Sidecars
  therefore get no workspace exceptions unless the template labels them and
  the bind sources agree with that workspace.

### Ownership and label lookups

With `ownership.owner` set, `addOwnerLabelFilter`
(`app/internal/ownership/middleware.go:1175`) replaces every client value under
the `label` list filter with the owner label (plus any visibility selectors).
Upstream drops the client values on purpose and pins it with
`TestListLabelFilterKeepsVisibilityScopeWhileDroppingClientValues`: Swarm
control-plane lists fold `label` into a map, so a client value that repeats the
owner key could displace the owner selector.

DCB finds containers and object records only through those label filters and
takes the first result without checking its labels:

- Compose `FindExisting` (`existing.go:22`), `findPrimary` (`manage.go:93`),
  project lookups (`manage.go:310,347`) and `objectRecords`
  (`object_state.go:60`).
- Single-container `findLabeled` (`pkg/host/docker/spawn.go:85`), which backs
  `Up`'s reuse lookup, `Inspect`, `Stop` and `RemoveByID` lookups.

Measured through an ownership-enabled proxy:

- A list for `project=<p>, service=side` returned the `app` container. The
  same filter sent directly to the daemon returned nothing.
- Compose `Up` therefore read the primary as the existing `side` container,
  found its config hash different, stopped and removed the primary, created
  `side`, then failed at "inspect primary".
- Compose `Remove` read every owned volume as an object record and stopped at
  DCB's own record-shape check ("invalid materialized object ownership
  record"), before deleting anything.

Inferred for Menagerie with one owner for all workspaces: a workspace's `Up`,
`Stop` or rebuild can select another workspace's container. Owner-label
isolation and DCB label lookup cannot both hold at this base. Resolving it
needs a ruling: for example, a fork change that keeps client `label` values
whose key is not the owner key on Engine (non-Swarm) lists, or a DCB change
that checks labels on the returned containers.
`TestForkEndpointsDCBLabelLookupsLoseClientLabels` pins the four DCB lookup
shapes as dropped.

### Mount-path redaction

Default `response.redact_mount_paths: true` replaces `Mounts[].Source` with
`<redacted>` in `GET /containers/json` (measured). Compose decides which object
roots are still mounted from that field (`object_state.go:126`,
`objectRootMounted`). With redaction, `previousObjectRecords` finds no mounted
root, so `Up` never retires an old object root or its ledger volume after a
recreate (inferred: the roots and `dcb-objects-*` volumes accumulate until
`Remove`). The Menagerie profile must either disable mount-path redaction or
accept that leak.

### Candidate Compose rules

Add to the single-container candidate:

```yaml
- { match: { method: GET,    path: "/networks" },        action: allow }
- { match: { method: POST,   path: "/networks/create" }, action: allow }
- { match: { method: GET,    path: "/volumes" },         action: allow }
- { match: { method: POST,   path: "/volumes/create" },  action: allow }
- { match: { method: DELETE, path: "/volumes/*" },       action: allow }
# Teardown only (Host.Remove); Menagerie does not call it.
- { match: { method: DELETE, path: "/networks/*" },      action: allow }
```

Keep the network and volume inspectors at their defaults. Do not grant
`/networks/**` or `/volumes/**`: those also admit network connect and
disconnect, network and volume prune, and volume inspect, which DCB does not
call. `TestForkEndpointsComposeBroadGrantsWiden` pins that difference.

## Menagerie must avoid

- Treating HTTP `/grpc` and `/session` admission as proof builds work or are
  constrained; treating the client gateway as `gateway.v0` is also inaccurate.
- `insecure_accept_opaque_buildkit_tunnels`, broad wildcard write rules or
  blind-write acknowledgment as a build compatibility fix. Use the per-profile
  LLBBridge passthrough, and enable it only on the Menagerie profile.
- Enabling host BuildKit `security.insecure` or `network.host`, including when
  a workspace has a privileged-container exception.
- Push/save/archive exports or external-worker load. Do not enable global
  read-exfiltration acknowledgment for operations Menagerie does not need.
- Treating `allow_any_command` as harmless. It admits any argv, including as
  root, in every container the profile can reach. Its bound is owner-label
  isolation, `allow_privileged=false`, and the target container's
  capabilities and mounts.
- Enabling ownership without resolving the label-lookup incompatibility, or
  relying on caller-supplied labels or list filters as isolation.
- Granting `/networks/**` or `/volumes/**` for Compose.
- Compose templates that use `extra_hosts`, `group_add`, static network
  addresses, MAC addresses, network or volume driver options, plugin drivers,
  or `macvlan`/`ipvlan`/`host` network drivers.
- An object root (`UserDataFolder`) outside `allowed_bind_mounts`, or one the
  daemon host cannot see at the same path.
- Calling DCB `Watch`: its restart and archive-sync actions stay denied.
- Assuming a local BuildKit context name authenticates its original host path.
- Exposing the proxy/host Docker/SSH-agent sockets inside workspaces or hook
  containers.

## Verification scope

`TestForkEndpointsCandidatePolicy` asserts HTTP status and whether the downstream
handler ran for the single-container candidate routes, version normalization,
slash-bearing image names, optional exports and negative create/pull cases. It
uses a stored-exec lookup stub and does not test a real hijack, daemon ownership
or exceptions. `TestForkEndpointsComposeCandidatePolicy` does the same for the
Compose routes with DCB-shaped bodies, and each negative changes one field of a
valid control. `TestForkEndpointsComposeBroadGrantsWiden` compares the narrow
rows with broad grants. `TestForkEndpointsDCBLabelLookupsLoseClientLabels`
pins the ownership filter result for DCB's lookup filters.
`TestForkEndpointsBuilderGatewayDenied` pins the gateway/unknown-method denial
on both tunnels. `TestForkEndpointsBuilderExporterWireShape` pins the SDK wire
incompatibility with an isolated positive control. Existing mediation and body
suites supply deeper protocol tests. These tests add no production guard.

The measured Compose run used a local build of this branch, not a released
image, and no BuildKit build. A successful build/up/stop/rebuild through the
selected deployed policy, registry/auth behavior, daemon entitlements and the
workspace exception/bind contract remain epic acceptance evidence.
