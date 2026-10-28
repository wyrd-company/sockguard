# Menagerie profile

`candidate.yaml` is the exact proxy configuration template for automated acceptance and deployment. `workspace-exceptions.json` shows one approved primary workspace grant. Paths, UID, socket GID and registries are deployment inputs. Acceptance records every substitution and the raw and rendered hashes; a separately reconstructed configuration is not this profile.

The committed contracts are `docs/content/docs/workspace-exceptions.mdx`, `docs/content/docs/symlink-bind-sources.mdx`, `docs/content/docs/buildkit-llb-bridge.mdx` and `docs/fork-endpoints.md` in the fork.

## Identity and grants

The caller-built Docker client supplies exactly one header: `X-Sockguard-Workspace: W` for devcontainer jobs, or `X-Sockguard-Throwaway-Workspace: W` for command containers. `W` is an absolute canonical direct child of `workspace_root`. Labels and Compose project names never supply identity. Headerless create, start, restart and exec are denied. BuildKit `/grpc` and `/session` require no header.

Under the devcontainer header, `menagerie.throwaway.workspace` must be absent; `devcontainer.local_folder` may be absent or equal `W`. Under the throwaway header, the primary label must be absent; the throwaway label may be absent or equal `W`. Opposite-kind labels, both labels and mismatches are denied.

Every grant requires the devcontainer header, a present primary label equal to `W`, the matching current exception entry, an own-workspace bind and agreement of all mounted host sources. An absent label permits ordinary BASE create/start/restart and gets no grants, including `restartPolicy` and `extraBindSources`. Sidecars without the primary label and throwaways get no grants. Exec independently inspects its actual target and requires the same-kind label equal to `W`.

All workspace, socket and Compose staging roots are in `workspace_exceptions.per_workspace_roots` and `allowed_bind_mounts`. Every request is scoped to its own direct child under each root. The template cache is copied through archive; it is not a bind source or proxy mount. DCB `UserDataFolder` uses the per-workspace Compose staging child.

## Listener and peer access

The Unix listener is mode `0660`, with `socket_gid` and `allowed_profiles: [menagerie]`. The proxy retains socket ownership. UID-only `unix_peer_profiles` selects the profile. The filesystem group check is separate: a client with the socket group as a supplementary group can connect. A caller without socket filesystem access cannot connect; a caller in that group with a nonmatching UID is denied by the listener.

`SO_PEERCRED` supplies only the primary GID, but this profile has no GID matcher. The proxy container uses `group_add: [socket_gid]`. No `CHOWN` capability is added. Startup must fail and remove the socket when its chown fails.

## Proxy deployment

The proxy runs as root with `cap_drop: [ALL]` and `cap_add: [DAC_READ_SEARCH]`. The capability set contains only `DAC_READ_SEARCH`; `group_add` supplies membership of `socket_gid`. A socket-group setup failure must be reported before changing capabilities. An own-workspace `0700` subfolder remains searchable with `DAC_READ_SEARCH`.

Use a read-only root filesystem, `security_opt: [no-new-privileges:true]`, `network_mode: none`, and writable tmpfs `/tmp` for the archive spool. Mount the host Docker socket at `/var/run/docker.sock`; mount the workspace, socket and Compose staging roots read-only at the same host paths inside the proxy. Mount the exceptions directory read-only as a directory so atomic file replacement remains visible. Share `/run/sockguard` with the workspace service. Menagerie never writes the exceptions file.

The proxy must not front a Swarm manager: cluster-volume listing does not honor the local-volume owner selector. Compose networks use the `bridge` driver. The profile does not admit native libpod routes. Restart is checked by the proxy when a policy admits it; this profile's route list does not admit `POST /containers/*/restart`. Compose network deletion is also outside the route list.

## Command containers, exec and builds

Command containers use attach, wait and PUT/GET archive. The required proxy-wide `insecure_allow_read_exfiltration: true` opt-in is bounded by owner-label isolation. Image save, push and load remain denied. `container_archive.allowed_paths: ["/"]` is the explicit accepted root bound. Actual copy-in targets `path=/`; acceptance measures the consumer's request and tar entry names. Different consumer paths require measurement and a ruling before this bound changes. Entry names must be safe and relative even when target paths are absolute.

`allow_escaping_links: true` admits absolute symlink targets used by templates and candidates. A later archive entry may write through such a link within the container filesystem; acceptance measures this only with owned paths. `allow_setid: false`, `allow_device_nodes: false` and unsafe entry-name checks remain active.

Exec uses the real `allow_any_command: true` setting, with independent `allow_privileged: false`. `allow_root_user: true` is required by DCB `PatchSystemEnv`. A root-denial test must identify its separate variant setting `allow_root_user: false`; it does not describe the actual profile. Environment guards stay independent.

BuildKit permits uninspected LLBBridge passthrough for this profile. Outer solve, exporter, entitlement and session bounds still apply. The host-daemon exporter is `moby`; host networking, insecure entitlement, remote contexts, push and registry-cache export remain outside the profile. Registry values are placeholders; acceptance records exact registry/auth input substitutions without secrets.

## Acceptance evidence

Unknown configuration keys can be ignored by the proxy. Successful validation is not field-effect proof. Automated acceptance must record the exact profile hashes, substitutions, final source/image ID, runtime inputs and named positive/negative controls for each measured key. Unmeasured guards and daemon/store/BuildKit variants remain explicit gaps. `redact_container_env` retains its default enabled value and must be tested through DCB.

Ownership and response redaction are proxy-wide. Base and BuildKit images may be unowned (`allow_unowned_images: true`). Tests label their own images for resource provenance and must not remove shared base images. Startup/reload roots and current start/restart bind-device checks follow the committed contracts; residual races and daemon-driven starts remain documented there.
