---
relationships:
  references:
    - ../../docs/fork-endpoints.md
    - testdata/candidate.yaml
    - testdata/profile-input.json
---

# Real-daemon acceptance

Run from the repository root:

```sh
docker pull docker:29.9.2-dind
make acceptance
ACCEPTANCE_STORE=classic make acceptance
```

The target needs Docker, Go and a prepared bootstrap image. The local operator prepares and owns that image outside `run.sh`; the pull above is an explicit preparation command. Fork CI prepares it in job setup and owns it as ephemeral runner infrastructure, retaining `bootstrap-prepare.log` through the existing artifact upload even on preparation failure. Preparation must succeed before the protected suite begins. The wrapper never pulls or removes a shared bootstrap image and fails before compilation, the protected inventory baseline or any resource create when the prerequisite is missing.

The wrapper resolves `ACCEPTANCE_DAEMON_IMAGE` (default `docker:29.9.2-dind`) to an immutable image-config ID before admission. It records the requested value and available RepoDigests in `bootstrap-prerequisite.txt`, uses that ID with `--pull=never` for both creates, and checks each created container's `.Image` before starting it. A tag change after verification cannot select a different image. Locally built overrides remain supported:

```sh
# The operator has already built this image outside the wrapper.
ACCEPTANCE_DAEMON_IMAGE=example-fixture:local make acceptance
```

An empty or null RepoDigests value is recorded explicitly; it does not claim registry provenance. The prerequisite remains pre-existing infrastructure for the protected interval. Unknown inventory additions and removals still fail; prerequisite preparation does not authorize moving an unexplained object across the baseline or deleting it.

The target uses an owned privileged daemon, an owned runner and three owned volumes. It changes no shared daemon configuration. A separate module pins `devcontainer-builder` v0.2.0 (`c432d28f97ce18f07f8e032187ab7c211e8a6595`) and its Docker SDK; proxy dependencies are unchanged. The `sockguardacceptance` build tag and required fixture environment keep default Go tests hermetic. Running the tagged test binary without the fixture fails explicitly.

`ACCEPTANCE_STORE` selects `containerd` (default) or `classic`. The fork CI runs both. Each run records the actual daemon version, store, source commit/tree and built image ID. A passing containerd run proves that variant only. A separate BuildKit worker, native libpod and Swarm manager are outside this suite's runtime claim.

## Exact profile

`testdata/candidate.yaml` is a byte copy of the synchronized reviewed profile, with its README copied to `testdata/profile.md`. `testdata/profile-input.json` pins both hashes and enumerates all literal substitutions. The suite logs the raw template, mapping and rendered hashes and saves the rendered configuration. It retains the actual profile name and owner; workspace/scenario names and fixture inputs are generic. It never reconstructs an approximation of the profile.

Only scratch paths, caller UID, socket GID and registry placeholders are substituted. The runner, daemon and proxy share actual scratch paths at the same spelling through an owned volume; proxy roots are real read-only bind mounts. The proxy runs root with cap_drop ALL plus DAC_READ_SEARCH only, group_add socket GID, read-only root filesystem, no-new-privileges, network none and writable tmpfs /tmp. CHOWN is excluded. A separate no-group startup control proves fatal socket-chown handling.

The actual profile admits root exec for DCB PatchSystemEnv. `strict-root` changes that setting to false and proves root denial separately. The actual profile omits restart. `restart-route` and `restart-route-volume` add only that route for inspector controls, with separate hashes; baseline route denial is never counted as restart inspection. The build diagnostic variant `baseline-observe` adds only CLI `--log-level debug`; it is not final exact-baseline logging evidence. `llb-off` turns off the existing passthrough field for a negative build control.

The hermetic `TestForkAcceptanceProfileConfigEffects` reads this same fixture, rejects unknown authored keys with a test-only strict decoder and checks translated runtime fields. Its rule checks are the count and omitted restart route; it does not snapshot each rule's order independently. Raw-file hash agreement pins the copied bytes, and live calls pin the routes exercised. It complements live effects and composed field tests. It does not make the product's loader strict.

## Consumer and boundary cases

`TestAcceptance` names each scenario independently:

- `ConsumerDockerLifecycle`: original pinned DCB build/up/stop/rebuild, caller-built clients, headerless /grpc and /session, default metadata client reads only, and lifecycle environment under inspect redaction. The off control requires typed PermissionDenied at the exact LLBBridge/Ping policy boundary and an admitted headerless grpc upgrade.
- `ConsumerIdentityControls`: actual DCB privileged denial then live exception admission without proxy replacement, and forged runArgs label denial.
- `ConsumerComposeLifecycle`: primary/sidecar, bridge network, named volume, file config and inline content config, two Ups with changed sidecar config, followed by single-container, Compose-primary and whole-project lookups in both directions while both workspaces are populated, then Stop. The second Up must DELETE the exact previously owned ledger volume whose root the inspected inline-config mount consumed; the assertion bounds the request to that Up, requires force=1/status204 and confirms the volume is absent. A later teardown or unrelated volume cannot satisfy it. The file config binds its source directly; the inline config exercises private staging and the object-root ledger. These checks pin mounts, identity and retirement; config payload bytes are not read back. Sidecar labels are never repaired by the harness.
- `WorkspaceGrantReloadAndIdentity`: separate grant classes, matching-primary admission, unlabeled BASE admission, unlabeled/sidecar/throwaway grant denial, label-kind/mismatch denials, own/sibling socket scope and own 0700 access. The baseline admits seccomp=unconfined without a grant; it cannot prove grant necessity for that already-open setting. Device/runtime/GPU controls exercise create admission only and claim no GPU or alternate-runtime execution. Strict security grants and independent exec environment/outer Solve guards are pinned by `TestForkHostConfigFieldMatrix`, `TestForkFieldExecCommandAndIndependentGuards` and `TestForkFieldBuildkitProfileAndOuterSolve`; those are composed production-chain checks, separate from live effects.
- `BindSwapAtStartAndRestart` and `LocalVolumeDeviceReresolution`: unchanged mounts admit, owned directory swaps deny at proxy start, explicit restart variants test that inspector, and a separate direct-daemon marker control establishes or falsifies actual device re-resolution. An unchanged original marker records a measured limit rather than claiming re-resolution; the approved proxy recheck remains required. Driver-option volumes are created directly as owned fixtures: baseline volume-create does not admit those options.
- `ArchiveAttachWait`: actual PUT/GET copy, attach and wait; `CapturedConsumerArchive` feeds the exact tar bytes emitted by the committed application copy producer (`consumer-archive.json` records source commit/function hash). Its names are root-relative and its copy target is `/`; synthetic hardlink and hostile-entry controls remain separate. The test also checks safe relative tar entry names, directories, relative links, hardlinks and absolute symlink targets; unsafe names, setid and device-node denials. A separate owned in-container marker measures absolute-link write-through or records a failed copy request with the mount effect unmeasured. Foreign-owner archive reads must return 403 and the existing ownership message; 404/500 or another cause do not pass. No external path is targeted.
- `ExecSettingsAndTarget`: actual arbitrary argv, privileged denial, matching target admission, headerless/unlabeled-target denial and the separate strict-root control. Opposite/both/mismatched exec target labels are pinned by composed inspector tests, not claimed as live cases.
- `DeploymentMountsAndCapabilities`, `StartupChownFailure` and `SocketPeerFilesystemAccess`: actual inspected non-privileged deployment/flags/mounts, supplementary group access, no-group connection refusal, nonmatching UID policy denial and failed-chown cleanup.

`TestAcceptanceAssertions` runs the shared evidence validators against controlled non-Docker inputs. Its privileged=true counterfactual preserves the other valid deployment settings; ownership 404/500/wrong-reason, two-populated lookup swaps, unrelated/out-of-Up ledger deletion and unrelated permission failures must reject. These are assertion-layer controls, separate from the real observations supplied by the live scenarios.

These are assertions the suite is required to execute, not a claim that a particular source head passed. Required build or infrastructure failure leaves the suite failed; it is never converted into a skip. Residual overlay/libpod lifecycle gaps, daemon-driven starts, outside-proxy writes and start races remain in the committed boundary contracts.

## Evidence and ownership

The wrapper acquires the shared-heavy lock before the Sockguard lock and logs uptime, source head/tree, cwd, store and terminal exit. A parent gate can retain these locks across fixtures through verified inherited descriptors. After prerequisite verification, the wrapper compares source state and complete shared container/image/volume inventories before and after execution; any addition or removal fails the run. Shell fault tests cover bootstrap presence/provenance/immutable selection and both image associations, empty-suite, terminal-result, source/inventory and cleanup guards with tool doubles, separate from real-daemon evidence. CI controls execute the actual preparation and suite-step scripts with tool doubles; a failed preparation cannot admit the suite. On shared hosts it also needs the orchestrator's explicit heavy-slot release. `ACCEPTANCE_EVIDENCE_ROOT` can select the evidence parent directory. The printed `EVIDENCE` path contains the prerequisite receipt, daemon logs and copied runtime inputs/configuration/proxy logs even after failure. Fork CI uploads that directory on every outcome.

Every workload output image/container/network/volume carries a unique run label. The HTTP observation relay adds only the generic provenance label to consumer create requests; it leaves identity labels, security fields, binds and scheduling intact. Direct fixture IDs have creation receipts. Build-source images and caches stay confined to the owned daemon store and disappear with its owned volume; no shared image is removed.

Cleanup is registered before workload mutation and runs on test failure or panic. It selects only the run label or explicit owned IDs, checks a canary created before workload activity and removes it only after checking it remained running. The outer EXIT trap removes only the owned runner, daemon and volume handles. Logs distinguish selected resources from observed residue. No shared resource is inspected and then mutated.

For the narrow status-first reproduction, run only with parent release:

```sh
ACCEPTANCE_BUILD_TAGS=sockguardacceptance,sockguardbuildrepro \
  ./tests/acceptance/run.sh -test.run='^TestBuildDirectReproducer$'
```

This optional diagnostic bypasses the observation relay and logs only generated Solve/Status refs from successful socket writes. It does not delay, replay or change the pinned consumer schedule, and it does not log auth payloads. Its terminal result is reported separately from the acceptance suite.
