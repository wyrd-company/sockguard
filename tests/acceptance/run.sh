#!/usr/bin/env bash
# relationships:
#   references: [testdata/profile-input.json, ../../.github/workflows/fork-ci.yml]
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
if [[ "$(git rev-parse --show-toplevel)" != "$repo_root" ]]; then
  echo 'acceptance: wrong Git checkout' >&2
  exit 1
fi
exec 200>/tmp/menagerie-sockguard-heavy-gate.lock
flock 200
exec 201>/tmp/sockguard-gate.lock
flock 201
uptime
mode=full
if (( $# > 0 )); then mode=partial; fi
run_id="acceptance-$(date +%s)-$$"
evidence_root="${ACCEPTANCE_EVIDENCE_ROOT:-/tmp}"
mkdir -p "$evidence_root"
scratch="$(mktemp -d "$evidence_root/fl1576.XXXXXX")"
mkdir -p "$scratch/docker-config" "$scratch/tmp"
export DOCKER_CONFIG="$scratch/docker-config" TMPDIR="$scratch/tmp" GOFLAGS=-count=1
source_head="$(git rev-parse HEAD)"
source_tree="$(git rev-parse 'HEAD^{tree}')"
store="${ACCEPTANCE_STORE:-containerd}"
case "$store" in
  classic) feature=false ;;
  containerd) feature=true ;;
  *) echo "unsupported ACCEPTANCE_STORE: $store" >&2; exit 1 ;;
esac
daemon_image="${ACCEPTANCE_DAEMON_IMAGE:-docker:29.9.2-dind}"
daemon_id=''
runner_id=''
created_volumes=()
# Called by EXIT/INT/TERM traps.
# shellcheck disable=SC2329
cleanup() {
  rc=$?
  trap - EXIT INT TERM
  if [[ -n "$runner_id" ]]; then
    docker cp "$runner_id:/acceptance/." "$scratch/runtime" || rc=1
    docker rm -f -v "$runner_id" || rc=1
  fi
  if [[ -n "$daemon_id" ]]; then docker logs "$daemon_id" > "$scratch/daemon.log" 2>&1 || true; docker rm -f -v "$daemon_id" || rc=1; fi
  for owned_volume in "${created_volumes[@]}"; do docker volume rm "$owned_volume" || rc=1; done
  echo "ACCEPTANCE_OUTER_TERMINAL=$rc HEAD=$source_head TREE=$source_tree STORE=$store MODE=$mode EVIDENCE=$scratch"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'HEAD=%s TREE=%s CWD=%s STORE=%s RUN=%s MODE=%s\n' "$source_head" "$source_tree" "$repo_root" "$store" "$run_id" "$mode"
df -h "$scratch"
# A separate module pins the consumer SDK without adding proxy dependencies.
build_tags="${ACCEPTANCE_BUILD_TAGS:-sockguardacceptance}"
case "$build_tags" in sockguardacceptance|sockguardacceptance,sockguardbuildrepro) ;; *) echo 'unsupported acceptance build tags' >&2; exit 1 ;; esac
(cd tests/acceptance && CGO_ENABLED=0 GOOS=linux go test -mod=readonly -tags="$build_tags" -c -o "$scratch/acceptance.test" .)
# Refuse an empty compiled suite before acquiring daemon resources.
if ! ACCEPTANCE_REQUIRED=1 "$scratch/acceptance.test" -test.list '^TestAcceptance$' | grep -qx TestAcceptance; then
  echo 'acceptance: compiled binary has no required suite' >&2
  exit 1
fi
for purpose in paths socket store; do
  owned_volume="$run_id-$purpose"
  docker volume create --label "org.example.acceptance.run=$run_id" "$owned_volume"
  created_volumes+=("$owned_volume")
done
daemon_id="$(docker create --privileged --label "org.example.acceptance.run=$run_id" \
  --mount "type=volume,src=$run_id-paths,dst=/acceptance" \
  --mount "type=volume,src=$run_id-socket,dst=/run" \
  --mount "type=volume,src=$run_id-store,dst=/var/lib/docker" \
  --entrypoint dockerd "$daemon_image" --host=unix:///run/docker.sock --feature="containerd-snapshotter=$feature")"
docker start "$daemon_id"
ready=false
for _ in $(seq 1 120); do
  if docker exec "$daemon_id" docker info >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then docker logs "$daemon_id"; echo 'owned daemon failed startup' >&2; exit 1; fi
# The test runner and daemon share this volume at the SAME path. The proxy
# later bind-mounts its children from this daemon namespace at those paths.
docker exec "$daemon_id" sh -c 'chmod 0777 /acceptance; chmod 0666 /run/docker.sock'
runner_id="$(docker create --user 10001:10002 --group-add 20001 \
  --label "org.example.acceptance.run=$run_id" \
  --mount "type=volume,src=$run_id-paths,dst=/acceptance" \
  --mount "type=volume,src=$run_id-socket,dst=/run" \
  --env DOCKER_HOST=unix:///run/docker.sock --env DOCKER_CONFIG=/acceptance/docker-config \
  --env ACCEPTANCE_REQUIRED=1 --env ACCEPTANCE_RUN="$run_id" --env ACCEPTANCE_SOURCE_HEAD="$source_head" \
  --env ACCEPTANCE_SOURCE_TREE="$source_tree" --env ACCEPTANCE_STORE="$store" --env ACCEPTANCE_DAEMON_IMAGE="$daemon_image" \
  --entrypoint /acceptance.test "$daemon_image" -test.v -test.timeout=30m "${@}")"
docker cp "$scratch/acceptance.test" "$runner_id:/acceptance.test"
# Copy only fork-build inputs and tracked acceptance inputs. No node_modules,
# empty untracked fixture directories or operator Docker configuration.
git ls-files -z -- Dockerfile go.mod go.sum app tests/acceptance/testdata > "$scratch/source-paths"
tar -cf "$scratch/source.tar" --transform='s,^,src/,' --null -T "$scratch/source-paths"
sha256sum "$scratch/source.tar"
docker cp - "$runner_id:/" < "$scratch/source.tar"
docker start -a "$runner_id" || true
state="$(docker inspect --format '{{.State.Status}} {{.State.StartedAt}}' "$runner_id")"
if [[ "$state" != exited\ * || "$state" == *0001-01-01* ]]; then
  echo "acceptance: runner has no terminal execution receipt: $state" >&2
  exit 1
fi
rc="$(docker inspect --format '{{.State.ExitCode}}' "$runner_id")"
# Producer result, including panic/failure, is authoritative.
exit "$rc"
