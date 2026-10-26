#!/usr/bin/env bash
# Verifies a published wyrd-company fork image the way an operator would.
#
#   fork-verify-published-image.sh [--dry-run] --tag <X.Y.Z-wyrd.N> --digest <sha256:...>
#
# The fork publishes one thing: a multi-arch image on ghcr.io with a build
# provenance attestation signed by its fork-release.yml workflow. This checks
# that image. Upstream's scripts/verify-published-release.sh checks upstream's
# release (cosign signatures, Docker Hub, Quay, binaries), none of which the
# fork publishes.
#
# The repository comes from GITHUB_REPOSITORY, defaulting to the fork. The image
# is ghcr.io/<repository, lowercased>; the attestation must be signed by
# <repository>/.github/workflows/fork-release.yml through GitHub Actions' OIDC
# issuer.
#
# Checks, in order, each of which fails the run:
#   - the index carries linux/amd64 and linux/arm64;
#   - <image>:<tag> resolves to the digest;
#   - this host's platform runs and reports the tag as its version;
#   - the source label names the repository, and no label names upstream;
#   - gh attestation verify accepts the digest for that signer and issuer.
#
# --dry-run prints the resolved plan and contacts nothing.
set -euo pipefail

DRY_RUN=0
TAG=""
DIGEST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --tag) TAG="${2:-}"; shift 2 ;;
    --digest) DIGEST="${2:-}"; shift 2 ;;
    *) echo "fork-verify-published-image.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

if [ -z "${TAG}" ] || [ -z "${DIGEST}" ]; then
  echo "fork-verify-published-image.sh: --tag and --digest are required" >&2
  exit 2
fi
if ! [[ "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "fork-verify-published-image.sh: --digest must be sha256:<64 hex>, not '${DIGEST}'" >&2
  exit 2
fi

REPO="${GITHUB_REPOSITORY:-wyrd-company/sockguard}"
IMAGE="ghcr.io/$(printf '%s' "${REPO}" | tr '[:upper:]' '[:lower:]')"
PLATFORMS="linux/amd64,linux/arm64"
SOURCE="https://github.com/${REPO}"
SIGNER_WORKFLOW="${REPO}/.github/workflows/fork-release.yml"
ISSUER="https://token.actions.githubusercontent.com"
REF="${IMAGE}@${DIGEST}"

if [ "${DRY_RUN}" -eq 1 ]; then
  cat <<EOF
fork-verify-published-image.sh dry-run plan:
  repository:       ${REPO}
  image:            ${REF}
  tag:              ${IMAGE}:${TAG}
  platforms:        ${PLATFORMS}
  source label:     ${SOURCE}
  signer workflow:  ${SIGNER_WORKFLOW}
  issuer:           ${ISSUER}
EOF
  exit 0
fi

fail() {
  echo "::error::$*"
  exit 1
}

platforms="$(docker buildx imagetools inspect "${REF}" --format '{{json .Manifest}}' |
  jq -r '[.manifests[].platform | select(.os != "unknown") | "\(.os)/\(.architecture)"] | sort | join(",")')"
[ "${platforms}" = "${PLATFORMS}" ] || fail "Published platforms '${platforms}', expected '${PLATFORMS}'."

tagged="$(docker buildx imagetools inspect "${IMAGE}:${TAG}" --format '{{json .Manifest}}' | jq -r .digest)"
[ "${tagged}" = "${DIGEST}" ] || fail "${IMAGE}:${TAG} is ${tagged}, expected ${DIGEST}."

docker pull --quiet "${REF}" >/dev/null
reported="$(docker run --rm "${REF}" version -o json | jq -r .version)"
[ "${reported}" = "${TAG}" ] || fail "Image reports version '${reported}', expected '${TAG}'."

source_label="$(docker image inspect "${REF}" --format '{{ index .Config.Labels "org.opencontainers.image.source" }}')"
[ "${source_label}" = "${SOURCE}" ] || fail "Source label '${source_label}', expected '${SOURCE}'."
if docker image inspect "${REF}" --format '{{ json .Config.Labels }}' | grep -qi codeswhat; then
  fail "An image label names upstream."
fi

gh attestation verify "oci://${REF}" \
  --repo "${REPO}" \
  --signer-workflow "${SIGNER_WORKFLOW}" \
  --cert-oidc-issuer "${ISSUER}"
echo "fork-verify-published-image.sh: ${IMAGE}:${TAG} verified"
