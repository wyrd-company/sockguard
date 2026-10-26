#!/usr/bin/env bash
# The wyrd-company fork's rebase gate. The upkeep workflow runs it in the
# rebased worktree before it publishes the fork line, so a rebase that brings
# in an unclassified upstream workflow, drops a fork guard, shifts a
# line-scoped zizmor ignore, or brings back an upstream contact fails here
# instead of reaching the fork.
#
# Runs every fork test (scripts/fork-*.test.mjs), then zizmor when it is on
# PATH. Without zizmor it says so on stderr: the audit did not run, and the
# fork's CI runs it on the published head.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

shopt -s nullglob
tests=(scripts/fork-*.test.mjs)
if ((${#tests[@]} == 0)); then
  echo "fork-rebase-gate: no scripts/fork-*.test.mjs found; refusing to pass an empty gate" >&2
  exit 1
fi

# Reports go to stderr: the upkeep hands a failed gate to the board with the
# tail of its stderr, and node and zizmor both report findings on stdout.
node --test --experimental-strip-types "${tests[@]}" >&2

if command -v zizmor >/dev/null 2>&1; then
  zizmor --offline --config .github/zizmor.yml .github/workflows .github/actions >&2
else
  echo "fork-rebase-gate: zizmor is not on PATH; the workflow-security audit did not run" >&2
fi
