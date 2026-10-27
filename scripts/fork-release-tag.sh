#!/usr/bin/env bash
# Verifies a wyrd-company fork release tag before the image is built.
#
#   fork-release-tag.sh <tag>
#
# The fork's version is the upstream release it is built on plus a fork
# counter: 2.2.10-wyrd.1, 2.2.10-wyrd.2, then 2.3.1-wyrd.1 once the fork is
# rebased onto upstream v2.3.1. There is no `v`, so the tag can never match
# upstream's own `v*` release trigger.
#
# Every rule is a question git answers from history, not from a file the fork
# maintains:
#   - the tag names a commit on the fork line (FORK_LINE_REF);
#   - the newest stable upstream release in that commit's history is v<base>;
#   - the counter is the next one for that base, starting at 1;
#   - no fork tag on a newer base exists, so `latest` only moves forward.
# The release workflow serializes verification and publishing across every
# tag and manual run, fetching current fork tags after admission. These checks
# therefore apply even when an older run is admitted after a newer release.
#
# Run in a checkout with full history and the fork's tags. Reads upstream's
# tags from FORK_UPSTREAM_URL into refs/upstream-tags/, a namespace only this
# script writes, so a v* tag on the fork itself is never taken for a release.
#
# On success prints version=, base= and counter= lines, and appends them to
# $GITHUB_OUTPUT when that is set. On refusal prints the reason and exits 1.
set -euo pipefail

tag="${1:?usage: fork-release-tag.sh <tag>}"
line_ref="${FORK_LINE_REF:?FORK_LINE_REF must name the fork line ref}"
upstream_url="${FORK_UPSTREAM_URL:?FORK_UPSTREAM_URL must name upstream}"

refuse() {
  echo "fork-release-tag: $*" >&2
  exit 1
}

tag_pattern='^([0-9]+\.[0-9]+\.[0-9]+)-wyrd\.([1-9][0-9]*)$'
[[ "$tag" =~ $tag_pattern ]] || refuse "tag '${tag}' is not <upstream X.Y.Z>-wyrd.<N> with N >= 1"
base="${BASH_REMATCH[1]}"
counter="${BASH_REMATCH[2]}"

commit="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}" || true)"
[[ -n "$commit" ]] || refuse "tag '${tag}' does not exist in this checkout"

git rev-parse --verify --quiet "${line_ref}^{commit}" >/dev/null ||
  refuse "fork line '${line_ref}' does not exist in this checkout"
git merge-base --is-ancestor "$commit" "$line_ref" ||
  refuse "tag '${tag}' names ${commit}, which is not on the fork line ${line_ref}"

git fetch --quiet --no-tags "$upstream_url" "+refs/tags/v*:refs/upstream-tags/v*"

# Newest stable upstream release contained in the tagged commit. sort -V orders
# the filtered list; the anchored pattern is the filter.
contained=""
while IFS= read -r upstream_tag; do
  if git merge-base --is-ancestor "refs/upstream-tags/${upstream_tag}^{commit}" "$commit"; then
    contained="${upstream_tag}"$'\n'"${contained}"
  fi
done < <(git for-each-ref --format='%(refname:lstrip=2)' refs/upstream-tags/ |
  grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)
built_on="$(printf '%s' "$contained" | grep -v '^$' | sort -V | tail -n 1 || true)"
[[ -n "$built_on" ]] || refuse "tag '${tag}' names a commit that contains no stable upstream release"
[[ "$built_on" == "v${base}" ]] ||
  refuse "tag '${tag}' says base ${base}, but its commit is built on upstream ${built_on}"

# The fork's own release tags, other than this one.
fork_tags="$(git for-each-ref --format='%(refname:lstrip=2)' refs/tags/ |
  grep -E '^[0-9]+\.[0-9]+\.[0-9]+-wyrd\.[1-9][0-9]*$' | grep -vxF "$tag" || true)"

highest=0
newer_base=""
while IFS= read -r other; do
  [[ -n "$other" ]] || continue
  other_base="${other%-wyrd.*}"
  other_counter="${other##*-wyrd.}"
  if [[ "$other_base" == "$base" ]]; then
    if ((other_counter > highest)); then
      highest="$other_counter"
    fi
  elif [[ "$(printf '%s\n%s\n' "$base" "$other_base" | sort -V | tail -n 1)" == "$other_base" ]]; then
    newer_base="$other"
  fi
done <<<"$fork_tags"

[[ -z "$newer_base" ]] ||
  refuse "fork tag ${newer_base} is on a newer upstream base than ${tag}; latest only moves forward"
((counter == highest + 1)) ||
  refuse "tag '${tag}' has counter ${counter}; the next counter for base ${base} is $((highest + 1))"

result="$(printf 'version=%s\nbase=%s\ncounter=%s\n' "$tag" "$base" "$counter")"
printf '%s\n' "$result"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf '%s\n' "$result" >>"$GITHUB_OUTPUT"
fi
