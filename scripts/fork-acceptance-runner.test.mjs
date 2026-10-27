// relationships:
//   references: [../tests/acceptance/run.sh]
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const IMAGE_ID = `sha256:${"a".repeat(64)}`;
const OTHER_IMAGE_ID = `sha256:${"b".repeat(64)}`;
const REPO_DIGESTS = `["registry.example.test/fixture@sha256:${"c".repeat(64)}"]`;

// These fault tests pin only the shell runner's evidence/cleanup boundary.
// Tool doubles never count as daemon, lock admission or consumer acceptance.
function run(fault = "", { requested = "docker:29.9.2-dind", repoDigests = REPO_DIGESTS } = {}) {
  const root = mkdtempSync(join(tmpdir(), "acceptance-runner-"));
  try {
    mkdirSync(join(root, "tests/acceptance"), { recursive: true });
    mkdirSync(join(root, "bin"));
    copyFileSync(
      resolve(import.meta.dirname, "../tests/acceptance/run.sh"),
      join(root, "tests/acceptance/run.sh"),
    );
    const executable = (name, body) => {
      const path = join(root, "bin", name);
      writeFileSync(path, `#!/usr/bin/env bash\nset -eu\n${body}\n`);
      chmodSync(path, 0o755);
    };
    executable("flock", ":"); // Lock admission itself is measured by real runs.
    executable(
      "git",
      `
case "$*" in
  'rev-parse --show-toplevel') echo "$FIXTURE_ROOT" ;;
  'rev-parse HEAD') echo fixture-head ;;
  'rev-parse HEAD^{tree}') echo fixture-tree ;;
  'merge-base '*) echo fixture-base ;;
  'status --porcelain=v1')
    if [[ "$FAULT" == source && -e "$FIXTURE_ROOT/finished" ]]; then echo ' M Dockerfile'; fi ;;
  'diff --binary HEAD') : ;;
  'ls-files '*) : ;;
  *) echo "unexpected Git call $*" >&2; exit 91 ;;
esac`,
    );
    executable(
      "go",
      `
printf '%s\\n' "$*" >> "$FIXTURE_ROOT/go.calls"
while (( $# )); do
 if [[ "$1" == -o ]]; then
   shift
   printf '#!/usr/bin/env bash\\n[[ "$FAULT" != empty ]] && echo TestAcceptance\\nexit 0\\n' > "$1"
   chmod +x "$1"
   exit 0
 fi
 shift
done
exit 92`,
    );
    executable(
      "docker",
      `
printf '%s\\n' "$*" >> "$FIXTURE_ROOT/docker.calls"
case "$*" in
 'image inspect --format {{.Id}} '*)
   if [[ "$FAULT" == missing ]]; then exit 1; fi
   if [[ "$FAULT" == invalid-id ]]; then echo mutable:tag
   elif [[ "$FAULT" != empty-id ]]; then echo "$SELECTED_IMAGE_ID"; fi
   if [[ "$FAULT" == tag-change ]]; then touch "$FIXTURE_ROOT/tag-changed"; fi ;;
 'image inspect --format {{json .RepoDigests}} '*)
   if [[ "$FAULT" == provenance ]]; then exit 1; fi
   echo "$REPO_DIGESTS" ;;
 'container ls '*)
   if [[ "$FAULT" != container-remove || ! -e "$FIXTURE_ROOT/finished" ]]; then echo preexisting-container; fi
   if [[ ( "$FAULT" == inventory || "$FAULT" == container-add ) && -e "$FIXTURE_ROOT/finished" ]]; then echo foreign-container; fi ;;
 'image ls '*)
   if [[ "$FAULT" != image-remove || ! -e "$FIXTURE_ROOT/finished" ]]; then echo "$SELECTED_IMAGE_ID"; fi
   if [[ "$FAULT" == image-add && -e "$FIXTURE_ROOT/finished" ]]; then echo "$OTHER_IMAGE_ID"; fi ;;
 'volume ls '*)
   if [[ "$FAULT" != volume-remove || ! -e "$FIXTURE_ROOT/finished" ]]; then echo preexisting-volume; fi
   if [[ "$FAULT" == volume-add && -e "$FIXTURE_ROOT/finished" ]]; then echo foreign-volume; fi ;;
 'volume create '*) echo "owned-volume" ;;
 'create '*)
   role=runner
   if [[ "$*" == *--privileged* ]]; then role=daemon; fi
   if [[ "$FAULT" == "$role-unavailable" ]]; then
     if [[ "$*" == *--pull=never* ]]; then echo 'selected bootstrap image no longer available' >&2; exit 1; fi
     printf 'pull %s\\n' "$SELECTED_IMAGE_ID" >> "$FIXTURE_ROOT/docker.calls"
   fi
   selected="$SELECTED_IMAGE_ID"
   for arg in "$@"; do
     if [[ "$arg" == "$REQUESTED_IMAGE" && -e "$FIXTURE_ROOT/tag-changed" ]]; then selected="$OTHER_IMAGE_ID"; fi
   done
   if [[ "$FAULT" == "$role-image" ]]; then selected="$OTHER_IMAGE_ID"; fi
   echo "$selected" > "$FIXTURE_ROOT/$role.image"
   echo "owned-$role" ;;
 'start -a '*) touch "$FIXTURE_ROOT/finished" ;;
 'start '*|'exec '*) : ;;
 'cp '*) if [[ "$2" == - ]]; then cat >/dev/null; fi ;;
 'inspect --format {{.Image}} '*)
   role="\${4#owned-}"
   if [[ "$FAULT" == "$role-association-lookup" ]]; then exit 1; fi
   cat "$FIXTURE_ROOT/$role.image" ;;
 'inspect --format {{.State.Status}} {{.State.StartedAt}} '* )
   if [[ "$FAULT" == terminal ]]; then echo 'created 0001-01-01T00:00:00Z'; else echo 'exited 2026-01-01T00:00:00Z'; fi ;;
 'inspect --format {{.State.ExitCode}} '*)
   if [[ "$FAULT" == producer ]]; then echo 7; else echo 0; fi ;;
 'rm '*|'volume rm '*|'logs '*) if [[ "$FAULT" == cleanup && "$*" == 'rm -f -v owned-runner' ]]; then exit 9; fi ;;
 *) echo "unexpected Docker call $*" >&2; exit 93 ;;
esac`,
    );
    // Close only the negative child copies, even under legitimate parent locks.
    const result = spawnSync(
      "bash",
      fault === "inherited"
        ? ["-c", 'exec 200>&- 201>&-; exec bash "$1"', "--", join(root, "tests/acceptance/run.sh")]
        : [join(root, "tests/acceptance/run.sh")],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${join(root, "bin")}:${process.env.PATH}`,
          FIXTURE_ROOT: root,
          FAULT: fault,
          SELECTED_IMAGE_ID: IMAGE_ID,
          OTHER_IMAGE_ID,
          REQUESTED_IMAGE: requested,
          REPO_DIGESTS: repoDigests,
          ACCEPTANCE_DAEMON_IMAGE: requested,
          ACCEPTANCE_INHERITED_LOCKS: fault === "inherited" ? "1" : "",
          ACCEPTANCE_EVIDENCE_ROOT: root,
        },
      },
    );
    const calls = (name) =>
      existsSync(join(root, name)) ? readFileSync(join(root, name), "utf8") : "";
    const evidence = readdirSync(root).find((name) => name.startsWith("fl1576."));
    const receipt = evidence ? join(root, evidence, "bootstrap-prerequisite.txt") : "";
    return {
      ...result,
      calls: calls("docker.calls"),
      goCalls: calls("go.calls"),
      prerequisite: receipt && existsSync(receipt) ? readFileSync(receipt, "utf8") : "",
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function assertPinnedCreates(r) {
  const creates = r.calls.split("\n").filter((line) => line.startsWith("create "));
  assert.equal(creates.length, 2, r.stderr);
  for (const call of creates) {
    assert.ok(call.includes("--pull=never"), "bootstrap creates must refuse implicit pull");
    assert.ok(call.includes(IMAGE_ID), "both bootstrap creates must use resolved immutable ID");
  }
  assert.doesNotMatch(r.calls, /^pull |^image (?:pull|rm) |prune/m);
}

test("acceptance runner records a completed producer and removes only created handles", () => {
  const r = run();
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /ACCEPTANCE_OUTER_TERMINAL=0 HEAD=fixture-head/);
  assert.match(r.calls, /rm -f -v owned-runner/);
  assert.match(r.calls, /rm -f -v owned-daemon/);
  assert.equal(r.calls.match(/^volume rm /gm)?.length, 3);
  assert.doesNotMatch(r.calls, /prune|rm.*foreign/);
});

test("acceptance runner records the selected prerequisite and both container image associations", () => {
  const r = run();
  assert.equal(r.status, 0, r.stderr);
  assert.ok(
    r.prerequisite.includes(
      `requested=docker:29.9.2-dind image_id=${IMAGE_ID} repo_digests=${REPO_DIGESTS}`,
    ),
    "bootstrap receipt must retain requested value, immutable ID and RepoDigests",
  );
  for (const role of ["daemon", "runner"]) {
    assert.ok(
      r.prerequisite.includes(`role=${role} id=owned-${role} image_id=${IMAGE_ID}`),
      `bootstrap receipt must retain actual ${role} image association`,
    );
  }
  assert.ok(r.calls.includes(`image inspect --format {{json .RepoDigests}} ${IMAGE_ID}`));
  assertPinnedCreates(r);
});

for (const [fault, reason] of [
  ["missing", "bootstrap image prerequisite missing"],
  ["invalid-id", "did not resolve to an immutable image ID"],
  ["empty-id", "did not resolve to an immutable image ID"],
  ["provenance", "bootstrap prerequisite provenance lookup failed"],
]) {
  test(`acceptance runner refuses ${fault} prerequisite before protected admission`, () => {
    const r = run(fault);
    assert.equal(r.goCalls, "", "prerequisite failure must precede compilation/suite admission");
    assert.equal(r.status, 1, r.stderr);
    assert.ok(r.stderr.includes(reason), r.stderr);
    assert.doesNotMatch(r.calls, /^create |^pull |^volume create |^container ls /m);
    assert.doesNotMatch(r.stdout, /HEAD=fixture-head|ACCEPTANCE_OUTER_TERMINAL/);
  });
}

test("acceptance runner pins the selected ID when the requested tag moves after verification", () => {
  const r = run("tag-change");
  assert.equal(r.status, 0, "requested tag movement must not change bootstrap identity");
  assertPinnedCreates(r);
  assert.ok(r.prerequisite.includes(`role=daemon id=owned-daemon image_id=${IMAGE_ID}`));
  assert.ok(r.prerequisite.includes(`role=runner id=owned-runner image_id=${IMAGE_ID}`));
});

for (const repoDigests of ["[]", "null"]) {
  test(`acceptance runner supports a local image override with RepoDigests=${repoDigests}`, () => {
    const r = run("", { requested: "example-fixture:local", repoDigests });
    assert.equal(r.status, 0, "locally built overrides must not require registry digests");
    assert.ok(
      r.prerequisite.includes(
        `requested=example-fixture:local image_id=${IMAGE_ID} repo_digests=${repoDigests}`,
      ),
    );
    assertPinnedCreates(r);
    assert.doesNotMatch(r.prerequisite, /registry\.example/);
  });
}

for (const role of ["daemon", "runner"]) {
  test(`acceptance runner never pulls if the selected image disappears before ${role} create`, () => {
    const r = run(`${role}-unavailable`);
    assert.equal(r.status, 1, "missing selected image must fail create without pulling");
    assert.match(r.stderr, /selected bootstrap image no longer available/);
    assert.doesNotMatch(r.calls, /^pull |^image pull /m);
    assert.match(r.stdout, /ACCEPTANCE_OUTER_TERMINAL=1/);
    assert.equal(r.calls.match(/^volume rm /gm)?.length, 3);
  });
  for (const [fault, reason] of [
    [`${role}-image`, `${role} bootstrap image association differs from resolved prerequisite`],
    [`${role}-association-lookup`, `${role} bootstrap image association lookup failed`],
  ]) {
    test(`acceptance runner refuses ${fault} before that container starts`, () => {
      const r = run(fault);
      assert.equal(
        r.status,
        1,
        `${role} image association fault must reject before container start`,
      );
      assert.ok(r.stderr.includes(reason), r.stderr);
      assert.match(r.stdout, /ACCEPTANCE_OUTER_TERMINAL=1/);
      assert.ok(r.calls.includes(`rm -f -v owned-${role}`));
      assert.doesNotMatch(
        r.calls,
        role === "daemon" ? /^start owned-daemon$/m : /^start -a owned-runner$/m,
      );
    });
  }
}

for (const [fault, reason] of [
  ["empty", "compiled binary has no required suite"],
  ["terminal", "runner has no terminal execution receipt"],
  ["inventory", "shared resource inventory changed"],
  ...["container", "image", "volume"].flatMap((kind) =>
    ["add", "remove"].map((effect) => [`${kind}-${effect}`, "shared resource inventory changed"]),
  ),
  ["source", "source changed during execution"],
]) {
  test(`acceptance runner refuses ${fault} evidence`, () => {
    const r = run(fault);
    assert.equal(r.status, 1, r.stderr);
    assert.ok(r.stderr.includes(reason), r.stderr);
    assert.match(r.stdout, /ACCEPTANCE_OUTER_TERMINAL=1/);
    if (fault !== "empty") {
      assert.match(r.calls, /rm -f -v owned-runner/);
      assert.match(r.calls, /rm -f -v owned-daemon/);
    } else {
      assert.doesNotMatch(r.calls, /^create /m);
    }
  });
}
test("acceptance runner retains the failing producer status after unconditional cleanup", () => {
  const r = run("producer");
  assert.equal(r.status, 7, r.stderr);
  assert.match(r.stdout, /ACCEPTANCE_OUTER_TERMINAL=7/);
  assert.match(r.calls, /rm -f -v owned-runner/);
  assert.match(r.calls, /rm -f -v owned-daemon/);
});

test("acceptance runner fails when owned cleanup fails", () => {
  const r = run("cleanup");
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stdout, /ACCEPTANCE_OUTER_TERMINAL=1/);
  assert.match(r.calls, /rm -f -v owned-daemon/);
});

test("acceptance runner refuses unproved inherited lock ownership", () => {
  const r = run("inherited");
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /inherited lock descriptors missing or wrong/);
  assert.equal(r.calls, "");
});
