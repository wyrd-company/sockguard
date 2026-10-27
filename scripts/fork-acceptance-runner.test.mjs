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
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

// These fault tests pin only the shell runner's evidence/cleanup boundary.
// Tool doubles never count as daemon or consumer acceptance evidence.
function run(fault = "") {
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
 'container ls '*)
   if [[ "$FAULT" == inventory && -e "$FIXTURE_ROOT/finished" ]]; then echo foreign-container; fi ;;
 'image ls '*|'volume ls '*) : ;;
 'volume create '*) echo "owned-volume" ;;
 'create '*)
   if [[ "$*" == *--privileged* ]]; then echo owned-daemon; else echo owned-runner; fi ;;
 'start -a '*) touch "$FIXTURE_ROOT/finished" ;;
 'start '*) : ;;
 'exec '*) : ;;
 'cp '*) if [[ "$2" == - ]]; then cat >/dev/null; fi ;;
 'inspect --format {{.State.Status}} {{.State.StartedAt}} '* )
   if [[ "$FAULT" == terminal ]]; then echo 'created 0001-01-01T00:00:00Z'; else echo 'exited 2026-01-01T00:00:00Z'; fi ;;
 'inspect --format {{.State.ExitCode}} '*)
   if [[ "$FAULT" == producer ]]; then echo 7; else echo 0; fi ;;
 'rm '*|'volume rm '*|'logs '*) if [[ "$FAULT" == cleanup && "$*" == 'rm -f -v owned-runner' ]]; then exit 9; fi ;;
 *) echo "unexpected Docker call $*" >&2; exit 93 ;;
esac`,
    );
    // The negative must lack descriptors even when npm inherits the real
    // gate owner's locks. Close only this child process's descriptor copies.
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
          ACCEPTANCE_INHERITED_LOCKS: fault === "inherited" ? "1" : "",
          ACCEPTANCE_EVIDENCE_ROOT: root,
        },
      },
    );
    return {
      ...result,
      calls: existsSync(join(root, "docker.calls"))
        ? readFileSync(join(root, "docker.calls"), "utf8")
        : "",
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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
for (const [fault, reason] of [
  ["empty", "compiled binary has no required suite"],
  ["terminal", "runner has no terminal execution receipt"],
  ["inventory", "shared resource inventory changed"],
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
