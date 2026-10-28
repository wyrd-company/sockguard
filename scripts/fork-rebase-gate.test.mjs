import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const gate = resolve(repoRoot, "scripts/fork-rebase-gate.sh");
const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-fork-rebase-gate-"));

after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

const gitEnv = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
);

let count = 0;

// A checkout with the given fork test files and stub node/zizmor commands that
// record their arguments and exit with the configured status.
function fixture({ tests = ["fork-a.test.mjs", "fork-b.test.mjs"], node = 0, zizmor = 0 } = {}) {
  count += 1;
  const dir = join(fixtureRoot, String(count));
  const repo = join(dir, "repo");
  const bin = join(dir, "bin");
  mkdirSync(join(repo, "scripts", "nested"), { recursive: true });
  mkdirSync(bin);
  spawnSync("git", ["init", "--quiet", repo], { env: gitEnv });
  for (const name of tests) {
    writeFileSync(join(repo, "scripts", name), "");
  }
  writeFileSync(join(repo, "scripts", "other.test.mjs"), "");
  const log = join(dir, "calls");
  const stub = (name, status) => {
    if (status === null) {
      return;
    }
    writeFileSync(
      join(bin, name),
      `#!/bin/bash\nprintf '${name} %s\\n' "$*" >> "${log}"\necho "${name} reported"\nexit ${status}\n`,
    );
    chmodSync(join(bin, name), 0o755);
  };
  stub("node", node);
  stub("zizmor", zizmor);
  return { repo, bin, log };
}

function run(fx, cwd = fx.repo) {
  // Only the stubs, git and the shell utilities: a real node or zizmor on the
  // caller's PATH must not answer for a stub the fixture left out.
  const result = spawnSync("bash", [gate], {
    cwd,
    env: { ...gitEnv, PATH: `${fx.bin}:/usr/bin:/bin:/usr/local/bin` },
    encoding: "utf8",
  });
  let calls = "";
  try {
    calls = readFileSync(fx.log, "utf8");
  } catch {
    calls = "";
  }
  return { ...result, calls };
}

describe("fork-rebase-gate.sh", () => {
  it("runs every fork test, then zizmor on the workflows with the repository config", () => {
    const fx = fixture();
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(
      result.calls,
      [
        "node --test --experimental-strip-types scripts/fork-a.test.mjs scripts/fork-b.test.mjs",
        "zizmor --offline --config .github/zizmor.yml .github/workflows .github/actions",
        "",
      ].join("\n"),
    );
  });

  it("runs from the checkout root when started in a subdirectory", () => {
    const fx = fixture();
    const result = run(fx, join(fx.repo, "scripts", "nested"));
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.calls, /scripts\/fork-a\.test\.mjs/u);
  });

  it("fails when a fork test fails, before zizmor runs", () => {
    const fx = fixture({ node: 1 });
    const result = run(fx);
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.calls, /^zizmor/mu);
  });

  it("writes the test report to stderr, which the upkeep hands to the board", () => {
    const fx = fixture({ node: 1 });
    const result = run(fx);
    assert.match(result.stderr, /^node reported$/mu);
    assert.doesNotMatch(result.stdout, /node reported/u);
  });

  it("fails when zizmor reports a finding", () => {
    const fx = fixture({ zizmor: 13 });
    const result = run(fx);
    assert.equal(result.status, 13);
    assert.match(result.stderr, /^zizmor reported$/mu);
    assert.doesNotMatch(result.stdout, /zizmor reported/u);
  });

  it("says the audit did not run when zizmor is absent", () => {
    const fx = fixture({ zizmor: null });
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /zizmor is not on PATH; the workflow-security audit did not run/u);
    assert.doesNotMatch(result.calls, /^zizmor/mu);
  });

  it("refuses to pass when there is no fork test to run", () => {
    const fx = fixture({ tests: [] });
    const result = run(fx);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /refusing to pass an empty gate/u);
    assert.equal(result.calls, "");
  });

  it("covers the fork tests this repository carries", () => {
    // The glob is the gate's whole selection; a fork test named outside it
    // would never run after a rebase.
    const gateSource = readFileSync(gate, "utf8");
    assert.match(gateSource, /^tests=\(scripts\/fork-\*\.test\.mjs\)$/mu);
    for (const name of [
      "fork-workflow-guards.test.mjs",
      "fork-release-tag.test.mjs",
      "fork-security-contact.test.mjs",
    ]) {
      assert.ok(
        readFileSync(resolve(repoRoot, "scripts", name), "utf8").length > 0,
        `scripts/${name} is missing`,
      );
    }
  });
});
