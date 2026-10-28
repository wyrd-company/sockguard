import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const script = resolve(repoRoot, "scripts/fork-release-tag.sh");
const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-fork-release-tag-"));

after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

// A git environment that cannot reach the repository under test: no GIT_*
// variable from a hook or the caller's shell survives into the fixtures.
const gitEnv = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
);
Object.assign(gitEnv, {
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
});

function git(cwd, ...args) {
  const result = spawnSync("git", args, { cwd, env: gitEnv, encoding: "utf8" });
  assert.equal(result.status, 0, `git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout.trim();
}

let fixtureCount = 0;

// Upstream history: v2.2.9 -> v2.2.10 -> v2.2.11 -> v2.3.0-rc.1 -> v2.3.0.
// The fork clones it without tags and keeps its work on branch `line`.
function fixture() {
  fixtureCount += 1;
  const dir = join(fixtureRoot, String(fixtureCount));
  const upstream = join(dir, "upstream");
  const fork = join(dir, "fork");
  git(fixtureRoot, "init", "--quiet", "-b", "main", upstream);
  const upstreamCommits = {};
  for (const tag of ["v2.2.9", "v2.2.10", "v2.2.11", "v2.3.0-rc.1", "v2.3.0"]) {
    git(upstream, "commit", "--quiet", "--allow-empty", "-m", `release ${tag}`);
    git(upstream, "tag", tag);
    upstreamCommits[tag] = git(upstream, "rev-parse", "HEAD");
  }
  git(fixtureRoot, "clone", "--quiet", "--no-tags", upstream, fork);
  return { dir, upstream, fork, upstreamCommits };
}

// Adds a fork commit on top of `base` to branch `branch`, tags it, and returns
// the commit.
function forkCommit(fx, { from, branch = "line", tag, message = "fork change" }) {
  git(fx.fork, "checkout", "--quiet", "-B", branch, from);
  git(fx.fork, "commit", "--quiet", "--allow-empty", "-m", message);
  if (tag) {
    git(fx.fork, "tag", tag);
  }
  return git(fx.fork, "rev-parse", "HEAD");
}

function verify(fx, tag, extraEnv = {}) {
  const result = spawnSync("bash", [script, tag], {
    cwd: fx.fork,
    env: {
      ...gitEnv,
      FORK_LINE_REF: "refs/heads/line",
      FORK_UPSTREAM_URL: fx.upstream,
      GITHUB_OUTPUT: "",
      ...extraEnv,
    },
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function assertRefused(result, reason) {
  assert.equal(result.status, 1, `expected a refusal, got ${result.status}: ${result.stdout}`);
  assert.match(result.stderr, reason);
}

describe("fork-release-tag.sh", () => {
  it("accepts the first counter on the base the commit is built on and reports it", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.10-wyrd.1" });
    const output = join(fx.dir, "github-output");
    const result = verify(fx, "2.2.10-wyrd.1", { GITHUB_OUTPUT: output });
    assert.equal(result.status, 0, result.stderr);
    const expected = "version=2.2.10-wyrd.1\nbase=2.2.10\ncounter=1\n";
    assert.equal(result.stdout, expected);
    assert.equal(readFileSync(output, "utf8"), expected);
  });

  for (const tag of [
    "v2.2.10-wyrd.1",
    "2.2.10",
    "2.2.10-wyrd.0",
    "2.2.10-wyrd.01",
    "2.2.10-wyrd.1-rc.1",
    "2.2-wyrd.1",
  ]) {
    it(`refuses the tag shape '${tag}'`, () => {
      const fx = fixture();
      forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag });
      assertRefused(verify(fx, tag), /is not <upstream X\.Y\.Z>-wyrd\.<N>/u);
    });
  }

  it("refuses a tag that does not exist", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"] });
    assertRefused(verify(fx, "2.2.10-wyrd.1"), /does not exist in this checkout/u);
  });

  it("refuses a tag whose commit is not on the fork line", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"] });
    forkCommit(fx, {
      from: fx.upstreamCommits["v2.2.10"],
      branch: "side",
      tag: "2.2.10-wyrd.1",
      message: "side change",
    });
    assertRefused(verify(fx, "2.2.10-wyrd.1"), /is not on the fork line/u);
  });

  it("refuses a base the commit is not built on", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.11-wyrd.1" });
    assertRefused(
      verify(fx, "2.2.11-wyrd.1"),
      /says base 2\.2\.11, but its commit is built on upstream v2\.2\.10/u,
    );
  });

  it("orders upstream versions numerically, so v2.2.10 is newer than v2.2.9", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.9-wyrd.1" });
    assertRefused(verify(fx, "2.2.9-wyrd.1"), /built on upstream v2\.2\.10/u);
  });

  it("does not take an upstream release candidate for a release", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.3.0-rc.1"], tag: "2.2.11-wyrd.1" });
    const result = verify(fx, "2.2.11-wyrd.1");
    assert.equal(result.status, 0, result.stderr);
  });

  it("reads upstream releases only from upstream, never from a v* tag on the fork", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.11-wyrd.1" });
    // A forged upstream-looking tag on the fork's own commit.
    git(fx.fork, "tag", "v2.2.11");
    assertRefused(verify(fx, "2.2.11-wyrd.1"), /built on upstream v2\.2\.10/u);
  });

  it("refuses a commit that contains no stable upstream release", () => {
    const fx = fixture();
    git(fx.fork, "checkout", "--quiet", "--orphan", "line");
    git(fx.fork, "commit", "--quiet", "--allow-empty", "-m", "unrelated root");
    git(fx.fork, "tag", "2.2.10-wyrd.1");
    assertRefused(verify(fx, "2.2.10-wyrd.1"), /contains no stable upstream release/u);
  });

  it("accepts the next counter and refuses a skipped one", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.10-wyrd.1" });
    forkCommit(fx, { from: "line", tag: "2.2.10-wyrd.3" });
    assertRefused(
      verify(fx, "2.2.10-wyrd.3"),
      /has counter 3; the next counter for base 2\.2\.10 is 2/u,
    );
    git(fx.fork, "tag", "2.2.10-wyrd.2");
    git(fx.fork, "tag", "-d", "2.2.10-wyrd.3");
    const result = verify(fx, "2.2.10-wyrd.2");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^counter=2$/mu);
  });

  it("accepts a rerun of the newest tag and refuses a rebuild of an older counter", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.10-wyrd.1" });
    forkCommit(fx, { from: "line", tag: "2.2.10-wyrd.2" });
    assert.equal(verify(fx, "2.2.10-wyrd.2").status, 0);
    assertRefused(verify(fx, "2.2.10-wyrd.1"), /the next counter for base 2\.2\.10 is 3/u);
  });

  for (const { label, newerTag, from, reason } of [
    {
      label: "counter",
      newerTag: "2.2.10-wyrd.2",
      from: "line",
      reason: /the next counter for base 2\.2\.10 is 3/u,
    },
    {
      label: "base",
      newerTag: "2.2.11-wyrd.1",
      from: "v2.2.11",
      reason: /fork tag 2\.2\.11-wyrd\.1 is on a newer upstream base/u,
    },
  ]) {
    it(`fresh tag fetch refuses an older ${label} after the newer release and on rerun`, () => {
      const fx = fixture();
      const olderTag = "2.2.10-wyrd.1";
      // Keep the older tag on the fork line in both cases, so the refusal
      // must come from the counter/newer-base guard, not branch ancestry.
      git(fx.fork, "checkout", "--quiet", "-b", "line", fx.upstreamCommits["v2.2.10"]);
      git(fx.fork, "tag", olderTag);
      const runner = join(fx.dir, "runner");
      git(fx.dir, "clone", "--quiet", "--no-local", "--branch", "line", fx.fork, runner);
      const run = (tag) =>
        verify({ ...fx, fork: runner }, tag, { FORK_LINE_REF: "refs/remotes/origin/line" });
      assert.equal(run(olderTag).status, 0, "older tag must pass before the newer tag exists");

      forkCommit(fx, { from: fx.upstreamCommits[from] ?? from, tag: newerTag });
      const newer = verify(fx, newerTag);
      assert.equal(newer.status, 0, newer.stderr);
      assert.ok(!git(runner, "tag", "--list").includes(newerTag), "control checkout must be stale");
      assert.equal(run(olderTag).status, 0, "stale tags must expose the unsafe older admission");

      // Model the serialized workflow's full checkout fetch after admission.
      // This works even when the newer release ran before the older run.
      git(runner, "fetch", "--force", "--tags", "origin", "+refs/heads/*:refs/remotes/origin/*");
      assert.ok(
        git(runner, "tag", "--list").includes(newerTag),
        "full fetch must see the newer tag",
      );
      const current = run(newerTag);
      assert.equal(current.status, 0, current.stderr);
      assertRefused(run(olderTag), reason);
      assertRefused(run(olderTag), reason);
    });
  }

  it("resets the counter to 1 on a new upstream base", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.10-wyrd.1" });
    forkCommit(fx, { from: "line", tag: "2.2.10-wyrd.2" });
    // The upkeep rebases the fork line onto the next upstream release.
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.11"], tag: "2.2.11-wyrd.1" });
    const result = verify(fx, "2.2.11-wyrd.1");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^base=2\.2\.11$/mu);
  });

  it("refuses a release on an older base once a newer base has a fork tag", () => {
    const fx = fixture();
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.11"], tag: "2.2.11-wyrd.1" });
    forkCommit(fx, { from: fx.upstreamCommits["v2.2.10"], tag: "2.2.10-wyrd.1" });
    assertRefused(
      verify(fx, "2.2.10-wyrd.1"),
      /fork tag 2\.2\.11-wyrd\.1 is on a newer upstream base/u,
    );
  });
});
