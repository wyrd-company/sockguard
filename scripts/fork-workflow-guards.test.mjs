import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

// The wyrd-company fork keeps upstream's workflows and switches off the ones
// that publish under upstream's name, need secrets the fork lacks, or point at
// upstream-owned infrastructure. This file is the machine-checked form of that
// audit: every workflow file is classified below, and a rebase that brings in
// a new workflow, a new secret, or drops a guard fails here by name.

const repoRoot = resolve(import.meta.dirname, "..");
const workflowsDir = resolve(repoRoot, ".github/workflows");

const UPSTREAM = "github.repository == 'CodesWhat/sockguard'";

// Secrets an active (unguarded) job may read. GITHUB_TOKEN is always present.
// The Docker Hub pair only authenticates image pulls and every use is gated on
// both values being non-empty (DOCKERHUB_LOGIN), so an absent pair is skipped.
const ACTIVE_SECRET_ALLOWLIST = new Set(["GITHUB_TOKEN", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"]);

// disabled: every job must be skipped on the fork (directly guarded, or
//           needing a guarded job with no status function that overrides the skip).
// partial:  named jobs carry the guard; the rest run on the fork.
// active:   carries no fork guard in the file.
// fork:     owned by the fork, not upstream (see "fork-ci workflow" below).
//
// Upstream's workflows are also disabled in the repository's Actions settings,
// so fork-ci.yml is the only CI that runs. The dispositions above still hold
// for the day an upstream workflow is enabled again.
const DISPOSITIONS = {
  "ci-verify.yml": { kind: "active" },
  "fork-ci.yml": { kind: "fork" },
  "greptile.yml": { kind: "disabled", guard: UPSTREAM },
  "main-is-released.yml": { kind: "disabled", guard: UPSTREAM },
  "quality-api-version-watch.yml": { kind: "active" },
  "quality-fuzz-monthly.yml": { kind: "active" },
  "quality-fuzz-nightly.yml": { kind: "active" },
  "quality-go-bench-monthly.yml": { kind: "active" },
  "quality-integration-engines.yml": { kind: "active" },
  "quality-integration-podman.yml": { kind: "active" },
  "quality-integration.yml": { kind: "active" },
  "quality-mutation-monthly.yml": { kind: "partial", guarded: { "update-badge": UPSTREAM } },
  "quality-soak-weekly.yml": { kind: "active" },
  "quality-tri-tool-conformance.yml": { kind: "disabled", guard: UPSTREAM },
  "release-cut.yml": { kind: "disabled", guard: UPSTREAM },
  "release-from-tag.yml": { kind: "disabled", guard: UPSTREAM },
  "security-grype.yml": {
    kind: "partial",
    guarded: { "resolve-latest-release": UPSTREAM },
    skippedByNeeds: ["grype-published-release"],
  },
  "security-scorecard.yml": { kind: "active" },
  "security-zap-baseline.yml": { kind: "disabled", guard: UPSTREAM },
  "starchart.yml": { kind: "disabled", guard: UPSTREAM },
  // Fork-owned. Its own checks are in the "fork release workflow" block below.
  "fork-release.yml": { kind: "fork" },
};

// A status function in a job's own `if:` overrides skip propagation from a
// skipped `needs` job, so the job would run despite its skipped ancestor.
const STATUS_FUNCTION = /\b(always|cancelled|failure|success)\s*\(/u;

function readWorkflow(file) {
  return readFileSync(resolve(workflowsDir, file), "utf8");
}

function parseJobs(source, file) {
  const jobsStart = source.indexOf("\njobs:\n");
  assert.notEqual(jobsStart, -1, `${file}: jobs: block not found`);
  const jobsSource = source.slice(jobsStart + "\njobs:\n".length);
  const headers = [...jobsSource.matchAll(/^ {2}([A-Za-z0-9_-]+):$/gmu)];
  assert.ok(headers.length > 0, `${file}: no job headers found`);
  return headers.map((m, i) => {
    const end = i + 1 < headers.length ? headers[i + 1].index : jobsSource.length;
    const body = jobsSource.slice(m.index, end);
    const ifMatch = body.match(/^ {4}if: (.+)$/mu);
    const needsLine = body.match(/^ {4}needs:(.*)$/mu);
    let needs = [];
    if (needsLine) {
      const rest = needsLine[1].trim();
      // Only the inline forms are understood. A block list would be read as
      // "no needs" and report a job as unguarded, so refuse it loudly.
      assert.ok(rest !== "", `${file}: job ${m[1]} uses a block needs list this test cannot read`);
      needs = rest
        .replace(/^\[/u, "")
        .replace(/\]$/u, "")
        .split(",")
        .map((n) => n.trim())
        .filter(Boolean);
    }
    return { name: m[1], body, jobIf: ifMatch ? ifMatch[1].trim() : null, needs };
  });
}

// A job is skipped on the fork when its own `if:` carries the guard, or when it
// needs a skipped job and has no status function of its own.
function skippedJobs(jobs, guard, guardedNames) {
  const skipped = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const job of jobs) {
      if (skipped.has(job.name)) {
        continue;
      }
      const direct = guardedNames
        ? guardedNames.has(job.name) && guardsJob(job.jobIf, guard.get(job.name))
        : guardsJob(job.jobIf, guard.get("*"));
      const viaNeeds =
        job.needs.some((n) => skipped.has(n)) && !(job.jobIf && STATUS_FUNCTION.test(job.jobIf));
      if (direct || viaNeeds) {
        skipped.add(job.name);
        changed = true;
      }
    }
  }
  return skipped;
}

// The guard must be one of the `&&` conjuncts of the job's `if:`, and the
// expression must hold no `||`: `A || guard` still runs the job whenever A is
// true, which is how a dispatch-only exception would leak back in.
function guardsJob(jobIf, guard) {
  if (!jobIf || jobIf.includes("||")) {
    return false;
  }
  return jobIf.split(" && ").some((conjunct) => conjunct.trim() === guard);
}

function secretsIn(source) {
  return new Set([...source.matchAll(/\bsecrets\.([A-Za-z0-9_]+)/gu)].map((m) => m[1]));
}

describe("fork workflow dispositions", () => {
  it("classifies every workflow file exactly once", () => {
    const onDisk = readdirSync(workflowsDir)
      .filter((f) => f.endsWith(".yml"))
      .sort();
    assert.deepEqual(
      onDisk,
      Object.keys(DISPOSITIONS).sort(),
      "a workflow was added or removed without a fork disposition; classify it in this file",
    );
  });

  for (const [file, disposition] of Object.entries(DISPOSITIONS)) {
    if (disposition.kind !== "disabled") {
      continue;
    }
    it(`${file}: every job is skipped outside the upstream repository`, () => {
      const jobs = parseJobs(readWorkflow(file), file);
      const guard = new Map([["*", disposition.guard]]);
      const skipped = skippedJobs(jobs, guard, null);
      for (const job of jobs) {
        assert.ok(
          skipped.has(job.name),
          `${file}: job ${job.name} would run on the fork (no guard, and no skipped ancestor without a status function)`,
        );
      }
    });
  }

  for (const [file, disposition] of Object.entries(DISPOSITIONS)) {
    if (disposition.kind !== "partial") {
      continue;
    }
    it(`${file}: the named jobs are guarded and the dependents follow them`, () => {
      const jobs = parseJobs(readWorkflow(file), file);
      const guard = new Map(Object.entries(disposition.guarded));
      const skipped = skippedJobs(jobs, guard, new Set(Object.keys(disposition.guarded)));
      for (const name of Object.keys(disposition.guarded)) {
        assert.ok(skipped.has(name), `${file}: job ${name} lost its fork guard`);
      }
      for (const name of disposition.skippedByNeeds ?? []) {
        assert.ok(skipped.has(name), `${file}: job ${name} is no longer skipped through its needs`);
      }
      // Nothing outside the declared set may be skipped, or the fork would
      // silently lose a check this table says it keeps.
      const declared = new Set([
        ...Object.keys(disposition.guarded),
        ...(disposition.skippedByNeeds ?? []),
      ]);
      for (const name of skipped) {
        assert.ok(
          declared.has(name),
          `${file}: job ${name} is skipped but not declared in the disposition`,
        );
      }
    });
  }

  it("active and partial workflows read no secret the fork lacks", () => {
    for (const [file, disposition] of Object.entries(DISPOSITIONS)) {
      if (disposition.kind === "disabled") {
        continue;
      }
      const source = readWorkflow(file);
      const jobs = parseJobs(source, file);
      const guarded =
        disposition.kind === "partial"
          ? skippedJobs(
              jobs,
              new Map(Object.entries(disposition.guarded)),
              new Set(Object.keys(disposition.guarded)),
            )
          : new Set();
      // Secrets used only inside guarded jobs never run on the fork.
      const activeBodies = jobs
        .filter((j) => !guarded.has(j.name))
        .map((j) => j.body)
        .join("\n");
      for (const secret of secretsIn(activeBodies)) {
        assert.ok(
          ACTIVE_SECRET_ALLOWLIST.has(secret),
          `${file}: reads secrets.${secret}, which the fork does not have`,
        );
      }
    }
  });

  it("keeps Docker Hub credentials optional wherever an active job reads them", () => {
    for (const file of ["security-grype.yml"]) {
      const source = readWorkflow(file);
      const reads = [...source.matchAll(/secrets\.DOCKERHUB_(USERNAME|TOKEN)/gu)];
      const gated = [
        ...source.matchAll(
          /DOCKERHUB_LOGIN: \$\{\{ secrets\.DOCKERHUB_USERNAME != '' && secrets\.DOCKERHUB_TOKEN != '' \}\}/gu,
        ),
      ];
      const logins = [...source.matchAll(/if: \$\{\{ env\.DOCKERHUB_LOGIN == 'true' \}\}/gu)];
      assert.ok(reads.length > 0 && gated.length > 0, `${file}: Docker Hub login gate not found`);
      assert.equal(
        logins.length,
        gated.length,
        `${file}: every Docker Hub login must be gated on DOCKERHUB_LOGIN`,
      );
    }
  });

  it("zizmor.yml: each line-scoped ignore still points at the line it was written for", () => {
    // The guards above add lines to release-cut.yml and release-from-tag.yml.
    // zizmor.yml ignores a finding by file and line, so a shifted line turns an
    // accepted finding back into a failure of the workflow-security gate.
    const config = readFileSync(resolve(repoRoot, ".github/zizmor.yml"), "utf8");
    const entries = [...config.matchAll(/^\s+- ([A-Za-z0-9_.-]+\.yml):(\d+)$/gmu)];
    assert.ok(entries.length > 0, "no line-scoped zizmor ignores found");
    for (const [, file, line] of entries) {
      const text = readWorkflow(file).split("\n")[Number(line) - 1] ?? "";
      assert.match(
        text,
        /uses: \.\/\.github\/actions\//u,
        `.github/zizmor.yml ignores ${file}:${line}, which is not the local-action call it was written for`,
      );
    }
  });

  it("security-scorecard.yml: Scorecard results are not published to the OpenSSF API", () => {
    const source = readWorkflow("security-scorecard.yml");
    assert.match(source, /^\s+publish_results: false$/mu);
    assert.doesNotMatch(source, /publish_results: true/u);
  });

  it("ci-verify.yml: the PR gate runs on the epic branch family and is not fork-guarded", () => {
    const source = readWorkflow("ci-verify.yml");
    assert.match(source, /^ {2}push:\n {4}branches: \[[^\]]*'epic\/\*'[^\]]*\]$/mu);
    assert.match(source, /^ {2}pull_request:\n {4}branches: \[[^\]]*'epic\/\*'[^\]]*\]$/mu);
    assert.ok(
      !source.includes("CodesWhat/sockguard'"),
      "ci-verify.yml must not skip any job on the fork",
    );
  });
});

// fork-ci.yml is the fork's only active CI. It must stay on GitHub-owned
// actions pinned by SHA, read-only, secret-free and publish-free, and keep
// running the fork's test, lint and build gates.
describe("fork-ci workflow", () => {
  const FILE = "fork-ci.yml";
  const BRANCHES = "[main, 'epic/*']";

  function topLevelBlock(source, key) {
    const match = source.match(new RegExp(`^${key}:\\n((?:(?: .*)?\\n)*)`, "mu"));
    assert.ok(match, `${FILE}: top-level ${key}: block not found`);
    return match[1].trimEnd();
  }

  it("triggers only on push and pull_request for main and epic/*", () => {
    const on = topLevelBlock(readWorkflow(FILE), "on");
    assert.equal(
      on,
      `  push:\n    branches: ${BRANCHES}\n  pull_request:\n    branches: ${BRANCHES}`,
      `${FILE}: triggers must be exactly push and pull_request on ${BRANCHES}`,
    );
  });

  it("uses only GitHub-owned actions pinned by full commit SHA", () => {
    const uses = [...readWorkflow(FILE).matchAll(/^\s+(?:- )?uses: (.+)$/gmu)].map((m) => m[1]);
    assert.ok(uses.length > 0, `${FILE}: no uses: lines found`);
    for (const ref of uses) {
      assert.match(
        ref,
        /^(?:actions|docker)\/[A-Za-z0-9_.-]+@[0-9a-f]{40} {2}# v\d+\.\d+\.\d+$/u,
        `${FILE}: ${ref} is not a SHA-pinned actions/* or docker/* action`,
      );
    }
  });

  it("grants read-only contents permission and no job widens it", () => {
    const source = readWorkflow(FILE);
    assert.equal(topLevelBlock(source, "permissions"), "  contents: read");
    for (const job of parseJobs(source, FILE)) {
      assert.doesNotMatch(
        job.body,
        /^ {4}permissions:/mu,
        `${FILE}: job ${job.name} sets permissions`,
      );
    }
  });

  it("reads no secrets, logs in nowhere and pushes nothing", () => {
    const source = readWorkflow(FILE);
    assert.deepEqual([...secretsIn(source)], [], `${FILE}: reads a secret`);
    assert.doesNotMatch(
      source,
      /docker\/login-action|docker (?:login|push)|--push\b|^\s+push: true/mu,
    );
  });

  it("runs every job on the fork", () => {
    for (const job of parseJobs(readWorkflow(FILE), FILE)) {
      assert.equal(job.jobIf, null, `${FILE}: job ${job.name} has an if: and may be skipped`);
    }
  });

  it("runs the fork's test, lint and build gates", () => {
    const jobs = new Map(parseJobs(readWorkflow(FILE), FILE).map((j) => [j.name, j.body]));
    const gates = {
      "go-test":
        'run: |\n          DOCKER_CONFIG="$(mktemp -d)"\n          export DOCKER_CONFIG\n          ./scripts/ci/go-test.sh',
      "go-lint": "run: ./scripts/ci/go-lint.sh",
      "go-build": 'run: go build -o "$RUNNER_TEMP/sockguard" ./app/cmd/sockguard/',
      "docker-build": "run: docker build --tag sockguard:fork-ci .",
      node: "run: npx biome check .",
    };
    for (const [name, command] of Object.entries(gates)) {
      assert.ok(
        jobs.get(name)?.includes(command),
        `${FILE}: job ${name} no longer runs ${command}`,
      );
    }
    assert.ok(
      jobs.get("node").includes("run: npm test"),
      `${FILE}: job node no longer runs npm test`,
    );
  });
});

// The fork's own release workflow. It is the one workflow here that publishes,
// so it is held to the release freeze's terms: GitHub-owned actions only, one
// registry, no upstream names in the image, and a tag gate nothing can skip.
const { spawnSync } = await import("node:child_process");
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
const { tmpdir } = await import("node:os");

describe("fork release workflow", () => {
  const FILE = "fork-release.yml";
  const RELEASE_STEP = "Verify release tag";
  const IMAGE_CHECK_STEP = "Verify image, version, labels and attestation";
  const source = () => readWorkflow(FILE);

  function stepScript(stepName) {
    const workflow = source();
    const stepStart = workflow.indexOf(`      - name: ${stepName}\n`);
    assert.notEqual(stepStart, -1, `${FILE}: step ${stepName} not found`);
    const runStart = workflow.indexOf("        run: |\n", stepStart);
    assert.notEqual(runStart, -1, `${FILE}: step ${stepName} has no run block`);
    const end = workflow.indexOf("\n      - name:", runStart + 1);
    const nextJob = workflow.slice(runStart).search(/\n {2}[A-Za-z0-9_-]+:\n/u);
    const stop = [end, nextJob === -1 ? -1 : runStart + nextJob]
      .filter((i) => i !== -1)
      .reduce((a, b) => Math.min(a, b), workflow.length);
    return workflow
      .slice(runStart + "        run: |\n".length, stop)
      .split("\n")
      .map((line) => line.replace(/^ {10}/u, ""))
      .join("\n");
  }

  // The workflow-level env block, parsed, so a test that runs a step gets the
  // values the workflow declares rather than copies of them.
  function workflowEnv() {
    const block = source().match(/^env:\n((?: {2}[A-Z_]+: .+\n)+)/mu);
    assert.ok(block, `${FILE}: workflow env block not found`);
    return Object.fromEntries(
      [...block[1].matchAll(/^ {2}([A-Z_]+): (.+)$/gmu)].map((m) => [m[1], m[2].trim()]),
    );
  }

  function triggerBlock() {
    const block = source().match(/^on:\n((?: {2}.*\n|\s*#.*\n|\n)+?)(?=^\S)/mu);
    assert.ok(block, `${FILE}: on: block not found`);
    return block[1]
      .split("\n")
      .filter((line) => line.trim() !== "" && !line.trim().startsWith("#"))
      .join("\n");
  }

  // GitHub's tag filter glob as a regex: `*` is any run without `/`, `[..]` a
  // class, everything else literal.
  function globToRegex(glob) {
    let out = "";
    for (const ch of glob) {
      if (ch === "*") {
        out += "[^/]*";
      } else if (ch === "[" || ch === "]" || ch === "-") {
        out += ch;
      } else {
        out += ch.replace(/[.*+?^${}()|\\]/gu, "\\$&");
      }
    }
    return new RegExp(`^${out}$`, "u");
  }

  it("triggers only on a fork release tag push and on manual dispatch", () => {
    const triggers = triggerBlock();
    assert.equal(
      triggers,
      "  push:\n    tags: ['[0-9]*.[0-9]*.[0-9]*-wyrd.[0-9]*']\n  workflow_dispatch:",
      `${FILE}: triggers changed; a branch push or schedule would publish without a tag`,
    );
    const pattern = globToRegex("[0-9]*.[0-9]*.[0-9]*-wyrd.[0-9]*");
    for (const tag of ["2.2.10-wyrd.1", "2.3.1-wyrd.12"]) {
      assert.match(tag, pattern, `${FILE}: the trigger misses fork tag ${tag}`);
    }
    for (const tag of ["v2.2.10", "v2.2.10-wyrd.1", "2.2.10", "v3.0.0-rc.1"]) {
      assert.doesNotMatch(tag, pattern, `${FILE}: the trigger fires on ${tag}`);
    }
  });

  it("uses only SHA-pinned actions/* and docker/* actions", () => {
    const uses = [...source().matchAll(/^\s+(?:- )?uses: (\S+)/gmu)].map((m) => m[1]);
    assert.ok(uses.length > 0, `${FILE}: no uses: found`);
    for (const ref of uses) {
      assert.match(
        ref,
        /^(?:actions|docker)\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$/u,
        `${FILE}: ${ref} is not a SHA-pinned GitHub-owned action`,
      );
    }
  });

  it("pins each action to the commit upstream's workflows pin it to", () => {
    // Renovate does not run on the fork. Upstream's Renovate bumps arrive
    // through the upstream rebase, and this check then fails until the fork's
    // pins follow, so they cannot silently age.
    const upstreamPins = new Map();
    for (const [file, disposition] of Object.entries(DISPOSITIONS)) {
      if (disposition.kind === "fork") {
        continue;
      }
      for (const m of readWorkflow(file).matchAll(/uses: ([^@\s]+)@([0-9a-f]{40})/gu)) {
        const pins = upstreamPins.get(m[1]) ?? new Set();
        pins.add(m[2]);
        upstreamPins.set(m[1], pins);
      }
    }
    for (const m of source().matchAll(/uses: ([^@\s]+)@([0-9a-f]{40})/gu)) {
      const pins = upstreamPins.get(m[1]);
      assert.ok(
        pins,
        `${FILE}: ${m[1]} is used by no upstream workflow, so nothing keeps it current`,
      );
      assert.ok(
        pins.has(m[2]),
        `${FILE}: ${m[1]}@${m[2]} differs from upstream's pin ${[...pins].join(", ")}`,
      );
    }
  });

  it("publishes only to ghcr.io/wyrd-company/sockguard and names upstream only as the tag source", () => {
    const text = source();
    assert.equal(workflowEnv().IMAGE, "ghcr.io/wyrd-company/sockguard");
    assert.match(text, /^ {10}images: \$\{\{ env\.IMAGE \}\}$/mu);
    for (const registry of ["docker.io", "quay.io", "index.docker.io", "registry-1.docker.io"]) {
      assert.ok(!text.includes(registry), `${FILE}: names registry ${registry}`);
    }
    const upstreamLines = text.split("\n").filter((line) => /codeswhat/iu.test(line));
    assert.deepEqual(
      upstreamLines,
      ["  UPSTREAM_URL: https://github.com/CodesWhat/sockguard.git"],
      `${FILE}: only the upstream tag source may name upstream`,
    );
    assert.doesNotMatch(
      text,
      /secrets\.(?!GITHUB_TOKEN\b)/u,
      `${FILE}: reads a secret other than GITHUB_TOKEN`,
    );
  });

  it("tags the image with the verified fork version and latest, nothing else", () => {
    const tags = source().match(/^ {10}tags: \|\n((?: {12}.+\n)+)/mu);
    assert.ok(tags, `${FILE}: docker metadata tags block not found`);
    const lines = tags[1]
      .trim()
      .split("\n")
      .map((line) => line.trim());
    assert.equal(lines.length, 2, `${FILE}: image tags changed: ${lines.join(" | ")}`);
    assert.match(lines[0], /^type=raw,value=\$\{\{ needs\.verify\.outputs\.version \}\}$/u);
    assert.equal(lines[1], "type=raw,value=latest");
  });

  it("restores no build cache into the publishing job", () => {
    assert.doesNotMatch(source(), /cache-(?:from|to)|type=gha/u);
  });

  it("builds only after the tag is verified, and no job condition can skip that", () => {
    const jobs = parseJobs(source(), FILE);
    assert.deepEqual(
      jobs.map((j) => [j.name, j.needs]),
      [
        ["verify", []],
        ["image", ["verify"]],
        ["verify-image", ["verify", "image"]],
      ],
    );
    for (const job of jobs) {
      assert.equal(
        job.jobIf,
        null,
        `${FILE}: job ${job.name} has an if:, which can run it past a failed tag check`,
      );
    }
  });

  it("the tag step refuses a branch run and hands a tag to scripts/fork-release-tag.sh", () => {
    const script = stepScript(RELEASE_STEP);
    const dir = mkdtempSync(resolve(tmpdir(), "sockguard-fork-release-step-"));
    try {
      mkdirSync(resolve(dir, "scripts"));
      const log = resolve(dir, "calls");
      writeFileSync(
        resolve(dir, "scripts/fork-release-tag.sh"),
        `printf '%s\\n' "$*" >> "${log}"\n`,
      );
      const run = (refType) =>
        spawnSync("bash", ["-c", script], {
          cwd: dir,
          env: { PATH: process.env.PATH, REF_TYPE: refType, RELEASE_TAG: "2.2.10-wyrd.1" },
          encoding: "utf8",
        });
      const branch = run("branch");
      assert.equal(branch.status, 1);
      assert.match(branch.stdout, /Run this workflow on a release tag, not a branch/u);
      assert.throws(() => readFileSync(log, "utf8"), /ENOENT/u, "the tag check ran on a branch");
      const tag = run("tag");
      assert.equal(tag.status, 0, tag.stderr);
      assert.equal(readFileSync(log, "utf8"), "2.2.10-wyrd.1\n");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the image check runs scripts/fork-verify-published-image.sh on the verified tag and pushed digest", () => {
    const text = source();
    const step = text.slice(text.indexOf(`      - name: ${IMAGE_CHECK_STEP}\n`));
    assert.match(
      step,
      /^ {8}run: bash scripts\/fork-verify-published-image\.sh --tag "\$\{VERSION\}" --digest "\$\{DIGEST\}"$/mu,
    );
    assert.match(step, /^ {10}VERSION: \$\{\{ needs\.verify\.outputs\.version \}\}$/mu);
    assert.match(step, /^ {10}DIGEST: \$\{\{ needs\.image\.outputs\.digest \}\}$/mu);
    // The script derives the image and signer from the runner's repository;
    // the workflow must not override it.
    assert.doesNotMatch(text, /GITHUB_REPOSITORY:/u);
  });

  it("Dockerfile: image labels name the fork, not upstream", () => {
    const labels = readFileSync(resolve(repoRoot, "Dockerfile"), "utf8")
      .split("\n")
      .filter((line) => line.startsWith("LABEL "));
    assert.ok(labels.length > 0, "Dockerfile: no LABEL lines found");
    for (const line of labels) {
      assert.doesNotMatch(line, /codeswhat/iu, `Dockerfile: ${line}`);
    }
    assert.ok(
      labels.includes(
        'LABEL org.opencontainers.image.source="https://github.com/wyrd-company/sockguard"',
      ),
    );
    assert.ok(labels.includes('LABEL maintainer="wyrd-company"'));
  });
});
