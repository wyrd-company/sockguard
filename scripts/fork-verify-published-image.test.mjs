import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const script = resolve(repoRoot, "scripts/fork-verify-published-image.sh");
const workflowPath = resolve(repoRoot, ".github/workflows/fork-release.yml");
const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-fork-verify-image-"));

after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

const DIGEST = `sha256:${"a".repeat(64)}`;
const TAG = "2.2.10-wyrd.1";
const FORK = "wyrd-company/sockguard";

// Every test states GITHUB_REPOSITORY itself, set or unset, so the result does
// not depend on the runner that runs it.
// null and undefined both mean unset.
function baseEnv(repository) {
  const { GITHUB_REPOSITORY: _ignored, ...env } = process.env;
  return repository == null ? env : { ...env, GITHUB_REPOSITORY: repository };
}

function dryRun(repository) {
  return spawnSync("bash", [script, "--dry-run", "--tag", TAG, "--digest", DIGEST], {
    env: baseEnv(repository),
    encoding: "utf8",
  });
}

let count = 0;

// Runs the real checks against stub docker and gh commands that answer from
// env and record every invocation.
function runChecks(overrides = {}, repository = FORK) {
  count += 1;
  const dir = join(fixtureRoot, String(count));
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  const log = join(dir, "calls");
  writeFileSync(
    join(bin, "docker"),
    `#!/bin/bash
printf 'docker %s\\n' "$*" >> "${log}"
case "$1 $2" in
  "buildx imagetools")
    if [[ "$4" == *@* ]]; then printf '%s\\n' "$STUB_INDEX"; else printf '{"digest":"%s"}\\n' "$STUB_TAG_DIGEST"; fi ;;
  "pull --quiet") ;;
  "run --rm") printf '%s\\n' "$STUB_VERSION_JSON" ;;
  "image inspect")
    if [[ "$5" == *source* ]]; then printf '%s\\n' "$STUB_SOURCE"; else printf '%s\\n' "$STUB_LABELS"; fi ;;
  *) echo "unexpected docker $*" >&2; exit 99 ;;
esac
`,
  );
  writeFileSync(join(bin, "gh"), `#!/bin/bash\nprintf 'gh %s\\n' "$*" >> "${log}"\n`);
  chmodSync(join(bin, "docker"), 0o755);
  chmodSync(join(bin, "gh"), 0o755);
  const env = {
    ...baseEnv(repository),
    PATH: `${bin}:${process.env.PATH}`,
    STUB_INDEX: JSON.stringify({
      manifests: [
        { platform: { os: "linux", architecture: "amd64" } },
        { platform: { os: "linux", architecture: "arm64" } },
        { platform: { os: "unknown", architecture: "unknown" } },
      ],
    }),
    STUB_TAG_DIGEST: DIGEST,
    STUB_VERSION_JSON: `{"version":"${TAG}"}`,
    STUB_SOURCE: "https://github.com/wyrd-company/sockguard",
    STUB_LABELS: '{"maintainer":"wyrd-company"}',
    ...overrides,
  };
  const result = spawnSync("bash", [script, "--tag", TAG, "--digest", DIGEST], {
    env,
    encoding: "utf8",
  });
  const calls = existsSync(log) ? readFileSync(log, "utf8") : "";
  return { ...result, calls };
}

const ATTESTATION = new RegExp(
  `^gh attestation verify oci://ghcr\\.io/wyrd-company/sockguard@${DIGEST} --repo wyrd-company/sockguard --signer-workflow wyrd-company/sockguard/\\.github/workflows/fork-release\\.yml --cert-oidc-issuer https://token\\.actions\\.githubusercontent\\.com$`,
  "mu",
);

describe("fork-verify-published-image.sh", () => {
  for (const [label, repository] of [
    ["the runner's GITHUB_REPOSITORY", FORK],
    ["no GITHUB_REPOSITORY", undefined],
  ]) {
    it(`plans the fork image, signer and issuer under ${label}`, () => {
      const result = dryRun(repository);
      assert.equal(result.status, 0, result.stderr);
      assert.match(
        result.stdout,
        /^ {2}image:\s+ghcr\.io\/wyrd-company\/sockguard@sha256:a{64}$/mu,
      );
      assert.match(
        result.stdout,
        /^ {2}signer workflow:\s+wyrd-company\/sockguard\/\.github\/workflows\/fork-release\.yml$/mu,
      );
      assert.match(
        result.stdout,
        /^ {2}issuer:\s+https:\/\/token\.actions\.githubusercontent\.com$/mu,
      );
      assert.doesNotMatch(result.stdout, /codeswhat|docker\.io|quay\.io/iu);
    });
  }

  it("lowercases the repository for the ghcr path and keeps its case for the signer", () => {
    const result = dryRun("Wyrd-Company/Sockguard");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /ghcr\.io\/wyrd-company\/sockguard@/u);
    assert.match(result.stdout, /Wyrd-Company\/Sockguard\/\.github\/workflows\/fork-release\.yml/u);
  });

  it("agrees with fork-release.yml on the image and the signing workflow", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const image = workflow.match(/^ {2}IMAGE: (\S+)$/mu);
    assert.ok(image, "fork-release.yml: IMAGE not found");
    assert.match(
      dryRun(FORK).stdout,
      new RegExp(`^ {2}image:\\s+${image[1].replace(/[./]/gu, "\\$&")}@`, "mu"),
    );
    assert.match(workflow, /^ {2}PLATFORMS: linux\/amd64,linux\/arm64$/mu);
  });

  it("refuses a missing tag or digest, and a digest that is not sha256", () => {
    for (const args of [
      ["--tag", TAG],
      ["--digest", DIGEST],
      ["--tag", TAG, "--digest", "latest"],
    ]) {
      const result = spawnSync("bash", [script, "--dry-run", ...args], {
        env: baseEnv(FORK),
        encoding: "utf8",
      });
      assert.equal(result.status, 2, `${args.join(" ")} was accepted`);
    }
  });

  it("passes a correct image and verifies its attestation for the signer and issuer", () => {
    const result = runChecks();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.calls, ATTESTATION);
    assert.match(
      result.calls,
      /^docker run --rm ghcr\.io\/wyrd-company\/sockguard@sha256:a+ version -o json$/mu,
    );
  });

  it("verifies the same fork image and signer with no GITHUB_REPOSITORY", () => {
    // null, not undefined: undefined would take runChecks' default, the fork.
    const result = runChecks({}, null);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.calls, ATTESTATION);
  });

  for (const [name, overrides, reason] of [
    [
      "a missing platform",
      {
        STUB_INDEX: JSON.stringify({
          manifests: [{ platform: { os: "linux", architecture: "amd64" } }],
        }),
      },
      /Published platforms 'linux\/amd64'/u,
    ],
    [
      "a tag on another digest",
      { STUB_TAG_DIGEST: `sha256:${"b".repeat(64)}` },
      /is sha256:b+, expected/u,
    ],
    ["a wrong version", { STUB_VERSION_JSON: '{"version":"dev"}' }, /reports version 'dev'/u],
    [
      "an upstream source label",
      { STUB_SOURCE: "https://github.com/CodesWhat/sockguard" },
      /Source label 'https:\/\/github\.com\/CodesWhat\/sockguard'/u,
    ],
    [
      "another label naming upstream",
      { STUB_LABELS: '{"maintainer":"CodesWhat"}' },
      /An image label names upstream/u,
    ],
  ]) {
    it(`refuses ${name} before verifying the attestation`, () => {
      const result = runChecks(overrides);
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.match(result.stdout, reason);
      assert.doesNotMatch(result.calls, /^gh attestation/mu);
    });
  }
});
