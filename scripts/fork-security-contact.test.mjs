import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

// The wyrd-company fork takes vulnerability reports through GitHub private
// vulnerability reporting on its own repository. Upstream's addresses must not
// come back with an upstream rebase.

const repoRoot = resolve(import.meta.dirname, "..");
const ADVISORY_URL = "https://github.com/wyrd-company/sockguard/security/advisories/new";
const UPSTREAM_CONTACTS = [
  /security@getsockguard\.com/iu,
  /hi@getsockguard\.com/iu,
  /mailto:/iu,
  /github\.com\/CodesWhat\/sockguard\/security/iu,
];

function read(path) {
  return readFileSync(resolve(repoRoot, path), "utf8");
}

describe("fork security contact", () => {
  for (const path of ["SECURITY.md", ".github/ISSUE_TEMPLATE/config.yml"]) {
    it(`${path}: names the fork's private vulnerability reporting and no upstream contact`, () => {
      const text = read(path);
      assert.ok(text.includes(ADVISORY_URL), `${path}: the fork's advisory URL is missing`);
      for (const contact of UPSTREAM_CONTACTS) {
        assert.doesNotMatch(text, contact, `${path}: names an upstream contact`);
      }
    });
  }

  it(".github/ISSUE_TEMPLATE/config.yml: the security link is the fork's advisory form", () => {
    const text = read(".github/ISSUE_TEMPLATE/config.yml");
    const entry = text.match(/- name: Report a Security Vulnerability\n {4}url: (\S+)/u);
    assert.ok(entry, "security contact link not found");
    assert.equal(entry[1], ADVISORY_URL);
  });

  it("SECURITY.md: the in-scope image is the fork's image", () => {
    const text = read("SECURITY.md");
    assert.match(text, /`ghcr\.io\/wyrd-company\/sockguard:<tag>`/u);
    assert.doesNotMatch(text, /ghcr\.io\/codeswhat/iu);
  });
});
