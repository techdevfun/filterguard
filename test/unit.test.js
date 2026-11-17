/**
 * Unit tests: filter parser, permission scoring, uBO version gate,
 * baseline matching, manifest parsing.
 * All fixture data is synthetic and labelled as such.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { parseFilterFile, ruleSha256 } from "../dist/filters.js";
import { compareVersions, uboVerdict } from "../dist/versions.js";
import { scoreExtension } from "../dist/scoring.js";

const HIGH = "HIGH";
const MEDIUM = "MEDIUM";
const LOW = "LOW";
const NONE = "NONE";

function findingsFor(text) {
  return parseFilterFile(text).findings;
}

test("parser: planted trusted-rpnt scriptlet is HIGH (GHSA vector)", () => {
  const rules = findingsFor(
    "example.com#%#//scriptlet('trusted-rpnt', 'test', 'test')\n",
  );
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, HIGH);
  assert.equal(rules[0].trustedScriptlet, "trusted-rpnt");
  assert.equal(rules[0].kind, "scriptlet");
});

test("parser: ##+js trusted-set injection is HIGH", () => {
  const rules = findingsFor(
    "example.com##+js(trusted-set, localStorage, x, 1)\n",
  );
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, HIGH);
  assert.equal(rules[0].trustedScriptlet, "trusted-set");
});

test("parser: !#trusted-scriptlet marker line is HIGH", () => {
  const rules = findingsFor(
    "!#trusted-scriptlet('trusted-replace-xhr-response')\n",
  );
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, HIGH);
});

test("parser: $scriptlet option with a trusted name is HIGH", () => {
  const rules = findingsFor("||example.com^$scriptlet(trusted-set-cookie)\n");
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, HIGH);
});

test("parser: broad $redirect with no domain is HIGH", () => {
  const rules = findingsFor("*$redirect=noop.js\n");
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, HIGH);
  assert.equal(rules[0].kind, "network");
});

test("parser: broad $csp with no domain is HIGH", () => {
  const rules = findingsFor("$csp=script-src 'none'\n");
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, HIGH);
});

test("parser: domain-scoped $redirect is not flagged", () => {
  const rules = findingsFor("||example.com^$redirect=noop.js\n");
  assert.equal(rules.length, 0);
});

test("parser: broad $document block-all is MEDIUM", () => {
  const rules = findingsFor("*$document\n");
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, MEDIUM);
});

test("parser: exception rules are never flagged", () => {
  const rules = findingsFor(
    "@@||example.com^$document\n@@example.com#%#//scriptlet('trusted-rpnt', 'a', 'b')\n",
  );
  assert.equal(rules.length, 0);
});

test("parser: cosmetic hiding rules are never flagged", () => {
  const rules = findingsFor(
    "example.com##.ad-banner\nexample.com#@#.sponsored\n",
  );
  assert.equal(rules.length, 0);
});

test("parser: ordinary network block rules are never flagged", () => {
  const rules = findingsFor(
    "||ads.example.com^\n||tracker.example.net^$third-party\n",
  );
  assert.equal(rules.length, 0);
});

test("parser: comments and empty lines are skipped, not findings", () => {
  const parsed = parseFilterFile(
    "! a comment\n\n[Adblock Plus 2.0]\n||ads.example.com^\n",
  );
  assert.equal(parsed.parsedLines, 1);
  assert.equal(parsed.findings.length, 0);
});

test("parser: malformed rule becomes a counted warning, not a crash", () => {
  const parsed = parseFilterFile("||example.com^$scriptlet(trusted-set\n");
  assert.equal(parsed.warnings.length, 1);
  assert.match(parsed.warnings[0], /unbalanced/);
  assert.equal(parsed.rules[0].kind, "unknown");
  assert.equal(parsed.findings.length, 0);
});

test("parser: non-trusted scriptlet scoped to a domain is MEDIUM", () => {
  const rules = findingsFor(
    "example.com#%#//scriptlet('set-cookie', 'a', 'b')\n",
  );
  assert.equal(rules.length, 1);
  assert.equal(rules[0].severity, MEDIUM);
  assert.equal(rules[0].trustedScriptlet, null);
});

test("parser: same rule text with different whitespace shares one sha256", () => {
  const a = ruleSha256("example.com##+js(trusted-set,  x,  1)");
  const b = ruleSha256("example.com##+js(trusted-set, x, 1)");
  assert.equal(a, b);
});

test("versions: compareVersions orders releases and pre-releases", () => {
  assert.ok(compareVersions("1.75.2", "1.75.4") < 0);
  assert.ok(compareVersions("1.76.4", "1.76.4") === 0);
  assert.ok(compareVersions("1.76.5b0", "1.76.4") > 0);
  assert.ok(compareVersions("1.76.5b0", "1.76.5") < 0);
  assert.ok(compareVersions("1.76.0", "1.75.4") > 0);
});

test("versions: uBO 1.75.2 is vulnerable, 1.76.4 is ok, 1.75.4 warns", () => {
  assert.equal(uboVerdict("1.75.2").status, "vulnerable");
  assert.equal(uboVerdict("1.76.4").status, "ok");
  assert.equal(uboVerdict("1.76.5b0").status, "ok");
  assert.equal(uboVerdict("1.75.4").status, "patched-older");
  assert.equal(uboVerdict("1.76.0").status, "patched-older");
});

function fakeExt(overrides) {
  return {
    id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    name: "Test Ext",
    version: "1.0.0",
    browser: "chrome",
    profile: "/tmp/fake/Default",
    manifestVersion: 3,
    permissions: [],
    hostPermissions: [],
    optionalPermissions: [],
    contentScripts: [],
    updateUrl: "https://clients2.google.com/service/update2/crx",
    description: null,
    manifestReadable: true,
    ...overrides,
  };
}

test("scoring: <all_urls> host access alone is HIGH", () => {
  const v = scoreExtension(fakeExt({ hostPermissions: ["<all_urls>"] }));
  assert.equal(v.severity, HIGH);
  assert.ok(v.score >= 40);
});

test("scoring: debugger + management combine to HIGH", () => {
  const v = scoreExtension(
    fakeExt({ permissions: ["debugger", "management"] }),
  );
  assert.equal(v.severity, HIGH);
  assert.equal(v.score, 55);
});

test("scoring: tabs + webNavigation combo is MEDIUM", () => {
  const v = scoreExtension(fakeExt({ permissions: ["tabs", "webNavigation"] }));
  assert.equal(v.severity, MEDIUM);
  assert.equal(v.score, 15);
});

test("scoring: off-store update URL adds a MEDIUM-weight finding", () => {
  const v = scoreExtension(
    fakeExt({ updateUrl: "https://updates.example.com/crx" }),
  );
  assert.ok(v.findings.some((f) => f.key === "update:off-store"));
  assert.equal(v.severity, MEDIUM);
});

test("scoring: MV2 on Chromium adds a LOW finding", () => {
  const v = scoreExtension(fakeExt({ manifestVersion: 2 }));
  assert.equal(v.severity, LOW);
  assert.ok(v.findings.some((f) => f.key === "manifest:v2"));
});

test("scoring: clean MV3 extension with no permissions is OK", () => {
  const v = scoreExtension(fakeExt({}));
  assert.equal(v.severity, NONE);
  assert.equal(v.score, 0);
  assert.equal(v.findings.length, 0);
});

test("scoring: uBO 1.75.2 is HIGH, uBO 1.76.4 is OK", () => {
  const old = scoreExtension(
    fakeExt({
      id: "cjpalhdlnbpafiamejdnhcphjbkeiagm",
      name: "uBlock Origin",
      version: "1.75.2",
    }),
  );
  assert.equal(old.severity, HIGH);
  assert.ok(old.findings.some((f) => f.key === "ubo:vulnerable"));
  const fixed = scoreExtension(
    fakeExt({
      id: "cjpalhdlnbpafiamejdnhcphjbkeiagm",
      name: "uBlock Origin",
      version: "1.76.4",
    }),
  );
  assert.equal(fixed.severity, NONE);
  assert.equal(fixed.ubo.status, "ok");
});

test("scoring: content script on all urls at document_start is a finding", () => {
  const v = scoreExtension(
    fakeExt({
      contentScripts: [{ matches: ["<all_urls>"], runAt: "document_start" }],
    }),
  );
  assert.ok(
    v.findings.some((f) => f.key === "content-script:all-urls-document-start"),
  );
  assert.equal(v.severity, MEDIUM);
});
