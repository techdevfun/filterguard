/**
 * E2E tests: run the built CLI against a SYNTHETIC fixture profile
 * and a SYNTHETIC My filters file in tmp. No real browser data.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

const UBO_ID = "cjpalhdlnbpafiamejdnhcphjbkeiagm";
const NOTE_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async function fixtureProfile() {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  const profile = join(root, "Default");
  const uboDir = join(profile, "Extensions", UBO_ID, "1.75.2");
  const noteDir = join(profile, "Extensions", NOTE_ID, "2.3.0");
  await mkdir(uboDir, { recursive: true });
  await mkdir(noteDir, { recursive: true });
  await writeFile(
    join(uboDir, "manifest.json"),
    JSON.stringify({
      manifest_version: 2,
      name: "uBlock Origin",
      version: "1.75.2",
      description: "Finally, an efficient blocker. Easy on CPU and memory.",
      permissions: [
        "webRequest",
        "webRequestBlocking",
        "storage",
        "unlimitedStorage",
      ],
      host_permissions: ["<all_urls>"],
      update_url: "https://clients2.google.com/service/update2/crx",
    }),
  );
  await writeFile(
    join(noteDir, "manifest.json"),
    JSON.stringify({
      manifest_version: 3,
      name: "Quick Notes Everywhere",
      version: "2.3.0",
      description: "Take notes on any page.",
      permissions: ["storage", "tabs"],
      host_permissions: ["<all_urls>"],
      content_scripts: [
        {
          matches: ["<all_urls>"],
          js: ["content.js"],
          run_at: "document_start",
        },
      ],
      update_url: "https://clients2.google.com/service/update2/crx",
    }),
  );
  return { root, profile };
}

const PLANTED = "example.com#%#//scriptlet('trusted-rpnt', 'test', 'test')";
const OWN_TRUSTED = "example.org##+js(trusted-set, localStorage, myFlag, 1)";

async function fixtureFilters(root, lines, name = "my-filters.txt") {
  const path = join(root, name);
  await writeFile(path, lines.join("\n") + "\n", "utf8");
  return path;
}

async function runCli(args, cwd) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args], {
      cwd,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return {
      code: err.code ?? 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

test("e2e: scan flags vulnerable uBO 1.75.2 and the all-urls note extension (exit 1)", async (t) => {
  const { root, profile } = await fixtureProfile();
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(["scan", "--profile-dir", profile], root);
  assert.equal(res.code, 1);
  assert.match(res.stdout, /uBlock Origin 1\.75\.2/);
  assert.match(res.stdout, /VULNERABLE/);
  assert.match(res.stdout, /Quick Notes Everywhere/);
  assert.match(res.stdout, /HIGH 3/);
});

test("e2e: scan --json shape", async (t) => {
  const { root, profile } = await fixtureProfile();
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(["scan", "--profile-dir", profile, "--json"], root);
  assert.equal(res.code, 1);
  const data = JSON.parse(res.stdout);
  assert.equal(data.tool, "filterguard");
  assert.equal(data.version, "0.1.0");
  assert.equal(data.command, "scan");
  assert.equal(typeof data.summary.high, "number");
  assert.ok(data.summary.high >= 2);
  assert.ok(Array.isArray(data.findings));
  assert.ok(data.findings.every((f) => typeof f.key === "string"));
});

test("e2e: scan on an empty profile dir exits 2", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(
    ["scan", "--profile-dir", join(root, "Default")],
    root,
  );
  assert.equal(res.code, 2);
  assert.match(res.stderr, /no browser profile found/);
});

test("e2e: filters flags the planted trusted rule and not ordinary rules (exit 1)", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = await fixtureFilters(root, [
    "! My filters - SYNTHETIC fixture",
    "||ads.example.com^",
    "example.com##.ad-banner",
    "@@||example.com^$document",
    PLANTED,
  ]);
  const res = await runCli(["filters", "--filters", file], root);
  assert.equal(res.code, 1);
  assert.match(res.stdout, /trusted-rpnt/);
  assert.match(res.stdout, /HIGH 1/);
  assert.match(res.stdout, /rules parsed 4/);
});

test("e2e: filters on a clean list exits 0", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = await fixtureFilters(root, [
    "||ads.example.com^",
    "example.com##.ad-banner",
  ]);
  const res = await runCli(["filters", "--filters", file], root);
  assert.equal(res.code, 0);
  assert.match(res.stdout, /no findings/);
});

test("e2e: filters with a missing file exits 2", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(
    ["filters", "--filters", join(root, "nope.txt")],
    root,
  );
  assert.equal(res.code, 2);
});

test("e2e: check fails, then passes after the planted rule is removed and the own rule is allowlisted", async (t) => {
  const { root, profile } = await fixtureProfile();
  t.after(() => rm(root, { recursive: true, force: true }));
  const dirty = await fixtureFilters(root, [
    "||ads.example.com^",
    PLANTED,
    OWN_TRUSTED,
  ]);
  const before = await runCli(
    ["check", "--profile-dir", profile, "--filters", dirty],
    root,
  );
  assert.equal(before.code, 1);
  assert.match(before.stdout, /trusted-rpnt/);

  // Fix the fixture the way a user would: update uBO to 1.76.4,
  // delete the planted rule, keep the rule the user wrote.
  const uboManifest = join(
    profile,
    "Extensions",
    UBO_ID,
    "1.76.4",
    "manifest.json",
  );
  await mkdir(join(profile, "Extensions", UBO_ID, "1.76.4"), {
    recursive: true,
  });
  await writeFile(
    uboManifest,
    JSON.stringify({
      manifest_version: 2,
      name: "uBlock Origin",
      version: "1.76.4",
      permissions: ["webRequest", "storage"],
      host_permissions: ["<all_urls>"],
      update_url: "https://clients2.google.com/service/update2/crx",
    }),
  );
  await rm(join(profile, "Extensions", UBO_ID, "1.75.2"), {
    recursive: true,
    force: true,
  });
  const clean = await fixtureFilters(root, ["||ads.example.com^", OWN_TRUSTED]);
  const baseline = join(root, "baseline.json");
  // Baseline the reviewed state: the updated extension set (scan) plus
  // the one trusted rule the user wrote (filters). --save-baseline
  // merges into the same file, so one baseline covers both halves.
  const saveScan = await runCli(
    ["scan", "--profile-dir", profile, "--save-baseline", baseline],
    root,
  );
  assert.equal(
    saveScan.code,
    1,
    `scan baseline save should report findings: ${saveScan.stdout}`,
  );
  const save = await runCli(
    ["filters", "--filters", clean, "--save-baseline", baseline],
    root,
  );
  assert.equal(
    save.code,
    1,
    `save-baseline should still report the own rule: ${save.stdout}`,
  );
  const after = await runCli(
    [
      "check",
      "--profile-dir",
      profile,
      "--filters",
      clean,
      "--baseline",
      baseline,
    ],
    root,
  );
  assert.equal(
    after.code,
    0,
    `check should pass on the reviewed state: ${after.stdout}`,
  );
  assert.doesNotMatch(after.stdout, /trusted-rpnt/);
  assert.doesNotMatch(after.stdout, /trusted-set/);
  assert.match(after.stdout, /accepted by baseline/);
  const baselineData = JSON.parse(await readFile(baseline, "utf8"));
  // 4 extension findings + 1 filter finding, deduped by key.
  assert.equal(baselineData.entries.length, 5);
});

test("e2e: diff reports new and fixed findings, exit 1 on new HIGH", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clean = await fixtureFilters(root, ["||ads.example.com^"], "clean.txt");
  const dirty = await fixtureFilters(
    root,
    ["||ads.example.com^", PLANTED],
    "dirty.txt",
  );
  const baseA = join(root, "a.json");
  const baseB = join(root, "b.json");
  await runCli(["filters", "--filters", clean, "--save-baseline", baseA], root);
  await runCli(["filters", "--filters", dirty, "--save-baseline", baseB], root);
  const res = await runCli(["diff", baseA, baseB], root);
  assert.equal(res.code, 1);
  assert.match(res.stdout, /new: 1/);
  assert.match(res.stdout, /trusted-rpnt/);
  const back = await runCli(["diff", baseB, baseA], root);
  assert.equal(back.code, 0);
  assert.match(back.stdout, /fixed: 1/);
});

test("e2e: explain dissects the planted rule", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(["explain", PLANTED], root);
  assert.equal(res.code, 1);
  assert.match(res.stdout, /trusted-rpnt/);
  assert.match(res.stdout, /GHSA-cmqw-9r2w-6wv2/);
  assert.match(res.stdout, /what to do/);
});

test("e2e: explain finds an extension by id", async (t) => {
  const { root, profile } = await fixtureProfile();
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(["explain", UBO_ID, "--profile-dir", profile], root);
  assert.equal(res.code, 1);
  assert.match(res.stdout, /uBlock Origin 1\.75\.2/);
  assert.match(res.stdout, /VULNERABLE/);
});

test("e2e: init writes a valid config", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const res = await runCli(["init"], root);
  assert.equal(res.code, 0);
  const config = JSON.parse(
    await readFile(join(root, "filterguard.config.json"), "utf8"),
  );
  assert.equal(config.version, 1);
  assert.equal(config.baselineFile, "filterguard.baseline.json");
  assert.match(res.stdout, /My filters/);
});

test("e2e: --help and --version exit 0", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "filterguard-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const help = await runCli(["--help"], root);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /GHSA-cmqw-9r2w-6wv2/);
  const version = await runCli(["--version"], root);
  assert.equal(version.code, 0);
  assert.match(version.stdout, /filterguard 0\.1\.0/);
});
