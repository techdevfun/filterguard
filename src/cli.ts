#!/usr/bin/env node
/**
 * filterguard - audit what is ALREADY in your browser.
 *
 * Usage:
 *   filterguard scan [--profile-dir <dir>] [--browser <name>] [--json]
 *              [--save-baseline <file>]
 *   filterguard filters [--filters <file>] [--json] [--save-baseline <file>]
 *   filterguard check [--profile-dir <dir>] [--filters <file>]
 *              [--baseline <file>] [--json]
 *   filterguard diff <baseline-a> <baseline-b> [--json]
 *   filterguard explain <rule-or-extension-id> [--profile-dir <dir>]
 *              [--filters <file>] [--json]
 *   filterguard init
 *   filterguard --help | --version
 *
 * Exit codes: 0 = no HIGH finding; 1 = >=1 HIGH finding;
 * 2 = usage error / nothing to audit.
 *
 * The tool is 100% local for scan/filters: it reads extension
 * manifest.json files and the filter file you point at, and makes
 * no network calls. It never deletes anything.
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  diffBaselines,
  emptyBaseline,
  loadBaseline,
  saveBaselineMerged,
  type Baseline,
} from "./baseline.js";
import { VERSION } from "./cli-version.js";
import { CONFIG_FILE, loadConfig, writeDefaultConfig } from "./config.js";
import { parseFilterFile, ruleSha256, type ParsedRule } from "./filters.js";
import { discoverProfiles, knownProfilePaths } from "./profiles.js";
import {
  findingsFromExtensions,
  findingsFromRules,
  renderHuman,
  renderJson,
  SCOPE_FOOTER,
  summarize,
  type Finding,
} from "./report.js";
import { scoreExtension, type ExtensionVerdict } from "./scoring.js";
import {
  GHSA_ID,
  GHSA_URL,
  RECOMMENDED_UBO_VERSION,
  UBO_RELEASES_URL,
} from "./versions.js";

function usage(): string {
  return [
    `filterguard ${VERSION} - audit extensions and My filters for planted trusted scriptlets`,
    "",
    "Usage:",
    "  filterguard scan [--profile-dir <dir>] [--browser <name>] [--json]",
    "             [--save-baseline <file>]",
    "  filterguard filters [--filters <file>] [--json] [--save-baseline <file>]",
    "  filterguard check [--profile-dir <dir>] [--filters <file>]",
    "             [--baseline <file>] [--json]",
    "  filterguard diff <baseline-a> <baseline-b> [--json]",
    "  filterguard explain <rule-or-extension-id> [--profile-dir <dir>]",
    "             [--filters <file>] [--json]",
    "  filterguard init",
    "  filterguard --help | --version",
    "",
    "Exit codes: 0 = no HIGH finding, 1 = >=1 HIGH finding,",
    "  2 = usage error or nothing to audit.",
    "",
    "Why this exists: updating uBlock Origin past " + GHSA_ID + " closes the",
    "hole, but does NOT remove a trusted filter the attack already planted.",
    "That rule sits in your own My filters list until you check it.",
    "Recommended uBlock Origin version: " +
      RECOMMENDED_UBO_VERSION +
      " or newer.",
    "See " + GHSA_URL,
    "Releases: " + UBO_RELEASES_URL,
    "",
    SCOPE_FOOTER,
    "Install from source for now (npm package pending): see README.",
  ].join("\n");
}

interface Flags {
  positional: string[];
  json: boolean;
  profileDir?: string;
  browser?: string;
  filters?: string;
  baseline?: string;
  saveBaseline?: string;
  config?: string;
}

function parseFlags(argv: string[]): Flags | null {
  const flags: Flags = { positional: [], json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") flags.json = true;
    else if (a === "--profile-dir") flags.profileDir = argv[++i];
    else if (a === "--browser") flags.browser = argv[++i];
    else if (a === "--filters") flags.filters = argv[++i];
    else if (a === "--baseline") flags.baseline = argv[++i];
    else if (a === "--save-baseline") flags.saveBaseline = argv[++i];
    else if (a === "--config") flags.config = argv[++i];
    else if (a.startsWith("--")) return null;
    else flags.positional.push(a);
  }
  return flags;
}

function fail(message: string): number {
  console.error(`filterguard: ${message}`);
  return 2;
}

function emit(
  command: string,
  findings: Finding[],
  summary: ReturnType<typeof summarize>,
  warnings: string[],
  json: boolean,
): void {
  if (json) {
    console.log(renderJson(command, findings, summary, warnings));
  } else {
    console.log(renderHuman(findings, summary));
    for (const w of warnings) console.error(`warning: ${w}`);
  }
}

function exitFor(findings: Finding[]): number {
  return findings.some((f) => f.severity === "HIGH") ? 1 : 0;
}

function collectExtensionFindings(opts: {
  browser?: string;
  profileDir?: string;
}): { verdicts: ExtensionVerdict[]; warnings: string[]; profiles: number } {
  const profiles = discoverProfiles(opts);
  const verdicts: ExtensionVerdict[] = [];
  const warnings: string[] = [];
  for (const p of profiles) {
    warnings.push(...p.warnings);
    for (const ext of p.extensions) verdicts.push(scoreExtension(ext));
  }
  return { verdicts, warnings, profiles: profiles.length };
}

function baselineFromFindings(findings: Finding[]): Baseline {
  const b = emptyBaseline();
  const seen = new Set<string>();
  for (const f of findings) {
    if (seen.has(f.key)) continue;
    seen.add(f.key);
    b.entries.push({
      kind: f.kind,
      key: f.key,
      text: f.target,
      severity: f.severity,
      reason: f.reason,
      added: new Date().toISOString().slice(0, 10),
    });
  }
  return b;
}

function cmdScan(flags: Flags): number {
  const { verdicts, warnings, profiles } = collectExtensionFindings(flags);
  if (profiles === 0) {
    return fail(
      "no browser profile found. Pass --profile-dir <dir> or run " +
        "`filterguard init` to see the well-known profile locations.",
    );
  }
  const findings = findingsFromExtensions(verdicts);
  const summary = summarize(findings, {
    profilesScanned: profiles,
    extensionsScanned: verdicts.length,
    rulesParsed: 0,
  });
  if (flags.saveBaseline) {
    saveBaselineMerged(flags.saveBaseline, baselineFromFindings(findings));
    if (!flags.json) {
      console.error(
        `baseline saved: ${flags.saveBaseline} (${findings.length} finding(s))`,
      );
    }
  }
  emit("scan", findings, summary, warnings, flags.json);
  return exitFor(findings);
}

function readFiltersFile(
  flags: Flags,
): { content: string; path: string } | null {
  const path =
    flags.filters ??
    loadConfig(flags.config ?? CONFIG_FILE)?.filtersFile ??
    null;
  if (!path) return null;
  const resolved = resolve(path);
  if (!existsSync(resolved)) {
    console.error(`filterguard: filter file not found: ${resolved}`);
    return null;
  }
  return { content: readFileSync(resolved, "utf8"), path: resolved };
}

function cmdFilters(flags: Flags): number {
  const file = readFiltersFile(flags);
  if (!file) {
    return fail(
      "no filter file given. Export My filters first: uBlock Origin " +
        "Dashboard -> My filters -> Export, then pass --filters <file>.",
    );
  }
  const parsed = parseFilterFile(file.content);
  const findings = findingsFromRules(parsed.findings);
  const summary = summarize(findings, {
    profilesScanned: 0,
    extensionsScanned: 0,
    rulesParsed: parsed.parsedLines,
  });
  if (flags.saveBaseline) {
    saveBaselineMerged(flags.saveBaseline, baselineFromFindings(findings));
    if (!flags.json) {
      console.error(
        `baseline saved: ${flags.saveBaseline} (${findings.length} finding(s))`,
      );
    }
  }
  emit("filters", findings, summary, parsed.warnings, flags.json);
  return exitFor(findings);
}

function cmdCheck(flags: Flags): number {
  const warnings: string[] = [];
  const allFindings: Finding[] = [];
  let rulesParsed = 0;

  const scan = collectExtensionFindings(flags);
  const profiles = scan.profiles;
  const extensions = scan.verdicts.length;
  warnings.push(...scan.warnings);
  allFindings.push(...findingsFromExtensions(scan.verdicts));

  const file = readFiltersFile(flags);
  if (file) {
    const parsed = parseFilterFile(file.content);
    rulesParsed = parsed.parsedLines;
    warnings.push(...parsed.warnings);
    allFindings.push(...findingsFromRules(parsed.findings));
  } else {
    warnings.push(
      "no filter file supplied: filter half skipped. " +
        "Export My filters (uBO Dashboard -> My filters -> Export) and pass --filters <file>.",
    );
  }

  if (profiles === 0 && !file) {
    return fail("nothing to audit: no browser profile and no filter file.");
  }

  let findings = allFindings;
  let accepted: Finding[] = [];
  if (flags.baseline) {
    const baseline = loadBaseline(flags.baseline);
    if (!baseline)
      return fail(`baseline not found or unreadable: ${flags.baseline}`);
    const keys = new Set(baseline.entries.map((e) => e.key));
    accepted = allFindings.filter((f) => keys.has(f.key));
    findings = allFindings.filter((f) => !keys.has(f.key));
  }

  const summary = summarize(findings, {
    profilesScanned: profiles,
    extensionsScanned: extensions,
    rulesParsed,
  });
  emit("check", findings, summary, warnings, flags.json);
  if (!flags.json && accepted.length > 0) {
    console.log(
      `\naccepted by baseline: ${accepted.length} finding(s) (reviewed, not failed)`,
    );
  }
  return exitFor(findings);
}

function cmdDiff(flags: Flags): number {
  const [aPath, bPath] = flags.positional;
  if (!aPath || !bPath)
    return fail("usage: filterguard diff <baseline-a> <baseline-b>");
  const a = loadBaseline(aPath);
  const b = loadBaseline(bPath);
  if (!a) return fail(`baseline not found or unreadable: ${aPath}`);
  if (!b) return fail(`baseline not found or unreadable: ${bPath}`);
  const diff = diffBaselines(a, b);
  const newHigh = diff.added.filter((e) => e.severity === "HIGH");
  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          tool: "filterguard",
          version: VERSION,
          added: diff.added,
          removed: diff.removed,
          unchanged: diff.unchanged,
        },
        null,
        2,
      ),
    );
  } else {
    const lines: string[] = [];
    lines.push(`diff: ${aPath} -> ${bPath}`);
    lines.push(
      `  new: ${diff.added.length} | fixed: ${diff.removed.length} | unchanged: ${diff.unchanged.length}`,
    );
    for (const e of diff.added)
      lines.push(`  NEW ${e.severity} [${e.kind}] ${e.text.slice(0, 90)}`);
    for (const e of diff.removed)
      lines.push(`  FIXED ${e.severity} [${e.kind}] ${e.text.slice(0, 90)}`);
    console.log(lines.join("\n"));
  }
  return newHigh.length > 0 ? 1 : 0;
}

function cmdExplain(flags: Flags): number {
  const arg = flags.positional[0];
  if (!arg) return fail("usage: filterguard explain <rule-or-extension-id>");
  const warnings: string[] = [];

  // Extension drill-down: match by id or name in scanned profiles.
  const scan = collectExtensionFindings(flags);
  warnings.push(...scan.warnings);
  const match = scan.verdicts.find(
    (v) =>
      v.extension.id === arg ||
      v.extension.name.toLowerCase() === arg.toLowerCase() ||
      v.extension.name.toLowerCase().includes(arg.toLowerCase()),
  );
  if (match) {
    const lines: string[] = [];
    lines.push(`extension: ${match.extension.name} ${match.extension.version}`);
    lines.push(`id: ${match.extension.id}`);
    lines.push(`browser: ${match.extension.browser}`);
    lines.push(`profile: ${match.extension.profile}`);
    lines.push(`manifest version: ${match.extension.manifestVersion}`);
    lines.push(`score: ${match.score} (${match.severity})`);
    lines.push(`permissions: ${match.extension.permissions.join(", ") || "-"}`);
    lines.push(
      `host permissions: ${match.extension.hostPermissions.join(", ") || "-"}`,
    );
    for (const cs of match.extension.contentScripts) {
      lines.push(
        `content script: matches ${cs.matches.join(", ")}${cs.runAt ? ` at ${cs.runAt}` : ""}`,
      );
    }
    lines.push(`update url: ${match.extension.updateUrl ?? "-"}`);
    if (match.ubo) lines.push(`uBlock Origin: ${match.ubo.label}`);
    lines.push("findings:");
    if (match.findings.length === 0) lines.push("  (none)");
    for (const f of match.findings) {
      lines.push(`  - [${f.severity}] ${f.reason}`);
      lines.push(`    evidence: ${f.evidence}`);
      lines.push(`    fix: ${f.remediation}`);
    }
    lines.push(SCOPE_FOOTER);
    console.log(lines.join("\n"));
    return match.severity === "HIGH" ? 1 : 0;
  }

  // Otherwise treat the argument as a filter rule to dissect.
  const parsed = parseFilterFile(arg);
  const rule: ParsedRule | undefined = parsed.rules.find(
    (r) => r.kind !== "empty" && r.kind !== "comment",
  );
  if (!rule) {
    return fail(
      `no extension matched "${arg}" and it does not parse as a filter rule.`,
    );
  }
  const lines: string[] = [];
  lines.push(`rule: ${rule.text}`);
  lines.push(`kind: ${rule.kind}`);
  lines.push(
    `domains: ${rule.domains.join(", ") || "(none - applies everywhere)"}`,
  );
  lines.push(`options: ${rule.options.join(", ") || "-"}`);
  lines.push(`trusted scriptlet: ${rule.trustedScriptlet ?? "-"}`);
  lines.push(`severity: ${rule.severity}`);
  lines.push(`sha256: ${ruleSha256(rule.text)}`);
  lines.push("reasons:");
  for (const r of rule.reasons) lines.push(`  - ${r}`);
  if (rule.reasons.length === 0)
    lines.push("  (none - this rule is not flagged)");
  // The rule was passed on the command line, not read from a file,
  // so a "find line N" pointer would be meaningless here.
  const remediation = (rule.remediation ?? "No action needed.").replace(
    "find line 1, and delete",
    "find this rule, and delete",
  );
  lines.push(`what to do: ${remediation}`);
  lines.push(`reference: ${GHSA_ID} - ${GHSA_URL}`);
  lines.push(SCOPE_FOOTER);
  console.log(lines.join("\n"));
  return rule.severity === "HIGH" ? 1 : 0;
}

function cmdInit(): number {
  if (existsSync(CONFIG_FILE)) {
    console.log(`${CONFIG_FILE} already exists - not overwritten.`);
  } else {
    writeDefaultConfig(CONFIG_FILE);
    console.log(`wrote ${CONFIG_FILE}`);
  }
  console.log("");
  console.log("Well-known browser profile locations on this machine:");
  for (const p of knownProfilePaths()) console.log(`  ${p}`);
  console.log("");
  console.log("To audit your My filters list, export it first:");
  console.log("  uBlock Origin Dashboard -> My filters -> Export");
  console.log("  (the live list lives in extension storage, not a plain file,");
  console.log(
    "   so v0.1.0 reads the export you point at with --filters <file>)",
  );
  console.log("AdGuard: Settings -> User rules -> Export.");
  console.log("");
  console.log("Then run: filterguard check --filters <exported-file>");
  return 0;
}

export function main(argv: string[]): number {
  const [command, ...rest] = argv;
  if (!command || command === "--help" || command === "-h") {
    console.log(usage());
    return 0;
  }
  if (command === "--version" || command === "-v") {
    console.log(`filterguard ${VERSION}`);
    return 0;
  }
  const flags = parseFlags(rest);
  if (!flags) {
    console.error(usage());
    return 2;
  }
  switch (command) {
    case "scan":
      return cmdScan(flags);
    case "filters":
      return cmdFilters(flags);
    case "check":
      return cmdCheck(flags);
    case "diff":
      return cmdDiff(flags);
    case "explain":
      return cmdExplain(flags);
    case "init":
      return cmdInit();
    default:
      console.error(usage());
      return fail(`unknown command: ${command}`);
  }
}

// Unconditional, like the other factory CLIs: the npm bin is a symlink
// to dist/cli.js, so argv[1] is the symlink path, not this file.
process.exitCode = main(process.argv.slice(2));
