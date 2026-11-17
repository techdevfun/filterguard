/**
 * Human and JSON report rendering.
 * The same data drives both shapes; --json never hides a finding
 * the human table shows.
 */
import type { ParsedRule, Severity } from "./filters.js";
import type { ExtensionVerdict } from "./scoring.js";
import { extensionKey } from "./baseline.js";
import { VERSION } from "./cli-version.js";

export interface Finding {
  severity: Severity;
  kind: "extension" | "filter";
  target: string;
  reason: string;
  evidence: string;
  remediation: string;
  line?: number;
  key: string;
}

export interface Summary {
  high: number;
  medium: number;
  low: number;
  ok: number;
  profilesScanned: number;
  extensionsScanned: number;
  rulesParsed: number;
}

export const SCOPE_FOOTER =
  "Scope: filterguard audits extension manifests and filter lists only. " +
  "It does not inspect extension code, runtime behaviour, or store-freshness. " +
  "A clean result means no risky manifest or filter was found - not that the " +
  "browser is safe. It never deletes anything: review each finding, then " +
  "remove the rule or extension yourself.";

export function summarize(
  findings: Finding[],
  meta: Omit<Summary, "high" | "medium" | "low" | "ok">,
): Summary {
  return {
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low: findings.filter((f) => f.severity === "LOW").length,
    ok: 0,
    ...meta,
  };
}

export function findingsFromExtensions(
  verdicts: ExtensionVerdict[],
): Finding[] {
  const out: Finding[] = [];
  for (const v of verdicts) {
    for (const f of v.findings) {
      out.push({
        severity: f.severity,
        kind: "extension",
        target: `${v.extension.name} ${v.extension.version} (${v.extension.id})`,
        reason: f.reason,
        evidence: f.evidence,
        remediation: f.remediation,
        key: extensionKey(v.extension.id, f.key),
      });
    }
  }
  return out;
}

export function findingsFromRules(rules: ParsedRule[]): Finding[] {
  return rules
    .filter((r) => r.severity !== "NONE")
    .map((r) => ({
      severity: r.severity,
      kind: "filter" as const,
      target: `line ${r.line}: ${r.text.slice(0, 80)}${r.text.length > 80 ? "..." : ""}`,
      reason: r.reasons.join("; "),
      evidence: `line ${r.line}, sha256 ${r.sha256.slice(0, 12)}`,
      remediation: r.remediation ?? "Review the rule in My filters.",
      line: r.line,
      key: r.sha256,
    }));
}

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

export function renderHuman(
  findings: Finding[],
  summary: Summary,
  opts: { title?: string } = {},
): string {
  const lines: string[] = [];
  if (opts.title) lines.push(opts.title);
  if (findings.length === 0) {
    lines.push("no findings");
  } else {
    lines.push(`${pad("target", 58)} ${pad("severity", 8)} reason`);
    lines.push("-".repeat(106));
    for (const f of findings) {
      lines.push(`${pad(f.target, 58)} ${pad(f.severity, 8)} ${f.reason}`);
      lines.push(`  evidence: ${f.evidence}`);
      lines.push(`  fix: ${f.remediation}`);
    }
  }
  lines.push("");
  lines.push(
    `summary: HIGH ${summary.high} | MEDIUM ${summary.medium} | LOW ${summary.low} | ` +
      `profiles ${summary.profilesScanned} | extensions ${summary.extensionsScanned} | ` +
      `rules parsed ${summary.rulesParsed}`,
  );
  lines.push(SCOPE_FOOTER);
  return lines.join("\n");
}

export function renderJson(
  command: string,
  findings: Finding[],
  summary: Summary,
  warnings: string[],
): string {
  return JSON.stringify(
    {
      tool: "filterguard",
      version: VERSION,
      checkedAt: new Date().toISOString(),
      command,
      summary,
      findings: findings.map((f) => ({
        severity: f.severity,
        kind: f.kind,
        target: f.target,
        reason: f.reason,
        evidence: f.evidence,
        remediation: f.remediation,
        ...(f.line !== undefined ? { line: f.line } : {}),
        key: f.key,
      })),
      warnings,
      scope: SCOPE_FOOTER,
    },
    null,
    2,
  );
}
