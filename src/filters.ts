/**
 * ABP-syntax filter parser (uBlock Origin "My filters" export,
 * AdGuard custom filters).
 *
 * The parser is conservative: a rule it does not understand becomes
 * a counted parse warning, never a silent drop and never a crash.
 * It reports; it never deletes anything.
 *
 * Syntax sources (checked 2026-11-17):
 *  - https://adblockplus.org/filter-cheatsheet
 *  - https://help.eyeo.com/en/adblockplus/how-to-write-filters
 *  - https://github.com/gorhill/uBlock/wiki/Static-filter-syntax
 *  - https://adguard.com/kb/general/ad-filtering/create-own-filters/
 */
import { createHash } from "node:crypto";

export type Severity = "HIGH" | "MEDIUM" | "LOW" | "NONE";

export type RuleKind =
  | "comment"
  | "empty"
  | "exception"
  | "cosmetic"
  | "cosmetic-exception"
  | "scriptlet"
  | "network"
  | "unknown";

export interface ParsedRule {
  line: number;
  text: string;
  kind: RuleKind;
  /** Domains the rule is scoped to. Empty = no domain restriction (broad). */
  domains: string[];
  options: string[];
  trustedScriptlet: string | null;
  severity: Severity;
  reasons: string[];
  remediation: string | null;
  sha256: string;
  warning: string | null;
}

export interface ParseResult {
  rules: ParsedRule[];
  /** Rules that carry a finding (severity HIGH/MEDIUM/LOW). */
  findings: ParsedRule[];
  warnings: string[];
  totalLines: number;
  parsedLines: number;
}

export const GHSA_REF =
  "GHSA-cmqw-9r2w-6wv2 (uBlock Origin universal XSS, High, public 15 Nov 2026)";

const TRUSTED_RE = /trusted-[a-z0-9-]+/i;
const SCRIPTLET_CALL_RE = /scriptlet\s*\(\s*['"]?(trusted-[a-z0-9-]+)/i;
const JS_INJECT_RE = /##\+js\s*\(\s*['"]?(trusted-[a-z0-9-]+)/i;

/** Collapse whitespace runs so the same rule text with different
 *  spacing still matches one baseline entry. */
export function normalizeRuleText(text: string): string {
  return text.trim().replace(/\s+/g, " ");
}

export function ruleSha256(text: string): string {
  return createHash("sha256").update(normalizeRuleText(text)).digest("hex");
}

function splitOptions(raw: string): string[] {
  // Split on commas that are not inside parentheses, so a scriptlet
  // argument list such as $scriptlet(a, b, c) stays one option.
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of raw) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim() !== "") out.push(cur.trim());
  return out;
}

function openCloseBalanced(text: string): boolean {
  let depth = 0;
  for (const ch of text) {
    if (ch === "(") depth++;
    if (ch === ")") {
      depth--;
      if (depth < 0) return false;
    }
  }
  return depth === 0;
}

function plantedRemediation(lineNo: number): string {
  return (
    `Open uBlock Origin Dashboard -> My filters, find line ${lineNo}, ` +
    `and delete this rule if you did not write it. Then re-run ` +
    "`filterguard check`. If you DID write it on purpose, allowlist it " +
    "with `filterguard filters --save-baseline` after review - never " +
    "allowlist a rule you do not recognise."
  );
}

function classify(
  lineNo: number,
  rawLine: string,
  warnings: string[],
): ParsedRule {
  const text = rawLine.trim();
  const base: Omit<ParsedRule, "severity" | "reasons" | "remediation"> = {
    line: lineNo,
    text,
    kind: "unknown",
    domains: [],
    options: [],
    trustedScriptlet: null,
    sha256: ruleSha256(text),
    warning: null,
  };

  if (text === "") {
    return {
      ...base,
      kind: "empty",
      severity: "NONE",
      reasons: [],
      remediation: null,
    };
  }
  if (text.startsWith("[Adblock")) {
    return {
      ...base,
      kind: "comment",
      severity: "NONE",
      reasons: [],
      remediation: null,
    };
  }
  // uBO/AdGuard trusted-scriptlet marker written as a comment-style line.
  if (text.startsWith("!#")) {
    const m = TRUSTED_RE.exec(text);
    if (m) {
      return {
        ...base,
        kind: "scriptlet",
        trustedScriptlet: m[0].toLowerCase(),
        severity: "HIGH",
        reasons: [
          `trusted scriptlet ${m[0].toLowerCase()} runs JavaScript on matched sites`,
          `planted-filter vector: ${GHSA_REF}`,
        ],
        remediation: plantedRemediation(lineNo),
      };
    }
    return {
      ...base,
      kind: "comment",
      severity: "NONE",
      reasons: [],
      remediation: null,
    };
  }
  if (text.startsWith("!")) {
    return {
      ...base,
      kind: "comment",
      severity: "NONE",
      reasons: [],
      remediation: null,
    };
  }
  if (text.startsWith("@@")) {
    // Exception rules whitelist traffic; they are never flagged.
    return {
      ...base,
      kind: "exception",
      severity: "NONE",
      reasons: [],
      remediation: null,
    };
  }

  // Cosmetic / scriptlet-injection forms: domain##+js(...), domain#%#//scriptlet(...),
  // domain#$#//scriptlet(...), domain##rule, domain#@#rule.
  const hashIdx = text.indexOf("#");
  if (hashIdx >= 0) {
    const afterHash = text.slice(hashIdx);
    const domainPart = text.slice(0, hashIdx);
    const domains = domainPart
      ? domainPart
          .split(",")
          .map((d) => d.trim())
          .filter(Boolean)
      : [];
    if (afterHash.startsWith("#@#")) {
      return {
        ...base,
        kind: "cosmetic-exception",
        domains,
        severity: "NONE",
        reasons: [],
        remediation: null,
      };
    }
    const scriptletMatch =
      SCRIPTLET_CALL_RE.exec(afterHash) ?? JS_INJECT_RE.exec(text);
    if (
      afterHash.startsWith("#%#") ||
      afterHash.startsWith("#$#") ||
      afterHash.startsWith("##+js(")
    ) {
      if (scriptletMatch) {
        const name = scriptletMatch[1].toLowerCase();
        return {
          ...base,
          kind: "scriptlet",
          domains,
          trustedScriptlet: name,
          severity: "HIGH",
          reasons: [
            `trusted scriptlet ${name} runs JavaScript on ${domains.length ? domains.join(", ") : "every site"}`,
            `planted-filter vector: ${GHSA_REF}`,
          ],
          remediation: plantedRemediation(lineNo),
        };
      }
      const broad = domains.length === 0 || domains.includes("*");
      return {
        ...base,
        kind: "scriptlet",
        domains,
        severity: broad ? "HIGH" : "MEDIUM",
        reasons: [
          broad
            ? "scriptlet injection with no domain restriction runs code on every site"
            : `scriptlet injection runs code on ${domains.join(", ")} - review it`,
        ],
        remediation:
          "Open My filters, confirm you wrote this scriptlet, and allowlist it after review; otherwise delete it.",
      };
    }
    if (afterHash.startsWith("##") || afterHash.startsWith("#$?#")) {
      // Plain cosmetic hiding rules are never flagged.
      return {
        ...base,
        kind: "cosmetic",
        domains,
        severity: "NONE",
        reasons: [],
        remediation: null,
      };
    }
    // A '#' form we do not recognise: warn, count, do not drop.
    const warning = `line ${lineNo}: unrecognised '#' filter form, kept as unknown`;
    warnings.push(warning);
    return {
      ...base,
      kind: "unknown",
      domains,
      severity: "NONE",
      reasons: [],
      remediation: null,
      warning,
    };
  }

  // Network rule: [domains] [$options]. Domains are the part before '$'.
  const dollarIdx = text.indexOf("$");
  const pattern = dollarIdx >= 0 ? text.slice(0, dollarIdx) : text;
  const options = dollarIdx >= 0 ? splitOptions(text.slice(dollarIdx + 1)) : [];
  const domains = parsePatternDomains(pattern);

  if (!openCloseBalanced(text)) {
    const warning = `line ${lineNo}: unbalanced parentheses, kept as unknown`;
    warnings.push(warning);
    return {
      ...base,
      kind: "unknown",
      domains,
      options,
      severity: "NONE",
      reasons: [],
      remediation: null,
      warning,
    };
  }

  const optNames = options.map((o) => o.split("=")[0].trim().toLowerCase());
  const broad = domains.length === 0 || domains.includes("*");

  // Trusted scriptlet carried as a network-rule option.
  const scriptletOpt = options.find((o) =>
    o.toLowerCase().startsWith("scriptlet"),
  );
  if (scriptletOpt) {
    const m = TRUSTED_RE.exec(scriptletOpt);
    if (m) {
      return {
        ...base,
        kind: "scriptlet",
        domains,
        options,
        trustedScriptlet: m[0].toLowerCase(),
        severity: "HIGH",
        reasons: [
          `trusted scriptlet ${m[0].toLowerCase()} runs JavaScript on ${broad ? "every site" : domains.join(", ")}`,
          `planted-filter vector: ${GHSA_REF}`,
        ],
        remediation: plantedRemediation(lineNo),
      };
    }
    return {
      ...base,
      kind: "scriptlet",
      domains,
      options,
      severity: broad ? "HIGH" : "MEDIUM",
      reasons: [
        broad
          ? "scriptlet option with no domain restriction runs code on every site"
          : `scriptlet option runs code on ${domains.join(", ")} - review it`,
      ],
      remediation:
        "Open My filters, confirm you wrote this scriptlet, and allowlist it after review; otherwise delete it.",
    };
  }

  if (optNames.includes("redirect") || optNames.includes("redirect-rule")) {
    if (broad) {
      return {
        ...base,
        kind: "network",
        domains,
        options,
        severity: "HIGH",
        reasons: [
          "broad $redirect rule with no domain restriction rewrites responses on every site",
        ],
        remediation:
          "Scope the redirect to the domains you meant, or delete the rule.",
      };
    }
    return {
      ...base,
      kind: "network",
      domains,
      options,
      severity: "NONE",
      reasons: [],
      remediation: null,
    };
  }
  if (optNames.includes("csp")) {
    if (broad) {
      return {
        ...base,
        kind: "network",
        domains,
        options,
        severity: "HIGH",
        reasons: [
          "broad $csp rule with no domain restriction rewrites the security policy of every site",
        ],
        remediation:
          "Scope the CSP rule to the domains you meant, or delete the rule.",
      };
    }
    return {
      ...base,
      kind: "network",
      domains,
      options,
      severity: "LOW",
      reasons: [
        "$csp rule can weaken the security policy of listed domains - confirm it is intentional",
      ],
      remediation:
        "Confirm this CSP rule is one you wrote; allowlist it after review.",
    };
  }
  if (optNames.includes("document") || optNames.includes("popup")) {
    if (broad) {
      return {
        ...base,
        kind: "network",
        domains,
        options,
        severity: "MEDIUM",
        reasons: [
          "block-all $document/$popup rule with no domain restriction blocks whole pages everywhere",
        ],
        remediation: "Scope the rule to the domains you meant, or delete it.",
      };
    }
    return {
      ...base,
      kind: "network",
      domains,
      options,
      severity: "LOW",
      reasons: [
        "$document/$popup rule blocks whole pages on listed domains - confirm it is intentional",
      ],
      remediation:
        "Confirm this rule is one you wrote; allowlist it after review.",
    };
  }

  return {
    ...base,
    kind: "network",
    domains,
    options,
    severity: "NONE",
    reasons: [],
    remediation: null,
  };
}

/** Extract the domain list from a network-rule pattern part. */
function parsePatternDomains(pattern: string): string[] {
  let p = pattern.trim();
  if (p === "" || p === "*") return [];
  // Regex rules start with '/' and carry no domain scope.
  if (p.startsWith("/")) return [];
  p = p.replace(/^\|\|/, "").replace(/^\|/, "").replace(/\^.*$/, "");
  p = p.replace(/^\*\./, "").replace(/^\*\./, "");
  if (p === "" || p === "*") return [];
  // A pattern with a path (example.com/ads/*) scopes to its host.
  const host = p.split("/")[0];
  if (!host || host.includes("*")) return [];
  return [host];
}

/** Parse a whole filter file. Never throws on bad input. */
export function parseFilterFile(content: string): ParseResult {
  const lines = content.split(/\r?\n/);
  const warnings: string[] = [];
  const rules: ParsedRule[] = [];
  for (let i = 0; i < lines.length; i++) {
    rules.push(classify(i + 1, lines[i], warnings));
  }
  const findings = rules.filter((r) => r.severity !== "NONE");
  return {
    rules,
    findings,
    warnings,
    totalLines: lines.length,
    parsedLines: rules.filter((r) => r.kind !== "empty" && r.kind !== "comment")
      .length,
  };
}
