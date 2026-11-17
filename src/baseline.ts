/**
 * Baseline allowlist: a JSON file of findings the user has reviewed
 * and accepted. `check` fails only on HIGH findings NOT in the baseline.
 *
 * A baseline entry is keyed by the sha256 of a canonical string, so the
 * same rule text with different whitespace still matches. A baseline
 * never silently ignores a finding: `check` lists allowlisted findings
 * as accepted, and `diff` shows what changed between two baselines.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Severity } from "./filters.js";
import { VERSION } from "./cli-version.js";

export interface BaselineEntry {
  kind: "filter" | "extension";
  key: string;
  text: string;
  severity: Severity;
  reason: string;
  added: string;
}

export interface Baseline {
  tool: "filterguard";
  version: string;
  createdAt: string;
  entries: BaselineEntry[];
}

export function filterKey(ruleText: string): string {
  return createHash("sha256")
    .update(ruleText.trim().replace(/\s+/g, " "))
    .digest("hex");
}

export function extensionKey(id: string, findingKey: string): string {
  // Version is deliberately NOT part of the key: updating an extension
  // does not invalidate a reviewed capability finding. A new capability
  // (new permission, new host pattern) is a new key and fails again.
  // The version reviewed is recorded in the entry text.
  return createHash("sha256").update(`ext:${id}:${findingKey}`).digest("hex");
}

export function emptyBaseline(): Baseline {
  return {
    tool: "filterguard",
    version: VERSION,
    createdAt: new Date().toISOString(),
    entries: [],
  };
}

export function loadBaseline(path: string): Baseline | null {
  if (!existsSync(path)) return null;
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    const b = parsed as Partial<Baseline>;
    if (!Array.isArray(b.entries)) return null;
    return {
      tool: "filterguard",
      version: typeof b.version === "string" ? b.version : VERSION,
      createdAt: typeof b.createdAt === "string" ? b.createdAt : "",
      entries: b.entries as BaselineEntry[],
    };
  } catch {
    return null;
  }
}

export function saveBaseline(path: string, baseline: Baseline): void {
  writeFileSync(path, JSON.stringify(baseline, null, 2) + "\n", "utf8");
}

/**
 * Save findings into a baseline file, merging with entries already
 * there (deduped by key). This is how a reviewed state is built up
 * across commands: `scan --save-baseline b.json` then
 * `filters --save-baseline b.json` leaves one baseline covering both.
 */
export function saveBaselineMerged(path: string, baseline: Baseline): void {
  const existing = loadBaseline(path);
  if (!existing) {
    saveBaseline(path, baseline);
    return;
  }
  const keys = new Set(existing.entries.map((e) => e.key));
  for (const entry of baseline.entries) {
    if (!keys.has(entry.key)) {
      existing.entries.push(entry);
      keys.add(entry.key);
    }
  }
  existing.createdAt = new Date().toISOString();
  saveBaseline(path, existing);
}

export interface BaselineDiff {
  added: BaselineEntry[];
  removed: BaselineEntry[];
  unchanged: BaselineEntry[];
}

export function diffBaselines(a: Baseline, b: Baseline): BaselineDiff {
  const aKeys = new Map(a.entries.map((e) => [e.key, e]));
  const bKeys = new Map(b.entries.map((e) => [e.key, e]));
  const added = b.entries.filter((e) => !aKeys.has(e.key));
  const removed = a.entries.filter((e) => !bKeys.has(e.key));
  const unchanged = b.entries.filter((e) => aKeys.has(e.key));
  return { added, removed, unchanged };
}
