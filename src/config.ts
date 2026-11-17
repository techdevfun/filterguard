/**
 * filterguard.config.json - written by `filterguard init`, read by
 * `scan` / `filters` / `check` when no flags override it.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";

export const CONFIG_FILE = "filterguard.config.json";

export interface FilterguardConfig {
  version: 1;
  browsers: string[];
  profileDir: string | null;
  filtersFile: string | null;
  baselineFile: string;
  thresholds: { high: number; medium: number };
}

export function defaultConfig(): FilterguardConfig {
  return {
    version: 1,
    browsers: ["chrome", "chromium", "brave", "edge", "firefox"],
    profileDir: null,
    filtersFile: null,
    baselineFile: "filterguard.baseline.json",
    thresholds: { high: 40, medium: 20 },
  };
}

export function loadConfig(path: string): FilterguardConfig | null {
  if (!existsSync(path)) return null;
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    return { ...defaultConfig(), ...(parsed as Partial<FilterguardConfig>) };
  } catch {
    return null;
  }
}

export function writeDefaultConfig(path: string): void {
  writeFileSync(path, JSON.stringify(defaultConfig(), null, 2) + "\n", "utf8");
}
