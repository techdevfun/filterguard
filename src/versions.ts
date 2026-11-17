/**
 * Version guidance for the uBlock Origin universal XSS,
 * GHSA-cmqw-9r2w-6wv2 (High, public 15 Nov 2026).
 *
 * Pinned to the check date below with sources in the README.
 * Re-check the advisory and the uBlock releases page before
 * trusting this table on a later date.
 */
export const GHSA_ID = "GHSA-cmqw-9r2w-6wv2";
export const GHSA_URL =
  "https://github.com/gorhill/uBlock/security/advisories/GHSA-cmqw-9r2w-6wv2";
export const UBO_RELEASES_URL = "https://github.com/gorhill/uBlock/releases";
export const RECOMMENDED_UBO_VERSION = "1.76.4";
export const CHECKED_AT = "2026-11-17";

/** Compare dotted versions. A part with a letter suffix (1.76.5b0)
 *  sorts below the same number without one (1.76.5). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(".");
  const pb = b.split(".");
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const [na, sa] = splitPart(pa[i] ?? "0");
    const [nb, sb] = splitPart(pb[i] ?? "0");
    if (na !== nb) return na - nb;
    if (sa === sb) continue;
    if (sa === "") return 1; // release beats pre-release of the same number
    if (sb === "") return -1;
    return sa < sb ? -1 : 1;
  }
  return 0;
}

function splitPart(part: string): [number, string] {
  const m = /^(\d+)(.*)$/.exec(part);
  if (!m) return [0, part];
  return [parseInt(m[1], 10), m[2]];
}

export type UboStatus = "vulnerable" | "patched-older" | "ok";

export interface UboVerdict {
  status: UboStatus;
  label: string;
  detail: string;
}

/** Classify an installed uBlock Origin version against GHSA-cmqw-9r2w-6wv2. */
export function uboVerdict(version: string): UboVerdict {
  if (compareVersions(version, "1.75.4") < 0) {
    return {
      status: "vulnerable",
      label: `uBlock Origin ${version} is VULNERABLE to ${GHSA_ID}`,
      detail:
        `Versions 1.75.2 and lower are vulnerable. Update to ` +
        `${RECOMMENDED_UBO_VERSION} or newer, then run ` +
        "`filterguard filters` - the update does NOT remove a filter " +
        "the attack already planted.",
    };
  }
  if (compareVersions(version, RECOMMENDED_UBO_VERSION) < 0) {
    return {
      status: "patched-older",
      label:
        `uBlock Origin ${version} is patched but older than recommended ` +
        `${RECOMMENDED_UBO_VERSION}`,
      detail:
        `1.75.4 carries the main fix, but 1.76.0 and ${RECOMMENDED_UBO_VERSION} ` +
        `add further security hardening. Update to ${RECOMMENDED_UBO_VERSION} ` +
        `or newer, then run \`filterguard filters\` to check My filters.`,
    };
  }
  return {
    status: "ok",
    label:
      `uBlock Origin ${version} is at or above the recommended ` +
      `${RECOMMENDED_UBO_VERSION} (as of ${CHECKED_AT})`,
    detail:
      "The version is patched. Still run `filterguard filters`: the update " +
      "does not remove a filter planted before the update.",
  };
}
