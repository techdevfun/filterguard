/**
 * Extension risk scoring from manifest data.
 *
 * Weights are the tool's own documented scale (see README "Verdict rules"):
 * a score of 40+ is HIGH, 20-39 MEDIUM, 1-19 LOW, 0 OK. The weights are
 * heuristics about capability, not proof of malicious behaviour.
 */
import {
  GHSA_ID,
  RECOMMENDED_UBO_VERSION,
  uboVerdict,
  type UboVerdict,
} from "./versions.js";
import type { Severity } from "./filters.js";

export interface ContentScript {
  matches: string[];
  runAt?: string;
  js?: string[];
}

export interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  browser: string;
  profile: string;
  manifestVersion: number;
  permissions: string[];
  hostPermissions: string[];
  optionalPermissions: string[];
  contentScripts: ContentScript[];
  updateUrl: string | null;
  description: string | null;
  /** Firefox extensions.json carries no manifest: permissions unknown. */
  manifestReadable: boolean;
}

export interface ExtensionFinding {
  severity: Severity;
  key: string;
  reason: string;
  evidence: string;
  remediation: string;
}

export interface ExtensionVerdict {
  extension: ExtensionInfo;
  score: number;
  severity: Severity;
  findings: ExtensionFinding[];
  ubo: UboVerdict | null;
}

const PERMISSION_WEIGHTS: Array<{
  permission: string;
  weight: number;
  reason: string;
}> = [
  {
    permission: "debugger",
    weight: 30,
    reason: "debugger can control other tabs and read page content",
  },
  {
    permission: "management",
    weight: 25,
    reason: "management can enable, disable and uninstall other extensions",
  },
  {
    permission: "webRequestBlocking",
    weight: 25,
    reason: "webRequestBlocking can block and rewrite network traffic",
  },
  {
    permission: "nativeMessaging",
    weight: 20,
    reason: "nativeMessaging can talk to native programs on this machine",
  },
  {
    permission: "proxy",
    weight: 20,
    reason: "proxy can route all browser traffic through a chosen server",
  },
  {
    permission: "privacy",
    weight: 15,
    reason: "privacy can change browser privacy settings",
  },
];

const STORE_UPDATE_URLS = [
  "https://clients2.google.com/service/update2/crx",
  "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
];

const KNOWN_IDS: Record<string, { name: string; kind: string }> = {
  cjpalhdlnbpafiamejdnhcphjbkeiagm: { name: "uBlock Origin", kind: "ubo" },
  "uBlock0@raymondhill.net": { name: "uBlock Origin", kind: "ubo" },
  bgnkhhnnamicmpeenaelnjfhikgbkllg: {
    name: "AdGuard AdBlocker",
    kind: "adguard",
  },
  "adguardadblocker@adguard.com": {
    name: "AdGuard AdBlocker",
    kind: "adguard",
  },
};

export function knownExtension(
  id: string,
): { name: string; kind: string } | null {
  return KNOWN_IDS[id] ?? null;
}

function severityForScore(score: number): Severity {
  if (score >= 40) return "HIGH";
  if (score >= 20) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

function severityForWeight(weight: number): Severity {
  if (weight >= 30) return "HIGH";
  if (weight >= 15) return "MEDIUM";
  return "LOW";
}

function allHosts(patterns: string[]): boolean {
  return patterns.some(
    (p) => p === "<all_urls>" || p === "*://*/*" || p === "*://*/",
  );
}

/** Score one installed extension. Pure function of its manifest. */
export function scoreExtension(ext: ExtensionInfo): ExtensionVerdict {
  const findings: ExtensionFinding[] = [];
  let score = 0;
  const add = (
    weight: number,
    key: string,
    reason: string,
    evidence: string,
    remediation: string,
  ) => {
    score += weight;
    findings.push({
      severity: severityForWeight(weight),
      key,
      reason,
      evidence,
      remediation,
    });
  };

  // Host scope comes from host_permissions plus permission entries that
  // are themselves match patterns (some manifests list them there).
  // Plain capability names such as "tabs" are NOT host patterns.
  const hostPatterns = [
    ...ext.hostPermissions,
    ...ext.permissions.filter((p) => p === "<all_urls>" || p.includes("://")),
  ];
  const broadHost = allHosts(hostPatterns);

  if (broadHost) {
    add(
      40,
      "host:all-urls",
      "can read and change data on every site you visit",
      `host access: ${hostPatterns.filter((p) => p === "<all_urls>" || p.startsWith("*://")).join(", ")}`,
      "If you do not need this extension on every site, restrict its site access in the browser settings.",
    );
  } else if (hostPatterns.length > 0) {
    add(
      5,
      "host:scoped",
      `can read and change data on ${hostPatterns.length} host pattern(s)`,
      `host access: ${hostPatterns.join(", ")}`,
      "Confirm each host pattern is one you expect this extension to touch.",
    );
  }

  for (const entry of PERMISSION_WEIGHTS) {
    if (ext.permissions.includes(entry.permission)) {
      add(
        entry.weight,
        `permission:${entry.permission}`,
        entry.reason,
        `permission: ${entry.permission}`,
        "Remove the extension if you do not need a capability this strong.",
      );
    }
  }

  if (ext.permissions.includes("cookies") && broadHost) {
    add(
      20,
      "permission:cookies-all-hosts",
      "cookies permission plus all-hosts access can read session cookies on every site",
      "permission: cookies + host access <all_urls>",
      "Restrict the extension to specific sites or remove it.",
    );
  }
  if (
    ext.permissions.includes("tabs") &&
    ext.permissions.includes("webNavigation")
  ) {
    add(
      15,
      "combo:tabs-webnavigation",
      "tabs + webNavigation can track every navigation you make",
      "permissions: tabs, webNavigation",
      "Confirm you expect this extension to see your browsing history.",
    );
  }

  for (const cs of ext.contentScripts) {
    const csBroad = allHosts(cs.matches);
    if (csBroad && cs.runAt === "document_start") {
      add(
        15,
        "content-script:all-urls-document-start",
        "content script runs on every page before it loads",
        `content script matches ${cs.matches.join(", ")} at document_start`,
        "Check the extension source or reviews for why it needs to run before page load.",
      );
    } else if (csBroad) {
      add(
        10,
        "content-script:all-urls",
        "content script runs on every page",
        `content script matches ${cs.matches.join(", ")}`,
        "Confirm you expect this extension to run on every page.",
      );
    }
  }

  if (ext.updateUrl && !STORE_UPDATE_URLS.includes(ext.updateUrl)) {
    add(
      15,
      "update:off-store",
      "updates come from outside the browser web store",
      `update_url: ${ext.updateUrl}`,
      "Off-store updates bypass store review. Prefer the store version of this extension.",
    );
  }

  if (ext.manifestVersion === 2 && ext.browser !== "firefox") {
    add(
      10,
      "manifest:v2",
      "Manifest V2 extension on a Chromium browser (Google is phasing MV2 out)",
      "manifest_version: 2",
      "Look for a Manifest V3 version of this extension.",
    );
  }

  if (!ext.manifestReadable) {
    findings.push({
      severity: "LOW",
      key: "manifest:unreadable",
      reason:
        "manifest not readable from this profile (Firefox extensions.json lists the add-on but not its permissions)",
      evidence: "source: extensions.json",
      remediation:
        "Open the browser add-ons page and review this extension by hand.",
    });
  }

  // uBlock Origin version gate (GHSA-cmqw-9r2w-6wv2).
  let ubo: UboVerdict | null = null;
  const known = knownExtension(ext.id);
  if (known?.kind === "ubo") {
    ubo = uboVerdict(ext.version);
    if (ubo.status === "vulnerable") {
      score += 40;
      findings.push({
        severity: "HIGH",
        key: "ubo:vulnerable",
        reason: ubo.label,
        evidence: `uBlock Origin ${ext.version}; vulnerable <= 1.75.2, fixed 1.75.4, recommended ${RECOMMENDED_UBO_VERSION}+ (${GHSA_ID})`,
        remediation: ubo.detail,
      });
    } else if (ubo.status === "patched-older") {
      score += 20;
      findings.push({
        severity: "MEDIUM",
        key: "ubo:patched-older",
        reason: ubo.label,
        evidence: `uBlock Origin ${ext.version}; recommended ${RECOMMENDED_UBO_VERSION}+`,
        remediation: ubo.detail,
      });
    }
  }

  return {
    extension: ext,
    score,
    severity: maxSeverity(severityForScore(score), findings),
    findings,
    ubo,
  };
}

const SEVERITY_ORDER: Severity[] = ["NONE", "LOW", "MEDIUM", "HIGH"];

/** Extension severity is the worse of its score band and its worst finding. */
function maxSeverity(
  scoreBand: Severity,
  findings: ExtensionFinding[],
): Severity {
  let worst = scoreBand;
  for (const f of findings) {
    if (SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(worst)) {
      worst = f.severity;
    }
  }
  return worst;
}
