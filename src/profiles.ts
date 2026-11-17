/**
 * Browser profile discovery and extension manifest reading.
 *
 * Reads ONLY extension manifest.json files (Chromium family) and
 * extensions.json (Firefox). Never reads history, cookies, passwords,
 * bookmarks, or any other browsing data. No network calls.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { compareVersions } from "./versions.js";
import type { ContentScript, ExtensionInfo } from "./scoring.js";

export interface ProfileScan {
  browser: string;
  path: string;
  extensions: ExtensionInfo[];
  warnings: string[];
}

const HOME = homedir();

interface BrowserRoot {
  browser: string;
  roots: string[];
}

function envPath(name: string): string | null {
  const v = process.env[name];
  return v && v !== "" ? v : null;
}

function browserRoots(): BrowserRoot[] {
  const platform = process.platform;
  if (platform === "darwin") {
    return [
      {
        browser: "chrome",
        roots: [join(HOME, "Library/Application Support/Google/Chrome")],
      },
      {
        browser: "chromium",
        roots: [join(HOME, "Library/Application Support/Chromium")],
      },
      {
        browser: "brave",
        roots: [
          join(HOME, "Library/Application Support/BraveSoftware/Brave-Browser"),
        ],
      },
      {
        browser: "edge",
        roots: [join(HOME, "Library/Application Support/Microsoft Edge")],
      },
      {
        browser: "firefox",
        roots: [join(HOME, "Library/Application Support/Firefox")],
      },
    ];
  }
  if (platform === "win32") {
    const local = envPath("LOCALAPPDATA") ?? join(HOME, "AppData/Local");
    const roaming = envPath("APPDATA") ?? join(HOME, "AppData/Roaming");
    return [
      { browser: "chrome", roots: [join(local, "Google/Chrome/User Data")] },
      { browser: "chromium", roots: [join(local, "Chromium/User Data")] },
      {
        browser: "brave",
        roots: [join(local, "BraveSoftware/Brave-Browser/User Data")],
      },
      { browser: "edge", roots: [join(local, "Microsoft/Edge/User Data")] },
      { browser: "firefox", roots: [join(roaming, "Mozilla/Firefox")] },
    ];
  }
  return [
    { browser: "chrome", roots: [join(HOME, ".config/google-chrome")] },
    { browser: "chromium", roots: [join(HOME, ".config/chromium")] },
    {
      browser: "brave",
      roots: [join(HOME, ".config/BraveSoftware/Brave-Browser")],
    },
    { browser: "edge", roots: [join(HOME, ".config/microsoft-edge")] },
    { browser: "firefox", roots: [join(HOME, ".mozilla/firefox")] },
  ];
}

function listDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => join(dir, e.name));
  } catch {
    return [];
  }
}

function profileDirs(root: string, browser: string): string[] {
  if (!existsSync(root)) return [];
  if (browser === "firefox") {
    // Firefox: each profile is a *.default* directory under the root.
    return listDirs(root).filter((d) => basename(d).includes(".default"));
  }
  // Chromium family: "Default" and "Profile N" directories.
  return listDirs(root).filter((d) => {
    const b = basename(d);
    return b === "Default" || /^Profile \d+$/.test(b);
  });
}

function readJsonFile(path: string): unknown | null {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function toStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

function parseManifest(
  id: string,
  browser: string,
  profilePath: string,
  manifest: Record<string, unknown>,
): ExtensionInfo {
  const permissions = toStringArray(manifest["permissions"]);
  const hostPermissions = toStringArray(manifest["host_permissions"]);
  const optionalPermissions = toStringArray(manifest["optional_permissions"]);
  const rawScripts = Array.isArray(manifest["content_scripts"])
    ? manifest["content_scripts"]
    : [];
  const contentScripts: ContentScript[] = rawScripts
    .filter(
      (s): s is Record<string, unknown> => typeof s === "object" && s !== null,
    )
    .map((s) => ({
      matches: toStringArray(s["matches"]),
      runAt: typeof s["run_at"] === "string" ? s["run_at"] : undefined,
      js: toStringArray(s["js"]),
    }));
  const name = typeof manifest["name"] === "string" ? manifest["name"] : id;
  const version =
    typeof manifest["version"] === "string" ? manifest["version"] : "0.0.0";
  return {
    id,
    name,
    version,
    browser,
    profile: profilePath,
    manifestVersion:
      typeof manifest["manifest_version"] === "number"
        ? manifest["manifest_version"]
        : 0,
    permissions,
    hostPermissions,
    optionalPermissions,
    contentScripts,
    updateUrl:
      typeof manifest["update_url"] === "string"
        ? manifest["update_url"]
        : null,
    description:
      typeof manifest["description"] === "string"
        ? manifest["description"]
        : null,
    manifestReadable: true,
  };
}

function scanChromiumProfile(
  browser: string,
  profilePath: string,
): ProfileScan {
  const warnings: string[] = [];
  const extensions: ExtensionInfo[] = [];
  const extRoot = join(profilePath, "Extensions");
  if (!existsSync(extRoot)) {
    warnings.push(`no Extensions directory in ${profilePath}`);
    return { browser, path: profilePath, extensions, warnings };
  }
  for (const idDir of listDirs(extRoot)) {
    const id = basename(idDir);
    const versionDirs = listDirs(idDir).sort((a, b) =>
      compareVersions(basename(a), basename(b)),
    );
    if (versionDirs.length === 0) {
      warnings.push(`extension ${id} has no version directory`);
      continue;
    }
    const manifest = readJsonFile(join(versionDirs[0], "manifest.json"));
    if (manifest === null || typeof manifest !== "object") {
      warnings.push(`extension ${id}: manifest.json unreadable`);
      continue;
    }
    extensions.push(
      parseManifest(
        id,
        browser,
        profilePath,
        manifest as Record<string, unknown>,
      ),
    );
  }
  return { browser, path: profilePath, extensions, warnings };
}

function scanFirefoxProfile(browser: string, profilePath: string): ProfileScan {
  const warnings: string[] = [];
  const extensions: ExtensionInfo[] = [];
  const data = readJsonFile(join(profilePath, "extensions.json"));
  if (data === null || typeof data !== "object") {
    warnings.push(`no readable extensions.json in ${profilePath}`);
    return { browser, path: profilePath, extensions, warnings };
  }
  const addons = (data as Record<string, unknown>)["addons"];
  if (!Array.isArray(addons)) {
    warnings.push(`extensions.json in ${profilePath} has no addons list`);
    return { browser, path: profilePath, extensions, warnings };
  }
  for (const addon of addons) {
    if (typeof addon !== "object" || addon === null) continue;
    const a = addon as Record<string, unknown>;
    if (a["type"] !== "extension" || a["active"] === false) continue;
    const locale =
      a["defaultLocale"] !== null && typeof a["defaultLocale"] === "object"
        ? (a["defaultLocale"] as Record<string, unknown>)
        : {};
    extensions.push({
      id: typeof a["id"] === "string" ? a["id"] : "unknown",
      name: typeof locale["name"] === "string" ? locale["name"] : "unknown",
      version: typeof a["version"] === "string" ? a["version"] : "0.0.0",
      browser,
      profile: profilePath,
      manifestVersion:
        typeof a["manifestVersion"] === "number" ? a["manifestVersion"] : 0,
      permissions: [],
      hostPermissions: [],
      optionalPermissions: [],
      contentScripts: [],
      updateUrl: null,
      description:
        typeof locale["description"] === "string"
          ? locale["description"]
          : null,
      manifestReadable: false,
    });
  }
  return { browser, path: profilePath, extensions, warnings };
}

export function scanProfileDir(
  browser: string,
  profilePath: string,
): ProfileScan {
  return browser === "firefox"
    ? scanFirefoxProfile(browser, profilePath)
    : scanChromiumProfile(browser, profilePath);
}

/**
 * Discover browser profiles on this machine.
 * `browser` limits discovery to one browser name (chrome|chromium|brave|edge|firefox).
 * `profileDir` overrides discovery with a single explicit profile directory.
 */
export function discoverProfiles(opts: {
  browser?: string;
  profileDir?: string;
}): ProfileScan[] {
  if (opts.profileDir) {
    const browser = opts.browser ?? "chrome";
    // A missing directory, or one with neither an Extensions folder nor
    // an extensions.json, is not a profile: report none, so callers
    // can exit 2 instead of reporting a clean audit of nothing.
    const isProfile =
      existsSync(opts.profileDir) &&
      (existsSync(join(opts.profileDir, "Extensions")) ||
        existsSync(join(opts.profileDir, "extensions.json")));
    if (!isProfile) return [];
    return [scanProfileDir(browser, opts.profileDir)];
  }
  const out: ProfileScan[] = [];
  for (const entry of browserRoots()) {
    if (opts.browser && entry.browser !== opts.browser) continue;
    for (const root of entry.roots) {
      for (const dir of profileDirs(root, entry.browser)) {
        out.push(scanProfileDir(entry.browser, dir));
      }
    }
  }
  return out;
}

/** Print the well-known profile locations for `filterguard init`. */
export function knownProfilePaths(): string[] {
  const out: string[] = [];
  for (const entry of browserRoots()) {
    for (const root of entry.roots) {
      out.push(`${entry.browser}: ${root}`);
    }
  }
  return out;
}
