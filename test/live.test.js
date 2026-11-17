/**
 * Live smoke tests (blueprint section 6).
 * Soft-skip on network failure: these assert the pre-creation state
 * (npm + GitHub names still free, advisory live, uBO release live),
 * never hard-fail CI.
 */
import test from "node:test";
import assert from "node:assert/strict";

async function getStatus(url, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: ctrl.signal,
      redirect: "follow",
    });
    return res.status;
  } finally {
    clearTimeout(t);
  }
}

test("live: npm package name `filterguard` is still unclaimed (404)", async (t) => {
  let status;
  try {
    status = await getStatus("https://registry.npmjs.org/filterguard");
  } catch {
    t.skip("network unavailable - cannot verify npm name");
    return;
  }
  assert.equal(status, 404, `expected npm 404 for filterguard, got ${status}`);
});

test("live: GitHub repo techdevfun/filterguard does not exist yet (404)", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://api.github.com/repos/techdevfun/filterguard",
    );
  } catch {
    t.skip("network unavailable - cannot verify GitHub name");
    return;
  }
  // Unauthenticated GitHub API may answer 403 when rate-limited:
  // that is a transport limit, not evidence the repo exists.
  if (status === 403) {
    t.skip("GitHub API rate-limited (403) - cannot verify repo name");
    return;
  }
  assert.equal(
    status,
    404,
    `expected GitHub 404 for techdevfun/filterguard, got ${status}`,
  );
});

test("live: GHSA advisory page for uBlock Origin returns 200", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://github.com/gorhill/uBlock/security/advisories/GHSA-cmqw-9r2w-6wv2",
    );
  } catch {
    t.skip("network unavailable - cannot verify advisory URL");
    return;
  }
  assert.equal(status, 200, `expected advisory 200, got ${status}`);
});

test("live: uBlock releases API returns 200", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://api.github.com/repos/gorhill/uBlock/releases?per_page=1",
    );
  } catch {
    t.skip("network unavailable - cannot verify releases API");
    return;
  }
  if (status === 403) {
    t.skip("GitHub API rate-limited (403) - cannot verify releases API");
    return;
  }
  assert.equal(status, 200, `expected releases API 200, got ${status}`);
});
