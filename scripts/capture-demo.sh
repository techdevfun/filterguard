#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# The fixture profile and filter list are SYNTHETIC, built here, and
# labelled as such in the transcript and the README:
#   - uBlock Origin 1.75.2 (the version vulnerable to GHSA-cmqw-9r2w-6wv2)
#     plus a note-taking extension with <all_urls> host access
#   - a My filters export containing one planted trusted-rpnt rule
#     (rule shape from the public advisory write-ups, fixture domain),
#     one trusted rule the user wrote on purpose, and ordinary rules
# Part 3 updates uBO to 1.76.4, deletes the planted rule, baselines
# the reviewed state, and shows the `check` CI gate passing (exit 0).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/filterguard-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/filterguard"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

WORK="$SCRATCH/fixture-profile"
UBO_OLD="$WORK/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.75.2"
NOTE="$WORK/Extensions/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/2.3.0"
mkdir -p "$UBO_OLD" "$NOTE"
cat > "$UBO_OLD/manifest.json" <<'EOF'
{
  "manifest_version": 2,
  "name": "uBlock Origin",
  "version": "1.75.2",
  "description": "Finally, an efficient blocker. Easy on CPU and memory.",
  "permissions": ["webRequest", "webRequestBlocking", "storage", "unlimitedStorage"],
  "host_permissions": ["<all_urls>"],
  "update_url": "https://clients2.google.com/service/update2/crx"
}
EOF
cat > "$NOTE/manifest.json" <<'EOF'
{
  "manifest_version": 3,
  "name": "Quick Notes Everywhere",
  "version": "2.3.0",
  "description": "Take notes on any page.",
  "permissions": ["storage", "tabs"],
  "host_permissions": ["<all_urls>"],
  "content_scripts": [{ "matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_start" }],
  "update_url": "https://clients2.google.com/service/update2/crx"
}
EOF

FILTERS="$SCRATCH/my-filters.txt"
cat > "$FILTERS" <<'EOF'
! My filters - SYNTHETIC fixture (not a real filter list)
||ads.example.com^
example.com##.ad-banner
@@||example.com^$document
example.com#%#//scriptlet('trusted-rpnt', 'test', 'test')
example.org##+js(trusted-set, localStorage, myFlag, 1)
EOF

OUT="$ROOT/demo/transcript.txt"
{
  echo "# filterguard demo - real CLI output on SYNTHETIC fixtures"
  echo "# (fixture profile + filter list built in this script; the"
  echo "#  planted rule shape is from the public GHSA-cmqw-9r2w-6wv2"
  echo "#  write-ups, on a fixture domain - not a real victim)"
  echo ""
  echo "\$ filterguard scan --profile-dir fixture-profile"
  filterguard scan --profile-dir "$WORK" || echo "exit: $?"
  echo ""
  echo "\$ filterguard filters --filters my-filters.txt"
  filterguard filters --filters "$FILTERS" || echo "exit: $?"
  echo ""
  echo "\$ filterguard check --profile-dir fixture-profile --filters my-filters.txt"
  filterguard check --profile-dir "$WORK" --filters "$FILTERS" || echo "exit: $?"
  echo ""
  echo "\$ filterguard explain \"example.com#%#//scriptlet('trusted-rpnt', 'test', 'test')\""
  filterguard explain "example.com#%#//scriptlet('trusted-rpnt', 'test', 'test')" || echo "exit: $?"
  echo ""
  echo "# Fix: update uBlock Origin to 1.76.4, delete the planted rule,"
  echo "# keep the trusted rule you wrote, baseline the reviewed state"
  UBO_NEW="$WORK/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.76.4"
  mkdir -p "$UBO_NEW"
  cat > "$UBO_NEW/manifest.json" <<'EOF'
{
  "manifest_version": 2,
  "name": "uBlock Origin",
  "version": "1.76.4",
  "permissions": ["webRequest", "storage"],
  "host_permissions": ["<all_urls>"],
  "update_url": "https://clients2.google.com/service/update2/crx"
}
EOF
  rm -rf "$WORK/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.75.2"
  cat > "$FILTERS" <<'EOF'
! My filters - SYNTHETIC fixture (not a real filter list)
||ads.example.com^
example.com##.ad-banner
@@||example.com^$document
example.org##+js(trusted-set, localStorage, myFlag, 1)
EOF
  echo "\$ filterguard scan --profile-dir fixture-profile --save-baseline baseline.json"
  filterguard scan --profile-dir "$WORK" --save-baseline "$SCRATCH/baseline.json" 2>&1 || echo "exit: $?"
  echo "\$ filterguard filters --filters my-filters.txt --save-baseline baseline.json"
  filterguard filters --filters "$FILTERS" --save-baseline "$SCRATCH/baseline.json" 2>&1 || echo "exit: $?"
  echo ""
  echo "\$ filterguard check --profile-dir fixture-profile --filters my-filters.txt --baseline baseline.json"
  filterguard check --profile-dir "$WORK" --filters "$FILTERS" --baseline "$SCRATCH/baseline.json" || echo "exit: $?"
} > "$OUT" 2>&1

echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
