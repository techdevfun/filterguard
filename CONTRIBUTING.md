# Contributing

## Development

```sh
npm install
npm run build
npm test        # unit + e2e (fixture profiles built in tmp, synthetic)
npm run test:live  # live smoke; soft-skips on network failure
npm run lint    # eslint + prettier
node scripts/preflight.js  # ASCII-only + no-internal-names scan
```

## Rules

- Zero runtime dependencies. TypeScript strict, Node 20+.
- Every figure cited in the README must come from a live source fetched
  during the build or a recorded fixture labelled as such. No invented
  numbers.
- All public content is English only (ASCII). The preflight script blocks
  anything else, including text inside the demo transcript.
- The tool reports; it never deletes anything. Never add a mode that
  edits a browser profile or a filter list automatically.
- The tool reads only extension manifest.json files and the filter file
  the user points at. Never read history, cookies, passwords, or
  bookmarks. Never add a network call to scan/filters.
- The demo fixtures are synthetic and labelled as such in the
  transcript, the GIF title card, and the README. Never present fixture
  numbers as measurements of a real machine. Live checks against real
  sources go in the build note and README, with the date recorded.
- A HIGH score is about capability, not proof of malice. A content
  blocker legitimately needs broad host access; the baseline is how a
  user records "I reviewed this and I chose it".
