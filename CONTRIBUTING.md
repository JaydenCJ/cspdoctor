# Contributing to cspdoctor

Issues, discussions and pull requests are all welcome — this project aims
to stay small, zero-dependency at runtime, and honest about what it flags.

## Getting started

Requirements: Node.js >= 22.13 (for the stable `node:test` runner used by the suite).

```bash
git clone https://github.com/JaydenCJ/cspdoctor.git
cd cspdoctor
npm install            # installs typescript, the only devDependency
npm run build          # compile TypeScript to dist/
npm test               # build + 90 node:test tests
bash scripts/smoke.sh  # end-to-end CLI check against examples/
```

`scripts/smoke.sh` exercises the real CLI (check, coverage, explain, exit
codes, --fail-on, --context meta, JSON output, stdin/header input,
determinism) against the bundled example policies and must print `SMOKE OK`.

## Before you open a pull request

1. `npx tsc -p tsconfig.json --noEmit` — the tree must type-check clean (strict mode is enforced).
2. `npm test` — all tests must pass.
3. `bash scripts/smoke.sh` — must print `SMOKE OK`.
4. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (parsing, classification, resolution and analysis all take
   values, not file handles — only the CLI touches the filesystem).
5. New diagnostics need a row in `docs/rules.md`, a stable code that is
   never reused, an `explain` entry, and at least one test.

## Ground rules

- **No runtime dependencies.** The zero-dependency install is a core
  feature; adding one needs justification in the PR and will usually be
  declined.
- No network calls, ever — the tool reads arguments, files and stdin,
  then prints. That is the whole I/O surface.
- Rule codes (`E1xx`/`W2xx`/`I3xx`) are stable API: never renumber or
  repurpose an existing code; add new ones instead.
- Severity must track real-world exploitability of the *effective*
  policy, not the literal text — grade findings after fallback
  resolution, the way browsers do.
- Additions to the bypass-host corpus (`src/intel.ts`) need a public,
  citable reason; speculation is not a finding.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include: `cspdoctor --version` output, the exact command line, and
the smallest policy string that reproduces the problem — one directive is
usually enough. If you believe a finding is wrong (or missing), say what
a browser actually does with that policy; browser-observable behavior is
the tiebreaker.

## Security

Do not open public issues for security problems; use GitHub private
vulnerability reporting on this repository instead.
