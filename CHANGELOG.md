# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-12

### Added

- `cspdoctor check`: parses one or more Content-Security-Policy values —
  raw strings, saved header lines (`Content-Security-Policy` and
  `-Report-Only`, comma-combined values split per RFC 9110), files or
  stdin — and grades them with a 36-rule catalog.
- Full CSP3 source-expression classifier: keywords (case-insensitive,
  quote-aware), nonces (base64 validity + entropy in bits), hashes
  (algorithm + digest-length validation), schemes, host sources with
  wildcard hosts/subdomains/ports and paths.
- Effective-policy grading: fallback chains are resolved first
  (`worker-src` → `child-src` → `script-src` → `default-src`, the
  no-fallback trio `base-uri`/`form-action`/`frame-ancestors`), so
  `default-src *` is an error while it governs scripts and degrades as
  critical directives override it.
- The classic footguns as first-class rules: unquoted keywords parsed as
  hosts (E101), typo'd keywords with did-you-mean (E102), 'none' mixed
  with other sources (W206), duplicate directives (W202),
  'strict-dynamic' without a nonce/hash (E106), nonce/hash neutralization
  of 'unsafe-inline' reported honestly (I301/I302).
- A curated known-bypass host corpus (JSONP endpoints, AngularJS CDNs,
  arbitrary-content hosts) flagged only where a host can reach a script
  context (W215).
- Missing-directive rules with real fallback semantics: unrestricted
  scripts (E114), missing `object-src 'none'` (E115), and the
  never-falls-back trio W207/W208/W209.
- `cspdoctor coverage`: prints which directive actually governs each of
  17 load contexts, with fallback arrows and unrestricted surfaces.
- `cspdoctor explain`: offline documentation for every rule code,
  directive, keyword and concept (fallbacks, strict-csp, exit-codes,
  meta, report-only), with did-you-mean on unknown topics.
- CI-ready surface: `--fail-on error|warning|info|never` (default
  warning), `--format json` with a stable shape, `--context header|meta`,
  `--quiet`, and exit codes 0 (clean) / 1 (findings) / 2 (usage error).
- Public programmatic API (`parsePolicy`, `extractPolicies`,
  `classifySource`, `analyzePolicy`, `checkPolicies`, `governing`,
  `coverageRows`, renderers) with type declarations.
- Test suite: 90 node:test tests (unit + CLI integration in fresh temp
  dirs) and an end-to-end `scripts/smoke.sh` against the bundled weak /
  legacy / strict example policies.

[0.1.0]: https://github.com/JaydenCJ/cspdoctor/releases/tag/v0.1.0
