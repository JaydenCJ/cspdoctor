#!/usr/bin/env bash
# Smoke test for cspdoctor: exercises the real CLI end to end against the
# bundled example policies and freshly written temp files. No network,
# idempotent, runs from a clean checkout (after `npm install`).
# Prints "SMOKE OK" on success.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$(pwd)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $1" >&2
  exit 1
}

# 1. Build (idempotent).
npm run build >/dev/null 2>&1 || fail "npm run build failed"
CLI="node $ROOT/dist/cli.js"
echo "[smoke] build ok"

# 2. --version matches package.json; --help documents the surface.
PKG_VERSION="$(node -p "require('$ROOT/package.json').version")"
CLI_VERSION="$($CLI --version)"
[ "$CLI_VERSION" = "$PKG_VERSION" ] || fail "--version mismatch: $CLI_VERSION != $PKG_VERSION"
HELP="$($CLI --help)"
for word in check coverage explain --fail-on --context --format "Exit codes"; do
  echo "$HELP" | grep -q -- "$word" || fail "--help missing $word"
done
echo "[smoke] --help/--version ok ($CLI_VERSION)"

# 3. Usage errors exit 2 (distinct from lint findings' 1).
set +e
$CLI --frobnicate >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "unknown flag should exit 2"; }
$CLI check --file "$WORKDIR/nope.txt" >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "missing file should exit 2"; }
$CLI check "" >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "empty policy should exit 2"; }
set -e
echo "[smoke] error handling ok (exit 2)"

# 4. The weak example (a saved curl response) fails with the seeded findings.
set +e
WEAK_OUT="$($CLI check --file examples/weak.txt)"; WEAK_CODE=$?
set -e
[ "$WEAK_CODE" -eq 1 ] || fail "weak.txt should exit 1, got $WEAK_CODE"
echo "$WEAK_OUT" | grep -q '5 errors, 4 warnings, 3 info' || fail "weak.txt counts wrong"
for needle in E101 E110 E111 E112 E113 W215 W207 W208 W209; do
  echo "$WEAK_OUT" | grep -q "$needle" || fail "weak.txt report missing $needle"
done
echo "$WEAK_OUT" | grep -q "host named \"unsafe-inline\"" || fail "missing unquoted-keyword message"
echo "$WEAK_OUT" | grep -q "fix: add: object-src 'none'" || echo "$WEAK_OUT" | grep -q "replace the wildcard" || fail "missing wildcard fix"
echo "[smoke] weak policy ok (5 errors, 4 warnings)"

# 5. The strict-CSP example passes with info-only findings.
$CLI check --file examples/strict.txt >/dev/null || fail "strict.txt should exit 0"
STRICT_OUT="$($CLI check --file examples/strict.txt)"
echo "$STRICT_OUT" | grep -q 'cspdoctor: OK — 0 errors, 0 warnings, 2 info' || fail "strict.txt should be clean"
echo "$STRICT_OUT" | grep -q 'I301' || fail "strict.txt should note the neutralized 'unsafe-inline'"
echo "[smoke] strict policy ok (exit 0)"

# 6. --fail-on moves the gate: legacy.txt has 1 error, 8 warnings.
set +e
$CLI check --file examples/legacy.txt >/dev/null 2>&1; [ $? -eq 1 ] || { set -e; fail "legacy.txt should exit 1 at fail-on warning"; }
$CLI check --file examples/legacy.txt --fail-on never >/dev/null 2>&1; [ $? -eq 0 ] || { set -e; fail "--fail-on never should exit 0"; }
set -e
echo "[smoke] --fail-on ok"

# 7. JSON output is valid JSON with stable fields.
set +e
JSON_OUT="$($CLI check "script-src *" --format json)"; JSON_CODE=$?
set -e
[ "$JSON_CODE" -eq 1 ] || fail "script-src * should exit 1"
echo "$JSON_OUT" | grep -q '"code": "E112"' || fail "JSON output missing E112"
echo "$JSON_OUT" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>JSON.parse(s))" \
  || fail "--format json is not valid JSON"
echo "[smoke] JSON output ok"

# 8. stdin, header stripping and report-only detection.
printf 'Content-Security-Policy-Report-Only: default-src *\n' > "$WORKDIR/ro.txt"
RO_OUT="$($CLI check - < "$WORKDIR/ro.txt" --fail-on never)" || fail "stdin check failed"
echo "$RO_OUT" | grep -q 'policy 1 (report-only)' || fail "report-only header not detected"
echo "$RO_OUT" | grep -q 'I309' || fail "missing report-only notice I309"
echo "[smoke] stdin + header stripping ok"

# 9. coverage resolves the fallback chains.
COV_OUT="$($CLI coverage "default-src 'self'; script-src 'none'")" || fail "coverage failed"
echo "$COV_OUT" | grep -q 'worker-src * -> script-src' || fail "coverage missing worker-src chain"
echo "$COV_OUT" | grep -Eq 'base-uri +\(unset\) +unrestricted' || fail "coverage missing unset base-uri"
echo "[smoke] coverage ok"

# 10. explain answers rule codes and directives; unknown topics exit 2.
$CLI explain E110 | grep -q "XSS" || fail "explain E110 failed"
$CLI explain worker-src | grep -q "child-src -> script-src -> default-src" || fail "explain worker-src failed"
set +e
$CLI explain frobnicate >/dev/null 2>&1; [ $? -eq 2 ] || { set -e; fail "unknown explain topic should exit 2"; }
set -e
echo "[smoke] explain ok"

# 11. --context meta flags header-only directives.
META_OUT="$($CLI check "default-src 'self'; frame-ancestors 'none'" --context meta --fail-on never)" \
  || fail "meta context check failed"
echo "$META_OUT" | grep -q 'W204' || fail "meta context should flag frame-ancestors as W204"
echo "[smoke] --context meta ok"

# 12. Determinism: two runs over the same input are byte-identical.
$CLI check --file examples/weak.txt > "$WORKDIR/run1.txt" 2>/dev/null || true
$CLI check --file examples/weak.txt > "$WORKDIR/run2.txt" 2>/dev/null || true
cmp -s "$WORKDIR/run1.txt" "$WORKDIR/run2.txt" || fail "repeat runs differ"
echo "[smoke] determinism ok"

echo "SMOKE OK"
