#!/usr/bin/env bash
# Example CI gate: fail the pipeline when a deployment's CSP regresses.
#
# In a real pipeline you would capture the headers of the environment you
# are gating, e.g.:
#
#   curl -sI https://staging.example.test/ > headers.txt
#
# This example uses the bundled captures so it runs fully offline.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CLI="node dist/cli.js"

echo "== gating the strict policy (should pass) =="
$CLI check --file examples/strict.txt --fail-on warning -q

echo
echo "== gating the weak policy (should fail; the if/else shows handling the exit code) =="
if $CLI check --file examples/weak.txt --fail-on warning -q; then
  echo "unexpected: weak policy passed" >&2
  exit 1
else
  echo "weak policy correctly rejected (exit $?)"
fi

echo
echo "ci-gate example finished"
