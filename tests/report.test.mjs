// Renderers: text for humans, JSON for CI. Output is plain (no color,
// no TTY detection) so it is byte-deterministic and grep-safe.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  checkPolicies,
  coverageRows,
  renderCoverageJson,
  renderCoverageText,
  renderJson,
  renderText,
  VERSION,
} from "../dist/index.js";
import { policy } from "./helpers.mjs";

function run(raw, options = {}) {
  return checkPolicies([policy(raw, options)], options);
}

test("text output carries the label, message, fix and FAIL summary", () => {
  const text = renderText(run("script-src 'unsafe-inline'"));
  assert.match(text, /error E110 script-src › 'unsafe-inline'/);
  assert.match(text, /fix: move inline code to nonced or hashed scripts/);
  assert.match(text, /cspdoctor: FAIL — /);
  assert.match(text, /\(fail-on: warning\)/);
  // Counts pluralize like prose: "1 directive" here, "2 errors" (E110 + E115).
  assert.match(text, /policy 1 \(enforced\): 1 directive — /);
  assert.match(renderText(run("script-src 'unsafe-inline'; object-src 'none'")), /— 1 error, /);
  // Missing-directive findings render as "<name> (not set)".
  assert.match(renderText(run("default-src 'self'")), /warning W207 base-uri \(not set\)/);
});

test("a clean strict policy renders OK and exits clean", () => {
  const result = run(
    "default-src 'self'; script-src 'nonce-Y2FmZWJhYmVjYWZlYmFiZQ' 'strict-dynamic'; " +
      "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; " +
      "upgrade-insecure-requests; report-to csp"
  );
  assert.equal(result.ok, true);
  assert.match(renderText(result), /cspdoctor: OK — 0 errors, 0 warnings/);
});

test("quiet mode keeps only per-policy and summary lines; report-only is labeled", () => {
  const text = renderText(run("script-src 'unsafe-inline'"), { quiet: true });
  assert.equal(text.split("\n").length, 4); // policy line, blank, summary, trailing \n
  assert.ok(!text.includes("E110"));
  assert.match(text, /policy 1 \(enforced\)/);
  const reportOnly = renderText(run("default-src 'self'", { reportOnly: true }));
  assert.match(reportOnly, /policy 1 \(report-only\)/);
});

test("JSON output is valid, versioned, and structurally stable", () => {
  const parsed = JSON.parse(renderJson(run("script-src 'unsafe-inline'", { failOn: "error" })));
  assert.equal(parsed.tool, "cspdoctor");
  assert.equal(parsed.version, VERSION);
  assert.equal(parsed.failOn, "error");
  assert.equal(parsed.ok, false);
  assert.equal(parsed.policies.length, 1);
  const finding = parsed.policies[0].findings.find((f) => f.code === "E110");
  assert.equal(finding.severity, "error");
  assert.equal(finding.directive, "script-src");
  assert.equal(finding.source, "'unsafe-inline'");
  assert.equal(typeof finding.fix, "string");
});

test("fail levels move the ok verdict, and 'never' always passes", () => {
  const raw = "default-src 'self'"; // warnings + info, no errors
  assert.equal(run(raw, { failOn: "error" }).ok, true);
  assert.equal(run(raw, { failOn: "warning" }).ok, false);
  assert.equal(run(raw, { failOn: "info" }).ok, false);
  assert.equal(run("script-src *", { failOn: "never" }).ok, true);
});

test("coverage text marks fallbacks with an arrow and unset contexts as unrestricted", () => {
  const text = renderCoverageText(coverageRows(policy("default-src 'self'")), 1);
  assert.match(text, /script-src\s+-> default-src\s+'self'/);
  assert.match(text, /base-uri\s+\(unset\)\s+unrestricted/);
  assert.match(text, /frame-ancestors\s+\(unset\)\s+unrestricted \(header-only directive\)/);
});

test("coverage JSON round-trips the same rows", () => {
  const rows = coverageRows(policy("script-src 'self'"));
  const parsed = JSON.parse(renderCoverageJson(rows, 2));
  assert.equal(parsed.policy, 2);
  assert.equal(parsed.coverage.length, rows.length);
  assert.equal(parsed.coverage[0].context, "script-src");
  assert.equal(parsed.coverage[0].viaFallback, false);
});
