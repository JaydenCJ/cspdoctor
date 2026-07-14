// Layer-3 rules: what the policy forgot. Missing directives are graded
// against the real fallback semantics — base-uri/form-action/
// frame-ancestors never inherit from default-src, and that is the point.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { byCode, codes, findings } from "./helpers.mjs";

const HARDENED =
  "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; " +
  "form-action 'self'; upgrade-insecure-requests; report-to csp";

test("E114: no script-src and no default-src means scripts are unrestricted", () => {
  const list = findings("img-src 'self'");
  assert.ok(codes(list).includes("E114"));
  assert.match(byCode(list, "E114")[0].message, /does not mitigate XSS/);
  // Satisfied by default-src, script-src, or script-src-elem.
  assert.ok(!codes(findings("default-src 'self'")).includes("E114"));
  assert.ok(!codes(findings("script-src 'self'")).includes("E114"));
  assert.ok(!codes(findings("script-src-elem 'self'")).includes("E114"));
});

test("E115: missing object-src without a default-src fallback", () => {
  assert.ok(codes(findings("script-src 'self'")).includes("E115"));
  assert.ok(!codes(findings("default-src 'self'")).includes("E115"));
  assert.ok(!codes(findings("script-src 'self'; object-src 'none'")).includes("E115"));
});

test("W207/W208/W209: the no-fallback trio is flagged even with default-src set", () => {
  const list = codes(findings("default-src 'none'"));
  assert.ok(list.includes("W207"));
  assert.ok(list.includes("W208"));
  assert.ok(list.includes("W209"));
});

test("the hardened baseline clears every missing-directive rule", () => {
  const list = codes(findings(HARDENED));
  for (const code of ["E114", "E115", "W207", "W208", "W209", "I303", "I304"]) {
    assert.ok(!list.includes(code), code);
  }
});

test("W208 message adapts to <meta> delivery, where the header is the only fix", () => {
  const [finding] = byCode(findings("default-src 'self'", { context: "meta" }), "W208");
  assert.match(finding.message, /not <meta>/);
});

test("I303/I305: reporting posture", () => {
  assert.ok(codes(findings("default-src 'self'")).includes("I303"));
  const uriOnly = findings("default-src 'self'; report-uri /csp");
  assert.ok(codes(uriOnly).includes("I305"));
  assert.ok(!codes(uriOnly).includes("I303"));
  const both = findings("default-src 'self'; report-uri /csp; report-to csp");
  assert.ok(!codes(both).includes("I305"));
});

test("I309: report-only policies are labeled as enforcing nothing", () => {
  const list = findings("default-src 'self'", { reportOnly: true });
  assert.ok(codes(list).includes("I309"));
});

test("an empty policy produces no missing-directive noise", () => {
  assert.deepEqual(findings(";;"), []);
});

test("findings are ordered errors, then warnings, then info", () => {
  const list = findings("img-src *; script-src 'unsafe-inline' bogus-src 'self'");
  const ranks = list.map((f) => ({ error: 0, warning: 1, info: 2 })[f.severity]);
  assert.deepEqual([...ranks].sort((a, b) => a - b), ranks);
  assert.equal(list[0].severity, "error");
});
