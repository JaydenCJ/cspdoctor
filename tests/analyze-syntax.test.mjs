// Layer-1 rules: what was literally written. Quoting mistakes, typos,
// malformed nonces/hashes, duplicates, deprecations and <meta> delivery.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { RULES } from "../dist/index.js";
import { byCode, codes, findings, GOOD_NONCE } from "./helpers.mjs";

test("E101: an unquoted keyword is called out as the host source it became", () => {
  const list = byCode(findings("script-src self unsafe-inline"), "E101");
  assert.equal(list.length, 2);
  assert.match(list[1].message, /host named "unsafe-inline"/);
  assert.match(list[1].fix, /'unsafe-inline'/);
  // Unquoted nonce-/sha256- sources are the same footgun.
  assert.equal(byCode(findings(`script-src nonce-${GOOD_NONCE} sha256-QUJD`), "E101").length, 2);
});

test("a real host that merely contains a keyword-ish label is not E101", () => {
  assert.ok(!codes(findings("script-src self.example.test")).includes("E101"));
  assert.ok(!codes(findings("script-src https://unsafe-inline")).includes("E101"));
});

test("E102: typo'd quoted keyword gets a did-you-mean", () => {
  const [finding] = byCode(findings("script-src 'unsafe-inlin'"), "E102");
  assert.equal(finding.fix, "did you mean 'unsafe-inline'?");
});

test("E103 for malformed nonces; W213 for valid-but-short nonces", () => {
  assert.ok(codes(findings("script-src 'nonce-###'")).includes("E103"));
  const short = byCode(findings("script-src 'nonce-QUJD'"), "W213");
  assert.equal(short.length, 1);
  assert.match(short[0].message, /24 bits/);
  // A 128-bit nonce triggers neither.
  const good = codes(findings(`script-src 'nonce-${GOOD_NONCE}'`));
  assert.ok(!good.includes("E103") && !good.includes("W213"));
});

test("E104: wrong digest length and unknown algorithms are distinguished", () => {
  const wrongLength = byCode(findings("script-src 'sha256-QUJD'"), "E104");
  assert.match(wrongLength[0].message, /decodes to 32 bytes/);
  const badAlgo = byCode(findings("script-src 'sha1-QUJDREVGRw=='"), "E104");
  assert.match(badAlgo[0].message, /not a CSP hash algorithm/);
});

test("E105: unparseable tokens are reported, not silently dropped", () => {
  const [finding] = byCode(findings("script-src 'self; img-src *"), "E105");
  assert.match(finding.message, /not a valid source expression/);
});

test("W201: unknown directives get a did-you-mean", () => {
  const [finding] = byCode(findings("script-source 'self'; default-src 'self'"), "W201");
  assert.equal(finding.fix, "did you mean script-src?");
});

test("W202: the ignored duplicate is flagged and not otherwise analyzed", () => {
  const list = findings("script-src 'self'; script-src 'unsafe-inline'");
  assert.equal(byCode(list, "W202").length, 1);
  // The duplicate's 'unsafe-inline' must NOT produce E110 — browsers never see it.
  assert.ok(!codes(list).includes("E110"));
});

test("W203: deprecated directives name their replacement", () => {
  const [finding] = byCode(findings("default-src 'self'; plugin-types application/pdf"), "W203");
  assert.equal(finding.fix, "use object-src 'none' instead");
});

test("W204 fires for header-only directives only under --context meta", () => {
  const raw = "default-src 'self'; frame-ancestors 'none'; sandbox";
  assert.ok(!codes(findings(raw)).includes("W204"));
  const metaFindings = findings(raw, { context: "meta" });
  assert.equal(byCode(metaFindings, "W204").length, 2);
});

test("W205/W206: empty source lists and 'none' mixed with other sources", () => {
  const [empty] = byCode(findings("default-src 'self'; script-src"), "W205");
  assert.match(empty.message, /behaves exactly like 'none'/);
  assert.ok(codes(findings("script-src 'none' 'self'")).includes("W206"));
  assert.ok(!codes(findings("script-src 'none'")).includes("W206"));
});

test("W214: keywords and nonces in directives where browsers ignore them", () => {
  assert.ok(codes(findings("style-src 'unsafe-eval'")).includes("W214"));
  assert.ok(codes(findings(`frame-ancestors 'nonce-${GOOD_NONCE}'`)).includes("W214"));
  assert.ok(!codes(findings("script-src 'unsafe-eval'")).includes("W214"));
});

test("every emitted code exists in the rule catalog with matching severity", () => {
  const list = findings(
    "bogus-directive x; script-src 'none' self 'unsafe-inlin' 'nonce-#' 'sha256-QUJD' %22 *; " +
      "script-src dup; style-src unsafe-inline 'unsafe-eval'; img-src http://cdn.example.test"
  );
  assert.ok(list.length >= 10);
  for (const finding of list) {
    const rule = RULES.get(finding.code);
    assert.notEqual(rule, undefined, finding.code);
    assert.equal(finding.severity, rule.severity, finding.code);
  }
});
