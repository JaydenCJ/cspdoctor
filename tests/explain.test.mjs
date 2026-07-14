// The explain knowledge base: rule codes, directives, keywords and
// concept topics must all resolve, and misses must suggest something.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { explainSuggestion, explainTopic, ruleList } from "../dist/index.js";

test("rule codes resolve case-insensitively; every catalog rule is explainable", () => {
  const entry = explainTopic("e110");
  assert.match(entry, /^E110 \(error\)/);
  assert.match(entry, /XSS/);
  for (const rule of ruleList()) {
    const each = explainTopic(rule.code);
    assert.notEqual(each, null, rule.code);
    assert.ok(each.includes(rule.title), rule.code);
  }
});

test("directives resolve with their fallback chain spelled out", () => {
  const entry = explainTopic("worker-src");
  assert.match(entry, /child-src -> script-src -> default-src/);
  assert.match(explainTopic("frame-ancestors"), /Header-only/);
  assert.match(explainTopic("base-uri"), /No fallback/);
});

test("keywords resolve with or without quotes, and aliases map to hash/nonce", () => {
  assert.match(explainTopic("'strict-dynamic'"), /nonce or hash/);
  assert.match(explainTopic("strict-dynamic"), /nonce or hash/);
  assert.match(explainTopic("sha256"), /hash/i);
  assert.match(explainTopic("nonces"), /128 bits/);
});

test("concept topics resolve", () => {
  assert.match(explainTopic("fallbacks"), /fall back to NOTHING/);
  assert.match(explainTopic("strict-csp"), /'strict-dynamic'/);
  assert.match(explainTopic("exit-codes"), /--fail-on/);
});

test("unknown topics return null and a plausible suggestion", () => {
  assert.equal(explainTopic("script-source"), null);
  assert.equal(explainSuggestion("script-source"), "script-src");
  assert.equal(explainSuggestion("qqqqqqqq"), null);
});
