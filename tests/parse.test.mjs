// Policy parsing: the "parse a serialized CSP" algorithm — semicolon
// splitting, whitespace handling, case, duplicates — plus header-line
// extraction from saved responses.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { extractPolicies, parsePolicy } from "../dist/index.js";

test("directives split on semicolons; values on any ASCII whitespace run", () => {
  const parsed = parsePolicy("default-src 'self'; img-src 'self' data:");
  assert.equal(parsed.directives.length, 2);
  assert.deepEqual(parsed.directives[0].rawValues, ["'self'"]);
  assert.deepEqual(parsed.directives[1].rawValues, ["'self'", "data:"]);
  // Tabs and repeated spaces separate values like single spaces.
  assert.deepEqual(
    parsePolicy("script-src\t'self'   https://example.test\t\t'unsafe-eval'").directives[0]
      .rawValues,
    ["'self'", "https://example.test", "'unsafe-eval'"]
  );
});

test("empty segments (;;) are ignored; a valueless directive has no sources", () => {
  const parsed = parsePolicy(";; upgrade-insecure-requests ;; ;");
  assert.equal(parsed.directives.length, 1);
  assert.equal(parsed.directives[0].name, "upgrade-insecure-requests");
  assert.deepEqual(parsed.directives[0].sources, []);
});

test("directive names are lowercased but the raw spelling is kept", () => {
  const parsed = parsePolicy("SCRIPT-SRC 'self'");
  assert.equal(parsed.directives[0].name, "script-src");
  assert.equal(parsed.directives[0].rawName, "SCRIPT-SRC");
});

test("duplicate directives are kept but marked, first occurrence wins", () => {
  const parsed = parsePolicy("script-src 'self'; SCRIPT-src 'unsafe-inline'");
  assert.equal(parsed.directives[0].duplicate, false);
  assert.equal(parsed.directives[1].duplicate, true); // case-insensitive match
});

test("extractPolicies: raw text without header names is one enforced policy", () => {
  assert.deepEqual(extractPolicies("default-src 'self'\n"), [
    { raw: "default-src 'self'", reportOnly: false },
  ]);
  assert.deepEqual(extractPolicies("   \n \n"), []); // blank input: no policies
});

test("extractPolicies: header lines found case-insensitively, report-only tagged, commas split (RFC 9110)", () => {
  const text = [
    "HTTP/2 200",
    "content-type: text/html",
    "Content-Security-Policy: default-src 'self', script-src 'none'",
    "content-security-policy-report-only: img-src *",
    "",
  ].join("\r\n");
  const extracted = extractPolicies(text);
  assert.equal(extracted.length, 3);
  assert.deepEqual(extracted[0], { raw: "default-src 'self'", reportOnly: false });
  assert.deepEqual(extracted[1], { raw: "script-src 'none'", reportOnly: false });
  assert.deepEqual(extracted[2], { raw: "img-src *", reportOnly: true });
  // reportOnly is threaded through parsePolicy's options.
  assert.equal(parsePolicy(extracted[2].raw, { reportOnly: extracted[2].reportOnly }).reportOnly, true);
});
