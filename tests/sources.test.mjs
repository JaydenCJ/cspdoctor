// Source-expression classification: every branch of the CSP3 grammar,
// including the deliberately browser-faithful edge cases (unquoted
// keywords become hosts, typo'd quoted keywords match nothing).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { classifySource, decodedByteLength, isBase64Value } from "../dist/index.js";
import { GOOD_NONCE } from "./helpers.mjs";

test("quoted keywords classify case-insensitively; typos become quoted-unknown", () => {
  const source = classifySource("'SELF'");
  assert.equal(source.kind, "keyword");
  assert.equal(source.name, "self");
  assert.equal(source.raw, "'SELF'");
  assert.equal(classifySource("'strict-dynamic'").name, "strict-dynamic");
  const typo = classifySource("'unsafe-inlin'");
  assert.equal(typo.kind, "quoted-unknown");
  assert.equal(typo.name, "unsafe-inlin");
});

test("a valid nonce reports its decoded entropy in bits", () => {
  const source = classifySource(`'nonce-${GOOD_NONCE}'`);
  assert.equal(source.kind, "nonce");
  assert.equal(source.valid, true);
  assert.equal(source.bits, 128);
});

test("nonce validity: empty, non-base64 and impossible-length payloads are invalid", () => {
  assert.equal(classifySource("'nonce-'").valid, false);
  assert.equal(classifySource("'nonce-###'").valid, false);
  assert.equal(classifySource("'nonce-QUJDA'").valid, false); // length % 4 === 1
  // URL-safe alphabet is fine per the CSP base64-value grammar.
  assert.equal(classifySource("'nonce-abc-_1234567890abcdefgh'").valid, true);
});

test("hash sources validate algorithm and digest length", () => {
  const ok = classifySource("'sha256-" + "A".repeat(43) + "='");
  assert.equal(ok.kind, "hash");
  assert.equal(ok.valid, true);

  const short = classifySource("'sha256-QUJD'");
  assert.equal(short.valid, false);
  assert.match(short.reason, /32 bytes/);

  assert.equal(classifySource("'sha384-" + "B".repeat(64) + "'").valid, true);
  // Unknown algorithms are hash *attempts* with a targeted reason.
  const sha1 = classifySource("'sha1-QUJDREVGRw=='");
  assert.equal(sha1.kind, "hash");
  assert.match(sha1.reason, /not a CSP hash algorithm/);
});

test("bare schemes and full host sources parse into their parts", () => {
  const scheme = classifySource("HTTPS:");
  assert.equal(scheme.kind, "scheme");
  assert.equal(scheme.scheme, "https");

  const host = classifySource("https://cdn.example.test:8443/assets/");
  assert.equal(host.kind, "host");
  assert.equal(host.scheme, "https");
  assert.equal(host.host, "cdn.example.test");
  assert.equal(host.port, "8443");
  assert.equal(host.path, "/assets/");
  // Wildcards: bare *, *.example.test subdomains, and port *.
  assert.equal(classifySource("*").wildcardHost, true);
  const sub = classifySource("*.example.test");
  assert.equal(sub.wildcardSubdomain, true);
  assert.equal(sub.wildcardHost, false);
  assert.equal(classifySource("example.test:*").port, "*");
});

test("an unquoted keyword parses as a host source — the browser footgun", () => {
  const source = classifySource("unsafe-inline");
  assert.equal(source.kind, "host");
  assert.equal(source.host, "unsafe-inline");
});

test("broken quoting and out-of-grammar tokens are malformed with reasons", () => {
  assert.equal(classifySource("'self").kind, "malformed");
  assert.equal(classifySource("self'").kind, "malformed");
  assert.match(classifySource("'self").reason, /quotes/);
  assert.equal(classifySource("https://").kind, "malformed");
  assert.equal(classifySource("%22self%22").kind, "malformed");
});

test("base64 helpers agree with the CSP grammar", () => {
  assert.equal(isBase64Value("QUJD"), true);
  assert.equal(isBase64Value("QUJ="), true);
  assert.equal(isBase64Value(""), false);
  assert.equal(isBase64Value("Q"), false); // length % 4 === 1 can never decode
  assert.equal(decodedByteLength("QUJD"), 3);
  assert.equal(decodedByteLength("A".repeat(43) + "="), 32);
});
