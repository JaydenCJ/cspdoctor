// Layer-2 rules: what the policy effectively allows. Severity here
// depends on which contexts a directive really governs after fallback
// resolution — the part generic header checkers get wrong.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { byCode, codes, findings, GOOD_NONCE, GOOD_SHA256 } from "./helpers.mjs";

test("E110: 'unsafe-inline' in script-src, or in default-src when it governs scripts", () => {
  assert.ok(codes(findings("script-src 'self' 'unsafe-inline'")).includes("E110"));
  const viaDefault = byCode(findings("default-src 'unsafe-inline'"), "E110");
  assert.match(viaDefault[0].message, /default-src is what governs/);
  // …but not when script-src overrides the weak default-src.
  assert.ok(
    !codes(findings("default-src 'unsafe-inline'; script-src 'self'; style-src 'self'")).includes(
      "E110"
    )
  );
});

test("I301: a VALID nonce or hash neutralizes 'unsafe-inline'; an invalid one does not", () => {
  const withNonce = findings(`script-src 'nonce-${GOOD_NONCE}' 'unsafe-inline'`);
  assert.ok(!codes(withNonce).includes("E110"));
  assert.ok(codes(withNonce).includes("I301"));
  assert.ok(codes(findings(`script-src '${GOOD_SHA256}' 'unsafe-inline'`)).includes("I301"));
  const invalid = findings("script-src 'nonce-###' 'unsafe-inline'");
  assert.ok(codes(invalid).includes("E110"));
  assert.ok(!codes(invalid).includes("I301"));
});

test("W210: 'unsafe-inline' in a style context is the CSS-injection warning", () => {
  const list = findings("style-src 'self' 'unsafe-inline'");
  assert.ok(codes(list).includes("W210"));
  assert.ok(!codes(list).includes("E110"));
});

test("E111: 'unsafe-eval' where it actually governs eval", () => {
  assert.ok(codes(findings("script-src 'unsafe-eval'")).includes("E111"));
  assert.ok(codes(findings("default-src 'unsafe-eval'")).includes("E111"));
  // In script-src-elem eval is not governed: W214 (ignored), not E111.
  const elem = findings("script-src-elem 'unsafe-eval'; script-src 'self'");
  assert.ok(!codes(elem).includes("E111"));
  assert.ok(codes(elem).includes("W214"));
});

test("E106: 'strict-dynamic' without any valid nonce/hash blocks all scripts", () => {
  assert.ok(codes(findings("script-src 'strict-dynamic' 'self'")).includes("E106"));
  assert.ok(!codes(findings(`script-src 'strict-dynamic' 'nonce-${GOOD_NONCE}'`)).includes("E106"));
});

test("I302: with 'strict-dynamic', the host/scheme allowlist is inert, not flagged", () => {
  const list = findings(
    `script-src 'nonce-${GOOD_NONCE}' 'strict-dynamic' https: ajax.googleapis.com`
  );
  assert.ok(codes(list).includes("I302"));
  // https: and the bypass host must NOT be graded — CSP3 browsers ignore them.
  assert.ok(!codes(list).includes("E113"));
  assert.ok(!codes(list).includes("W215"));
});

test("E112: wildcards in code-execution contexts, wherever they land via fallback", () => {
  assert.ok(codes(findings("script-src *")).includes("E112"));
  assert.ok(codes(findings("object-src *")).includes("E112"));
  assert.ok(codes(findings("base-uri *")).includes("E112"));
  assert.ok(codes(findings("default-src *")).includes("E112"));
  const viaWildcardHost = findings("script-src https://*");
  assert.ok(codes(viaWildcardHost).includes("E112"));
});

test("wildcard severity degrades as critical contexts get overridden", () => {
  // default-src * still governs connect-src -> W211, not E112.
  const medium = findings(
    "default-src *; script-src 'self'; object-src 'none'; base-uri 'none'; worker-src 'self'"
  );
  assert.ok(!codes(medium).includes("E112"));
  assert.ok(codes(medium).includes("W211"));
  // Everything sensitive overridden -> only the low-risk I306 remains.
  const low = findings(
    "default-src *; script-src 'self'; object-src 'none'; base-uri 'none'; worker-src 'self'; " +
      "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; frame-src 'none'; " +
      "style-src 'self'; manifest-src 'self'"
  );
  assert.ok(!codes(low).includes("W211"));
  assert.ok(codes(low).includes("I306"));
});

test("W211 names the consequence for the most consequential governed context", () => {
  assert.match(byCode(findings("connect-src *"), "W211")[0].message, /exfiltrate/);
  assert.match(byCode(findings("form-action *"), "W211")[0].message, /submit user input anywhere/);
  assert.match(byCode(findings("frame-ancestors *"), "W211")[0].message, /clickjacking/);
});

test("E113: broad schemes in script/object/base contexts, with per-scheme messages", () => {
  const data = byCode(findings("script-src data:"), "E113");
  assert.match(data[0].message, /no server involved/);
  const https = byCode(findings("script-src https:"), "E113");
  assert.match(https[0].message, /not "HTTPS only"/);
  assert.ok(codes(findings("object-src data:")).includes("E113"));
  // data: in img-src is everyday practice — no E113.
  assert.ok(!codes(findings("img-src data:; script-src 'self'")).includes("E113"));
});

test("W212: unencrypted transport for hosts and schemes, loopback exempt", () => {
  assert.ok(codes(findings("img-src http://cdn.example.test")).includes("W212"));
  assert.ok(codes(findings("connect-src ws://feed.example.test")).includes("W212"));
  assert.ok(!codes(findings("connect-src http://127.0.0.1:8080")).includes("W212"));
  assert.ok(!codes(findings("connect-src http://localhost:3000")).includes("W212"));
  // http: as a scheme in a non-critical directive warns rather than errors…
  assert.ok(codes(findings("img-src http:; script-src 'self'")).includes("W212"));
  // …while in a script context it is E113 (broad) without a duplicate W212.
  const scripted = findings("script-src http:");
  assert.ok(codes(scripted).includes("E113"));
  assert.equal(byCode(scripted, "W212").length, 0);
});

test("W215: known bypass hosts, exact and via wildcard subdomains — script contexts only", () => {
  const exact = byCode(findings("script-src 'self' ajax.googleapis.com"), "W215");
  assert.match(exact[0].message, /AngularJS/);
  const wildcard = byCode(findings("script-src 'self' *.googleapis.com"), "W215");
  assert.ok(wildcard.length >= 1);
  assert.match(wildcard[0].message, /also admits/);
  // The same host in img-src is not a script-execution risk.
  assert.ok(!codes(findings("img-src ajax.googleapis.com; script-src 'self'")).includes("W215"));
});

test("I307/I308: wasm and unsafe-hashes are notices, not errors", () => {
  const list = findings(`script-src 'self' 'wasm-unsafe-eval' 'unsafe-hashes' '${GOOD_SHA256}'`);
  assert.ok(codes(list).includes("I307"));
  assert.ok(codes(list).includes("I308"));
  assert.ok(!codes(list).includes("E111"));
});
