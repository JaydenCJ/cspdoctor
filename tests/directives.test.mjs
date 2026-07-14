// The directive registry: fallback chains, delivery restrictions and
// keyword applicability. These facts drive both the analyzer and
// `cspdoctor coverage`, so they are pinned as spec knowledge.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  CONTEXTS,
  DIRECTIVES,
  keywordMeaningfulIn,
  nonceHashMeaningfulIn,
} from "../dist/index.js";

test("fallback chains match CSP3 (worker-src is the tricky one)", () => {
  assert.deepEqual(DIRECTIVES.get("worker-src").fallback, [
    "child-src",
    "script-src",
    "default-src",
  ]);
  assert.deepEqual(DIRECTIVES.get("frame-src").fallback, ["child-src", "default-src"]);
  assert.deepEqual(DIRECTIVES.get("script-src-elem").fallback, ["script-src", "default-src"]);
  assert.deepEqual(DIRECTIVES.get("style-src-attr").fallback, ["style-src", "default-src"]);
});

test("base-uri, form-action and frame-ancestors never fall back", () => {
  for (const name of ["base-uri", "form-action", "frame-ancestors"]) {
    assert.deepEqual(DIRECTIVES.get(name).fallback, [], name);
  }
});

test("header-only and deprecated directives are marked as such", () => {
  for (const name of ["frame-ancestors", "sandbox", "report-uri"]) {
    assert.equal(DIRECTIVES.get(name).metaAllowed, false, name);
  }
  assert.equal(DIRECTIVES.get("script-src").metaAllowed, true);
  assert.match(DIRECTIVES.get("block-all-mixed-content").deprecated.note, /default/);
  assert.equal(DIRECTIVES.get("plugin-types").deprecated.replacement, "object-src 'none'");
  assert.equal(DIRECTIVES.get("script-src").deprecated, null);
});

test("keyword applicability: 'unsafe-eval' is a script-src thing", () => {
  assert.equal(keywordMeaningfulIn("unsafe-eval", "script-src"), true);
  assert.equal(keywordMeaningfulIn("unsafe-eval", "style-src"), false);
  assert.equal(keywordMeaningfulIn("unsafe-inline", "style-src"), true);
  assert.equal(keywordMeaningfulIn("unsafe-inline", "frame-ancestors"), false);
  assert.equal(keywordMeaningfulIn("strict-dynamic", "img-src"), false);
  // 'self' and 'none' are meaningful in every source-list directive.
  assert.equal(keywordMeaningfulIn("self", "frame-ancestors"), true);
});

test("nonces and hashes only participate in script/style directives", () => {
  assert.equal(nonceHashMeaningfulIn("script-src"), true);
  assert.equal(nonceHashMeaningfulIn("style-src-elem"), true);
  assert.equal(nonceHashMeaningfulIn("frame-ancestors"), false);
  assert.equal(nonceHashMeaningfulIn("connect-src"), false);
});

test("every graded context is a known source-list directive", () => {
  for (const context of CONTEXTS) {
    const info = DIRECTIVES.get(context);
    assert.notEqual(info, undefined, context);
    assert.equal(info.sourceList, true, context);
  }
});
