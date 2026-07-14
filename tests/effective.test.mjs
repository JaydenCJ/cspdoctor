// Effective-policy resolution: the fallback chains humans get wrong,
// answered from a parsed policy. This is the engine behind both the
// severity grading and `cspdoctor coverage`.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { coverageRows, governedContexts, governing } from "../dist/index.js";
import { policy } from "./helpers.mjs";

test("a fetch context falls back to default-src when unset", () => {
  const parsed = policy("default-src 'self'");
  const resolved = governing(parsed, "img-src");
  assert.equal(resolved.name, "default-src");
});

test("worker-src resolution walks child-src, then script-src, then default-src", () => {
  assert.equal(
    governing(policy("child-src 'self'; script-src 'none'"), "worker-src").name,
    "child-src"
  );
  assert.equal(governing(policy("script-src 'self'"), "worker-src").name, "script-src");
  assert.equal(governing(policy("default-src 'self'"), "worker-src").name, "default-src");
});

test("base-uri never resolves through default-src", () => {
  assert.equal(governing(policy("default-src 'none'"), "base-uri"), null);
});

test("a duplicate directive does not participate in resolution", () => {
  const parsed = policy("script-src 'self'; script-src 'unsafe-inline'");
  const resolved = governing(parsed, "script-src");
  assert.deepEqual(resolved.directive.rawValues, ["'self'"]);
});

test("governedContexts inverts resolution: default-src picks up the rest", () => {
  const map = governedContexts(policy("default-src 'self'; script-src 'none'"));
  const scriptContexts = map.get("script-src");
  assert.ok(scriptContexts.includes("script-src"));
  assert.ok(scriptContexts.includes("worker-src")); // via the chain
  assert.ok(map.get("default-src").includes("img-src"));
  assert.ok(!map.get("default-src").includes("base-uri")); // no fallback
});

test("a fully shadowed directive governs no contexts", () => {
  const map = governedContexts(
    policy(
      "default-src *; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
        "connect-src 'self'; media-src 'self'; object-src 'none'; frame-src 'self'; " +
        "worker-src 'self'; manifest-src 'self'"
    )
  );
  assert.equal(map.get("default-src"), undefined);
});

test("coverageRows: governor, fallback flag, serialized sources, fixed order", () => {
  const rows = coverageRows(policy("default-src 'self'; script-src 'nonce-abc'"));
  const byContext = new Map(rows.map((row) => [row.context, row]));

  assert.deepEqual(byContext.get("script-src"), {
    context: "script-src",
    governedBy: "script-src",
    viaFallback: false,
    sources: "'nonce-abc'",
  });
  assert.equal(byContext.get("img-src").governedBy, "default-src");
  assert.equal(byContext.get("img-src").viaFallback, true);
  assert.equal(byContext.get("base-uri").governedBy, null);
  assert.equal(byContext.get("base-uri").sources, null);
  assert.equal(rows[0].context, "script-src"); // fixed order, all contexts
  assert.equal(rows.length, 17);
});
