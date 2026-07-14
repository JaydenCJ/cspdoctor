// CLI integration: the compiled binary, spawned for real, with temp
// files in a per-run directory. Exit codes are the contract under test.
import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { VERSION } from "../dist/index.js";

const CLI = join(import.meta.dirname, "..", "dist", "cli.js");
const WORKDIR = mkdtempSync(join(tmpdir(), "cspdoctor-test-"));
after(() => rmSync(WORKDIR, { recursive: true, force: true }));

/** Run the CLI; never throws — returns { code, stdout, stderr }. */
function run(args, stdin = "") {
  try {
    const stdout = execFileSync("node", [CLI, ...args], {
      encoding: "utf8",
      input: stdin,
    });
    return { code: 0, stdout, stderr: "" };
  } catch (error) {
    return { code: error.status, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
  }
}

test("--version prints the package version; --help documents the surface", () => {
  assert.equal(run(["--version"]).stdout.trim(), VERSION);
  const help = run(["--help"]).stdout;
  for (const needle of ["check", "coverage", "explain", "--fail-on", "--context", "Exit codes"]) {
    assert.ok(help.includes(needle), needle);
  }
});

test("usage errors exit 2 and point at --help", () => {
  const unknown = run(["check", "x", "--frobnicate"]);
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /unknown flag/);
  assert.equal(run(["check", "--file", join(WORKDIR, "missing.txt")]).code, 2);
  assert.equal(run(["check", ""]).code, 2); // empty policy string
});

test("a weak policy exits 1 with findings; --fail-on error can relax it", () => {
  const raw = "default-src 'self'"; // warnings, no errors
  const strict = run(["check", raw]);
  assert.equal(strict.code, 1);
  assert.match(strict.stdout, /W207/);
  assert.equal(run(["check", raw, "--fail-on", "error"]).code, 0);
  // An error-level policy fails even at --fail-on error.
  const errors = run(["check", "script-src 'unsafe-inline' *", "--fail-on", "error"]);
  assert.equal(errors.code, 1);
  assert.match(errors.stdout, /E110/);
  assert.match(errors.stdout, /E112/);
});

test("--format json emits machine-readable output with the same verdict", () => {
  const result = run(["check", "script-src *", "--format", "json"]);
  assert.equal(result.code, 1);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, false);
  assert.ok(parsed.policies[0].findings.some((f) => f.code === "E112"));
});

test("--file reads saved header lines, splits policies, and flags report-only", () => {
  const file = join(WORKDIR, "headers.txt");
  writeFileSync(
    file,
    "HTTP/2 200\r\n" +
      "Content-Security-Policy: default-src 'self'\r\n" +
      "Content-Security-Policy-Report-Only: script-src 'none'\r\n\r\n"
  );
  const result = run(["check", "--file", file]);
  assert.equal(result.code, 1);
  assert.match(result.stdout, /policy 1 \(enforced\)/);
  assert.match(result.stdout, /policy 2 \(report-only\)/);
  assert.match(result.stdout, /I309/);
});

test("stdin via '-' works for piped headers", () => {
  const result = run(["check", "-"], "Content-Security-Policy: script-src 'unsafe-eval'\n");
  assert.equal(result.code, 1);
  assert.match(result.stdout, /E111/);
});

test("coverage prints the resolution table and exits 0", () => {
  const result = run(["coverage", "default-src 'self'; script-src 'none'"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /worker-src\s+-> script-src/);
  assert.match(result.stdout, /base-uri\s+\(unset\)\s+unrestricted/);
});

test("explain resolves topics and exits 2 on unknown ones with a suggestion", () => {
  const known = run(["explain", "E112"]);
  assert.equal(known.code, 0);
  assert.match(known.stdout, /wildcard/i);
  const unknown = run(["explain", "script-source"]);
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /Did you mean: script-src\?/);
});

test("output is byte-deterministic across runs", () => {
  const args = ["check", "default-src *; script-src 'unsafe-inline' https:"];
  assert.equal(run(args).stdout, run(args).stdout);
});
