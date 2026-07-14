// Flag parsing: the CLI surface is small, so every flag and every
// rejection path is pinned here without touching the filesystem.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CliError, parseCliArgs } from "../dist/cliargs.js";

test("a bare policy argument defaults to the check command", () => {
  const options = parseCliArgs(["default-src 'self'"]);
  assert.equal(options.command, "check");
  assert.equal(options.policy, "default-src 'self'");
});

test("explicit subcommands parse, and '-' is accepted as stdin", () => {
  assert.equal(parseCliArgs(["check", "-"]).policy, "-");
  assert.equal(parseCliArgs(["coverage", "default-src 'self'"]).command, "coverage");
  assert.equal(parseCliArgs(["explain", "E110"]).topic, "E110");
});

test("flags: --file (repeatable), --format, --fail-on, --context, -q; both spellings", () => {
  const options = parseCliArgs([
    "check",
    "--file",
    "a.txt",
    "--file=b.txt",
    "--format",
    "json",
    "--fail-on=error",
    "--context",
    "meta",
    "-q",
  ]);
  assert.deepEqual(options.files, ["a.txt", "b.txt"]);
  assert.equal(options.format, "json");
  assert.equal(options.failOn, "error");
  assert.equal(options.context, "meta");
  assert.equal(options.quiet, true);
  // Every --fail-on level parses, including never.
  for (const level of ["error", "warning", "info", "never"]) {
    assert.equal(parseCliArgs(["check", "x", `--fail-on=${level}`]).failOn, level);
  }
});

test("help and version win regardless of position", () => {
  assert.equal(parseCliArgs(["--help"]).command, "help");
  assert.equal(parseCliArgs(["check", "x", "-V"]).command, "version");
});

test("unknown flags and bad enum values raise CliError", () => {
  assert.throws(() => parseCliArgs(["check", "x", "--frobnicate"]), CliError);
  assert.throws(() => parseCliArgs(["check", "x", "--format", "xml"]), /must be one of/);
  assert.throws(() => parseCliArgs(["check", "x", "--fail-on", "fatal"]), CliError);
  assert.throws(() => parseCliArgs(["check", "--file"]), /needs a value/);
});

test("missing or ambiguous input is rejected with guidance", () => {
  assert.throws(() => parseCliArgs([]), /no policy given/);
  assert.throws(() => parseCliArgs(["check"]), /no policy given/);
  assert.throws(() => parseCliArgs(["check", "x", "--file", "a.txt"]), /not both/);
  assert.throws(() => parseCliArgs(["explain"]), /needs a topic/);
  assert.throws(() => parseCliArgs(["explain", "a", "b"]), /exactly one topic/);
});

test("an unquoted policy (splatted into many arguments) gets the quoting hint", () => {
  assert.throws(
    () => parseCliArgs(["check", "default-src", "'self'"]),
    /quote the policy/
  );
});
