#!/usr/bin/env node
/**
 * The cspdoctor CLI. Thin by design: it reads input, delegates to the
 * pure parse/analyze/render modules, prints, and sets the exit code.
 * Exit codes are stable API: 0 clean (below --fail-on), 1 findings,
 * 2 usage or input error.
 */
import { readFileSync } from "node:fs";
import { checkPolicies } from "./analyze.js";
import { CliError, HELP_TEXT, parseCliArgs, type CliOptions } from "./cliargs.js";
import { coverageRows } from "./effective.js";
import { EXPLAIN_TOPICS_HINT, explainSuggestion, explainTopic } from "./explain.js";
import { extractPolicies, parsePolicy, type ExtractedPolicy } from "./parse.js";
import { renderCoverageJson, renderCoverageText, renderJson, renderText } from "./report.js";
import { VERSION } from "./version.js";
import type { Policy } from "./types.js";

function readInput(options: CliOptions): string[] {
  const texts: string[] = [];
  if (options.policy !== null) {
    texts.push(options.policy === "-" ? readFileSync(0, "utf8") : options.policy);
  }
  for (const file of options.files) {
    if (file === "-") {
      texts.push(readFileSync(0, "utf8"));
      continue;
    }
    try {
      texts.push(readFileSync(file, "utf8"));
    } catch (error) {
      throw new CliError(`cannot read ${file}: ${(error as Error).message}`);
    }
  }
  return texts;
}

function collectPolicies(options: CliOptions): Policy[] {
  const extracted: ExtractedPolicy[] = [];
  for (const text of readInput(options)) {
    extracted.push(...extractPolicies(text));
  }
  if (extracted.length === 0) {
    throw new CliError("the input contains no policy (empty string / no CSP header lines)");
  }
  return extracted.map((entry) => parsePolicy(entry.raw, { reportOnly: entry.reportOnly }));
}

export function main(argv: string[]): number {
  let options: CliOptions;
  try {
    options = parseCliArgs(argv);
  } catch (error) {
    if (error instanceof CliError) {
      process.stderr.write(`cspdoctor: ${error.message}\n`);
      process.stderr.write(`Run "cspdoctor --help" for usage.\n`);
      return 2;
    }
    throw error;
  }

  if (options.command === "help") {
    process.stdout.write(HELP_TEXT);
    return 0;
  }
  if (options.command === "version") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  try {
    if (options.command === "explain") {
      return runExplain(options.topic ?? "");
    }
    const policies = collectPolicies(options);
    if (options.command === "coverage") {
      return runCoverage(policies, options);
    }
    return runCheck(policies, options);
  } catch (error) {
    if (error instanceof CliError) {
      process.stderr.write(`cspdoctor: ${error.message}\n`);
      return 2;
    }
    throw error;
  }
}

function runCheck(policies: Policy[], options: CliOptions): number {
  const run = checkPolicies(policies, { context: options.context, failOn: options.failOn });
  const output =
    options.format === "json" ? renderJson(run) : renderText(run, { quiet: options.quiet });
  process.stdout.write(output);
  return run.ok ? 0 : 1;
}

function runCoverage(policies: Policy[], options: CliOptions): number {
  const chunks: string[] = [];
  policies.forEach((policy, i) => {
    const rows = coverageRows(policy);
    chunks.push(
      options.format === "json" ? renderCoverageJson(rows, i + 1) : renderCoverageText(rows, i + 1)
    );
  });
  process.stdout.write(chunks.join("\n"));
  return 0;
}

function runExplain(topic: string): number {
  const entry = explainTopic(topic);
  if (entry === null) {
    const suggestion = explainSuggestion(topic);
    process.stderr.write(`cspdoctor: nothing to explain for "${topic}"\n`);
    if (suggestion !== null) {
      process.stderr.write(`Did you mean: ${suggestion}?\n`);
    }
    process.stderr.write(`Topics: ${EXPLAIN_TOPICS_HINT}.\n`);
    return 2;
  }
  process.stdout.write(entry + "\n");
  return 0;
}

process.exit(main(process.argv.slice(2)));
