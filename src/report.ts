/**
 * Renderers. Text output is for humans reading a terminal; JSON output
 * is a stable shape for CI and scripting. Both are pure functions of a
 * `CheckRun` — no color codes, no TTY detection, so output is
 * byte-deterministic and safe to grep or diff.
 */
import type { CoverageRow } from "./effective.js";
import { DIRECTIVES } from "./directives.js";
import { VERSION } from "./version.js";
import type { CheckRun, Finding } from "./types.js";

export interface RenderOptions {
  /** Suppress per-finding detail; keep summary lines only. */
  quiet?: boolean;
}

/** "1 error", "4 warnings" — counts read like prose, not like a template. */
function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function findingLabel(finding: Finding): string {
  const where =
    finding.directive === null
      ? "policy"
      : finding.source !== null
        ? `${finding.directive} › ${finding.source}`
        : isMissingDirectiveFinding(finding)
          ? `${finding.directive} (not set)`
          : finding.directive;
  return `${finding.severity} ${finding.code} ${where}`;
}

/** Missing-directive rules point at a directive that does not exist yet. */
function isMissingDirectiveFinding(finding: Finding): boolean {
  return ["E114", "E115", "W207", "W208", "W209", "I304"].includes(finding.code);
}

/** Render a full check run as human-readable text (trailing newline included). */
export function renderText(run: CheckRun, options?: RenderOptions): string {
  const quiet = options?.quiet ?? false;
  const lines: string[] = [];

  for (const report of run.reports) {
    const counts = { error: 0, warning: 0, info: 0 };
    for (const finding of report.findings) counts[finding.severity] += 1;
    const mode = report.policy.reportOnly ? "report-only" : "enforced";
    lines.push(
      `policy ${report.index} (${mode}): ${plural(report.policy.directives.length, "directive")} — ` +
        `${plural(counts.error, "error")}, ${plural(counts.warning, "warning")}, ${counts.info} info`
    );
    if (!quiet) {
      for (const finding of report.findings) {
        lines.push("");
        lines.push(`  ${findingLabel(finding)}`);
        lines.push(`      ${finding.message}`);
        if (finding.fix !== null) lines.push(`      fix: ${finding.fix}`);
      }
    }
    lines.push("");
  }

  const verdict = run.ok ? "OK" : "FAIL";
  lines.push(
    `cspdoctor: ${verdict} — ${plural(run.totals.error, "error")}, ${plural(run.totals.warning, "warning")}, ` +
      `${run.totals.info} info (fail-on: ${run.failOn})`
  );
  return lines.join("\n") + "\n";
}

/** Render a full check run as stable, pretty-printed JSON. */
export function renderJson(run: CheckRun): string {
  const payload = {
    tool: "cspdoctor",
    version: VERSION,
    context: run.context,
    failOn: run.failOn,
    ok: run.ok,
    totals: run.totals,
    policies: run.reports.map((report) => ({
      index: report.index,
      reportOnly: report.policy.reportOnly,
      directives: report.policy.directives.map((d) => d.name),
      findings: report.findings.map((finding) => ({
        code: finding.code,
        severity: finding.severity,
        directive: finding.directive,
        source: finding.source,
        message: finding.message,
        fix: finding.fix,
      })),
    })),
  };
  return JSON.stringify(payload, null, 2) + "\n";
}

/** Render the `coverage` table for one policy as aligned text. */
export function renderCoverageText(rows: readonly CoverageRow[], policyIndex: number): string {
  const lines: string[] = [`effective coverage (policy ${policyIndex})`, ""];
  const contextWidth = Math.max(...rows.map((row) => row.context.length), "directive".length);
  const governedWidth = Math.max(
    ...rows.map((row) => governedLabel(row).length),
    "governed by".length
  );

  lines.push(`  ${"directive".padEnd(contextWidth)}  ${"governed by".padEnd(governedWidth)}  sources`);
  for (const row of rows) {
    lines.push(
      `  ${row.context.padEnd(contextWidth)}  ${governedLabel(row).padEnd(governedWidth)}  ${sourcesLabel(row)}`
    );
  }
  return lines.join("\n") + "\n";
}

function governedLabel(row: CoverageRow): string {
  if (row.governedBy === null) return "(unset)";
  return row.viaFallback ? `-> ${row.governedBy}` : row.governedBy;
}

function sourcesLabel(row: CoverageRow): string {
  if (row.governedBy === null) {
    const info = DIRECTIVES.get(row.context);
    const headerOnly = info !== undefined && !info.metaAllowed ? " (header-only directive)" : "";
    return `unrestricted${headerOnly}`;
  }
  return row.sources === "" ? "(empty — behaves like 'none')" : (row.sources ?? "");
}

/** Render coverage rows for one policy as stable JSON. */
export function renderCoverageJson(rows: readonly CoverageRow[], policyIndex: number): string {
  const payload = {
    tool: "cspdoctor",
    version: VERSION,
    policy: policyIndex,
    coverage: rows.map((row) => ({
      context: row.context,
      governedBy: row.governedBy,
      viaFallback: row.viaFallback,
      sources: row.sources,
    })),
  };
  return JSON.stringify(payload, null, 2) + "\n";
}
