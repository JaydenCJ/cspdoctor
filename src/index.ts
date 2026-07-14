/**
 * Public programmatic API. Everything the CLI does is available as pure
 * functions over plain data:
 *
 *   const policies = extractPolicies(headerText)
 *     .map((p) => parsePolicy(p.raw, { reportOnly: p.reportOnly }));
 *   const run = checkPolicies(policies, { failOn: "warning" });
 */
export { analyzePolicy, checkPolicies } from "./analyze.js";
export type { AnalyzeOptions, CheckOptions } from "./analyze.js";
export {
  CONTEXTS,
  DIRECTIVES,
  directiveNames,
  keywordMeaningfulIn,
  nonceHashMeaningfulIn,
} from "./directives.js";
export type { DirectiveInfo, DirectiveKind } from "./directives.js";
export { coverageRows, findDirective, governedContexts, governing } from "./effective.js";
export type { CoverageRow, Governing } from "./effective.js";
export { explainSuggestion, explainTopic } from "./explain.js";
export { BYPASS_HOSTS, findBypassHosts } from "./intel.js";
export { editDistance, nearest } from "./nearest.js";
export { extractPolicies, parsePolicy } from "./parse.js";
export type { ExtractedPolicy } from "./parse.js";
export { renderCoverageJson, renderCoverageText, renderJson, renderText } from "./report.js";
export { RULES, ruleList } from "./rules.js";
export type { RuleInfo } from "./rules.js";
export { KEYWORDS, classifySource, decodedByteLength, isBase64Value } from "./sources.js";
export { VERSION } from "./version.js";
export type {
  CheckRun,
  DeliveryContext,
  Directive,
  FailLevel,
  Finding,
  Policy,
  PolicyReport,
  Severity,
  SourceExpression,
  Totals,
} from "./types.js";
