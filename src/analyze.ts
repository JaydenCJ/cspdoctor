/**
 * The rule engine. Two layers of checks run over a parsed policy:
 *
 * 1. Directive-local syntax checks — quotes, typos, nonces, hashes,
 *    duplicates, deprecations — where the finding is about what was
 *    literally written.
 * 2. Effective-policy checks — 'unsafe-inline', wildcards, permissive
 *    schemes, bypass hosts, missing directives — where severity depends
 *    on which load contexts a directive *actually governs* after CSP's
 *    fallback chains are resolved. `default-src *` is an error when it
 *    is what governs scripts, and merely informational when every
 *    critical directive overrides it.
 *
 * Every finding carries a stable code from rules.ts and, when one can be
 * derived, a concrete fix.
 */
import {
  CRITICAL_CONTEXTS,
  DIRECTIVES,
  LOW_CONTEXTS,
  MEDIUM_CONTEXTS,
  SCRIPT_CONTEXTS,
  STYLE_CONTEXTS,
  directiveNames,
  keywordMeaningfulIn,
  nonceHashMeaningfulIn,
} from "./directives.js";
import { findDirective, governedContexts, governing } from "./effective.js";
import { findBypassHosts } from "./intel.js";
import { nearest } from "./nearest.js";
import { RULES } from "./rules.js";
import { INSECURE_SCHEMES, KEYWORDS, isLoopbackHost, looksLikeUnquotedKeyword } from "./sources.js";
import type {
  CheckRun,
  DeliveryContext,
  Directive,
  FailLevel,
  Finding,
  Policy,
  PolicyReport,
  Severity,
  SourceExpression,
} from "./types.js";

export interface AnalyzeOptions {
  /** Where the policy is delivered; default "header". */
  context?: DeliveryContext;
}

/** Bare scheme sources that are dangerous in a code-execution context. */
const BROAD_SCHEMES: ReadonlySet<string> = new Set(["https", "http", "data", "blob", "filesystem"]);

/** Human noun for what a load context controls, used in messages. */
const CONTEXT_NOUNS: Readonly<Record<string, string>> = {
  "script-src": "scripts",
  "script-src-elem": "script elements",
  "script-src-attr": "event handlers",
  "worker-src": "workers",
  "object-src": "plugin content",
  "base-uri": "<base> targets",
  "style-src": "styles",
  "style-src-elem": "stylesheets",
  "style-src-attr": "inline styles",
  "connect-src": "outbound connections",
  "frame-src": "embedded frames",
  "manifest-src": "app manifests",
  "form-action": "form submissions",
  "frame-ancestors": "embedding pages",
  "img-src": "images",
  "font-src": "fonts",
  "media-src": "media",
};

/** Preferred context to name in a W211 message, most consequential first. */
const MEDIUM_PRIORITY: readonly string[] = [
  "connect-src",
  "form-action",
  "frame-ancestors",
  "frame-src",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "manifest-src",
];

const W211_CONSEQUENCE: Readonly<Record<string, string>> = {
  "connect-src": "injected script can exfiltrate data to any origin",
  "form-action": "forms can submit user input anywhere — same as leaving form-action unset",
  "frame-ancestors": "any site may frame this page (clickjacking)",
  "frame-src": "any origin may be embedded inside this page",
  "style-src": "stylesheets may load from any origin",
  "style-src-elem": "stylesheets may load from any origin",
  "style-src-attr": "inline styles may come from any origin",
  "manifest-src": "app manifests may load from any origin",
};

function nounList(contexts: readonly string[]): string {
  const nouns = contexts.map((context) => CONTEXT_NOUNS[context] ?? context);
  return [...new Set(nouns)].join(", ");
}

class Emitter {
  readonly findings: Finding[] = [];
  private readonly seen = new Set<string>();

  emit(code: string, directive: string | null, source: string | null, message: string, fix: string | null): boolean {
    const key = `${code}|${directive ?? ""}|${source ?? ""}`;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    const info = RULES.get(code);
    if (info === undefined) {
      throw new Error(`internal: finding emitted with unknown code ${code}`);
    }
    this.findings.push({ code, severity: info.severity, directive, source, message, fix });
    return true;
  }

  has(code: string, directive: string | null, source: string | null): boolean {
    return this.seen.has(`${code}|${directive ?? ""}|${source ?? ""}`);
  }
}

/** Analyze one parsed policy; findings are sorted errors → warnings → info. */
export function analyzePolicy(policy: Policy, options?: AnalyzeOptions): Finding[] {
  const delivery = options?.context ?? "header";
  const out = new Emitter();

  for (const directive of policy.directives) {
    checkDirectiveSyntax(out, directive, delivery);
  }
  checkEffectivePolicy(out, policy);
  checkMissingDirectives(out, policy, delivery);
  checkPolicyHygiene(out, policy);

  const rank: Record<Severity, number> = { error: 0, warning: 1, info: 2 };
  return [...out.findings].sort((a, b) => rank[a.severity] - rank[b.severity]);
}

// --- layer 1: what was literally written ---------------------------------

function checkDirectiveSyntax(out: Emitter, directive: Directive, delivery: DeliveryContext): void {
  const { name } = directive;

  if (directive.duplicate) {
    out.emit(
      "W202",
      name,
      null,
      `browsers use only the first ${name} directive in a policy — this second occurrence is ignored entirely (source lists are not merged)`,
      `fold these sources into the first ${name} directive`
    );
    return; // the browser ignores everything else about it
  }

  const info = DIRECTIVES.get(name);
  if (info === undefined) {
    const suggestion = nearest(name, directiveNames());
    out.emit(
      "W201",
      name,
      null,
      `"${directive.rawName}" is not a CSP directive; browsers ignore it and everything after it up to the next ";"`,
      suggestion !== null ? `did you mean ${suggestion}?` : null
    );
    return;
  }

  if (info.deprecated !== null) {
    out.emit(
      "W203",
      name,
      null,
      `${name} is deprecated: ${info.deprecated.note}`,
      info.deprecated.replacement !== null ? `use ${info.deprecated.replacement} instead` : "remove it"
    );
  }

  if (delivery === "meta" && !info.metaAllowed) {
    out.emit(
      "W204",
      name,
      null,
      `${name} has no effect in a <meta>-delivered policy — browsers only honor it from the HTTP header`,
      `deliver ${name} via the Content-Security-Policy response header`
    );
  }

  if (!info.sourceList) return;

  if (directive.sources.length === 0) {
    out.emit(
      "W205",
      name,
      null,
      `${name} has an empty source list, which matches nothing — it behaves exactly like 'none'`,
      `write ${name} 'none' if blocking everything is intended`
    );
    return;
  }

  const hasNone = directive.sources.some((s) => s.kind === "keyword" && s.name === "none");
  if (hasNone && directive.sources.length > 1) {
    out.emit(
      "W206",
      name,
      null,
      `'none' is ignored because ${name} lists other sources as well — the directive is more permissive than it reads`,
      "keep 'none' alone, or delete it"
    );
  }

  for (const source of directive.sources) {
    checkSourceSyntax(out, directive, source);
  }
}

function checkSourceSyntax(out: Emitter, directive: Directive, source: SourceExpression): void {
  const { name } = directive;
  switch (source.kind) {
    case "host":
      if (looksLikeUnquotedKeyword(source)) {
        out.emit(
          "E101",
          name,
          source.raw,
          `${source.raw} has no quotes, so browsers read it as a host named "${source.raw}" — the keyword is not in effect`,
          `write '${source.raw}' (with quotes) if you meant the keyword — then rerun to see what the quoted form implies`
        );
      }
      return;
    case "quoted-unknown": {
      const suggestion = nearest(source.name, KEYWORDS);
      out.emit(
        "E102",
        name,
        source.raw,
        `${source.raw} is not a keyword any CSP level defines; browsers drop it silently`,
        suggestion !== null ? `did you mean '${suggestion}'?` : null
      );
      return;
    }
    case "nonce":
      if (!source.valid) {
        out.emit(
          "E103",
          name,
          source.raw,
          `the nonce payload ${source.value === "" ? "is empty" : `"${source.value}" is not valid base64`} — this nonce can never match a script`,
          "generate at least 16 random bytes per response and base64-encode them: 'nonce-<base64>'"
        );
      } else if (source.bits !== null && source.bits < 128) {
        out.emit(
          "W213",
          name,
          source.raw,
          `this nonce decodes to only ${source.bits} bits — below the recommended 128; a guessable nonce defeats the mechanism`,
          "generate at least 16 random bytes per response before base64-encoding"
        );
      }
      if (!nonceHashMeaningfulIn(name)) {
        out.emit(
          "W214",
          name,
          source.raw,
          `a nonce source has no effect in ${name}; browsers ignore it`,
          "move it to a script or style directive"
        );
      }
      return;
    case "hash":
      if (!source.valid) {
        out.emit(
          "E104",
          name,
          source.raw,
          `${source.raw} can never match: ${source.reason ?? "invalid hash source"}`,
          "recompute it, e.g.: shasum -a 256 the exact script text, then base64 the raw digest"
        );
      }
      if (!nonceHashMeaningfulIn(name)) {
        out.emit(
          "W214",
          name,
          source.raw,
          `a hash source has no effect in ${name}; browsers ignore it`,
          "move it to a script or style directive"
        );
      }
      return;
    case "malformed":
      out.emit(
        "E105",
        name,
        source.raw,
        `"${source.raw}" is not a valid source expression (${source.reason}); browsers drop it silently`,
        null
      );
      return;
    case "keyword":
      if (!keywordMeaningfulIn(source.name, name)) {
        out.emit(
          "W214",
          name,
          source.raw,
          `${source.raw} has no effect in ${name}; browsers ignore it`,
          "remove it, or move it to the directive it was meant for"
        );
      }
      return;
    case "scheme":
      return; // graded by the effective-policy layer
  }
}

// --- layer 2: what the policy effectively allows --------------------------

function checkEffectivePolicy(out: Emitter, policy: Policy): void {
  const govMap = governedContexts(policy);

  for (const directive of policy.directives) {
    if (directive.duplicate) continue;
    const info = DIRECTIVES.get(directive.name);
    if (info === undefined || !info.sourceList) continue;

    const contexts = govMap.get(directive.name) ?? [];
    const scriptContexts = contexts.filter((c) => SCRIPT_CONTEXTS.has(c));
    const styleContexts = contexts.filter((c) => STYLE_CONTEXTS.has(c));

    const hasValidNonce = directive.sources.some((s) => s.kind === "nonce" && s.valid);
    const hasValidHash = directive.sources.some((s) => s.kind === "hash" && s.valid);
    const neutralized = hasValidNonce || hasValidHash;
    const strictDynamic =
      directive.sources.some((s) => s.kind === "keyword" && s.name === "strict-dynamic") &&
      scriptContexts.length > 0;

    checkUnsafeKeywords(out, directive, scriptContexts, styleContexts, neutralized, contexts);

    if (strictDynamic && !neutralized) {
      out.emit(
        "E106",
        directive.name,
        "'strict-dynamic'",
        "'strict-dynamic' is present but no valid nonce or hash grants initial trust — CSP3 browsers will block every script on the page",
        "add a per-response 'nonce-<base64>' (or a script hash) next to 'strict-dynamic'"
      );
    }

    // With 'strict-dynamic', CSP3 browsers ignore host/scheme sources for
    // script loading, so those contexts drop out of the allowlist grading.
    let allowlistContexts = contexts;
    if (strictDynamic) {
      allowlistContexts = contexts.filter((c) => !SCRIPT_CONTEXTS.has(c) && c !== "worker-src");
      const inert = directive.sources
        .filter((s) => s.kind === "host" || s.kind === "scheme")
        .map((s) => s.raw);
      if (neutralized && inert.length > 0) {
        out.emit(
          "I302",
          directive.name,
          null,
          `host/scheme sources here (${inert.slice(0, 4).join(" ")}${inert.length > 4 ? " …" : ""}) are ignored by CSP3 browsers because 'strict-dynamic' is present — they only serve as a fallback for older browsers`,
          null
        );
      }
    }

    for (const source of directive.sources) {
      checkAllowlistSource(out, directive, source, allowlistContexts);
    }
  }
}

function checkUnsafeKeywords(
  out: Emitter,
  directive: Directive,
  scriptContexts: readonly string[],
  styleContexts: readonly string[],
  neutralized: boolean,
  contexts: readonly string[]
): void {
  const name = directive.name;
  const via = name === "default-src" ? " (default-src is what governs this here)" : "";

  for (const source of directive.sources) {
    if (source.kind !== "keyword") continue;

    if (source.name === "unsafe-inline") {
      if (neutralized && (scriptContexts.length > 0 || styleContexts.length > 0)) {
        out.emit(
          "I301",
          name,
          source.raw,
          "'unsafe-inline' is ignored by CSP2+ browsers because a nonce/hash is present — kept as the intended fallback for older browsers, nothing to fix",
          null
        );
      } else {
        if (scriptContexts.length > 0) {
          out.emit(
            "E110",
            name,
            source.raw,
            `'unsafe-inline' lets every injected <script>, event handler and javascript: URL run${via} — it turns off the XSS protection CSP exists to provide`,
            "move inline code to nonced or hashed scripts; once a nonce/hash is present, 'unsafe-inline' becomes a harmless legacy fallback"
          );
        }
        if (styleContexts.length > 0) {
          out.emit(
            "W210",
            name,
            source.raw,
            `'unsafe-inline' allows injected <style> blocks and style attributes${via} — CSS injection can deface the page and exfiltrate data via selectors`,
            "use nonces or hashes for styles too, then drop 'unsafe-inline'"
          );
        }
      }
    }

    if (source.name === "unsafe-eval" && contexts.includes("script-src")) {
      out.emit(
        "E111",
        name,
        source.raw,
        `'unsafe-eval' allows eval(), new Function() and string timers${via} — any injected string that reaches them becomes code`,
        "remove 'unsafe-eval'; if only WebAssembly needs it, 'wasm-unsafe-eval' is the narrower grant"
      );
    }

    if (source.name === "wasm-unsafe-eval" && contexts.includes("script-src")) {
      out.emit(
        "I307",
        name,
        source.raw,
        "'wasm-unsafe-eval' allows compiling WebAssembly from JavaScript — far narrower than 'unsafe-eval'; fine if you ship wasm",
        null
      );
    }

    if (source.name === "unsafe-hashes" && (scriptContexts.length > 0 || styleContexts.length > 0)) {
      out.emit(
        "I308",
        name,
        source.raw,
        "'unsafe-hashes' extends hash matching to inline event handlers — much safer than 'unsafe-inline'; refactoring to addEventListener removes the need",
        null
      );
    }
  }
}

function checkAllowlistSource(
  out: Emitter,
  directive: Directive,
  source: SourceExpression,
  contexts: readonly string[]
): void {
  const name = directive.name;

  if (source.kind === "host") {
    if (source.wildcardHost) {
      gradeWildcard(out, name, source.raw, contexts);
    } else {
      const scriptish = contexts.filter((c) => SCRIPT_CONTEXTS.has(c) || c === "worker-src");
      if (scriptish.length > 0) {
        for (const bypass of findBypassHosts(source.host, source.wildcardSubdomain)) {
          out.emit(
            "W215",
            name,
            source.raw,
            source.wildcardSubdomain
              ? `${source.raw} also admits ${bypass.host}, a known CSP bypass — it ${bypass.reason}`
              : `${source.host} is a known CSP bypass in a script context — it ${bypass.reason}`,
            "self-host the files you need, or move to nonces + 'strict-dynamic' so the host allowlist stops mattering"
          );
        }
      }
      if (
        source.scheme !== null &&
        INSECURE_SCHEMES.has(source.scheme) &&
        !isLoopbackHost(source.host)
      ) {
        out.emit(
          "W212",
          name,
          source.raw,
          `${source.raw} travels over unencrypted ${source.scheme}: — an on-path attacker can read and rewrite it`,
          `serve it over https:// instead`
        );
      }
    }
    return;
  }

  if (source.kind === "scheme") {
    const critical = contexts.filter((c) => CRITICAL_CONTEXTS.has(c));
    if (BROAD_SCHEMES.has(source.scheme) && critical.length > 0) {
      out.emit("E113", name, source.raw, broadSchemeMessage(source.scheme, critical), broadSchemeFix(source.scheme));
    }
    if (
      INSECURE_SCHEMES.has(source.scheme) &&
      !out.has("E113", name, source.raw) &&
      contexts.length > 0
    ) {
      out.emit(
        "W212",
        name,
        source.raw,
        `${source.raw} allows fetching over unencrypted ${source.scheme}: — content can be tampered with in transit`,
        "allow specific https:// origins instead"
      );
    }
  }
}

function gradeWildcard(out: Emitter, name: string, raw: string, contexts: readonly string[]): void {
  const critical = contexts.filter((c) => CRITICAL_CONTEXTS.has(c));
  if (critical.length > 0) {
    out.emit(
      "E112",
      name,
      raw,
      `${raw} lets every origin on the internet supply ${nounList(critical)} — one hosted file is a complete bypass`,
      "replace the wildcard with the exact origins you load from"
    );
    return;
  }
  const medium = MEDIUM_PRIORITY.filter((c) => contexts.includes(c) && MEDIUM_CONTEXTS.has(c));
  const primary = medium[0];
  if (primary !== undefined) {
    out.emit(
      "W211",
      name,
      raw,
      `${raw} in ${name}: ${W211_CONSEQUENCE[primary] ?? `${nounList([primary])} may involve any origin`}`,
      "list the origins you actually need"
    );
    return;
  }
  if (contexts.some((c) => LOW_CONTEXTS.has(c))) {
    out.emit(
      "I306",
      name,
      raw,
      `${raw} in ${name} is broad but usually low-risk — tighten it once the error- and warning-level findings are fixed`,
      null
    );
  }
}

function broadSchemeMessage(scheme: string, critical: readonly string[]): string {
  const nouns = nounList(critical);
  switch (scheme) {
    case "data":
      return `data: allows attacker-composed data: URIs to supply ${nouns} — <script src="data:…"> executes with no server involved`;
    case "https":
      return `https: is not "HTTPS only" — it allows every HTTPS origin on the internet to supply ${nouns}`;
    case "http":
      return `http: allows every origin on the internet, over plaintext, to supply ${nouns}`;
    case "blob":
      return `blob: lets already-running injected code mint new runnable URLs for ${nouns} at runtime`;
    default:
      return `${scheme}: allows locally minted ${scheme}: URLs to supply ${nouns}`;
  }
}

function broadSchemeFix(scheme: string): string {
  switch (scheme) {
    case "data":
      return "remove data:; if you need bootstrap payloads, nonce or hash them instead";
    case "https":
    case "http":
      return `replace ${scheme}: with the specific origins you load from`;
    default:
      return `remove ${scheme}: unless you can name the exact flow that needs it`;
  }
}

// --- layer 3: what the policy forgot ---------------------------------------

function checkMissingDirectives(out: Emitter, policy: Policy, delivery: DeliveryContext): void {
  if (policy.directives.length === 0) return; // nothing to grade

  if (governing(policy, "script-src") === null && governing(policy, "script-src-elem") === null) {
    out.emit(
      "E114",
      "script-src",
      null,
      "neither script-src nor default-src is set — script execution is completely unrestricted, so the policy does not mitigate XSS",
      "start with: script-src 'self'; object-src 'none'; base-uri 'none'"
    );
  }

  if (governing(policy, "object-src") === null) {
    out.emit(
      "E115",
      "object-src",
      null,
      "object-src is not set and there is no default-src fallback — <object> and <embed> can load from anywhere, and plugin content can run script",
      "add: object-src 'none'"
    );
  }

  if (findDirective(policy, "base-uri") === null) {
    out.emit(
      "W207",
      "base-uri",
      null,
      "base-uri is not set (it never falls back to default-src) — one injected <base> tag rebases every relative script URL to an attacker's origin",
      "add: base-uri 'none' (or base-uri 'self' if you use <base>)"
    );
  }

  if (findDirective(policy, "frame-ancestors") === null) {
    out.emit(
      "W208",
      "frame-ancestors",
      null,
      delivery === "meta"
        ? "frame-ancestors is not set — any site may frame this page (clickjacking); note it can only be delivered via the HTTP header, not <meta>"
        : "frame-ancestors is not set (it never falls back to default-src) — any site may frame this page (clickjacking)",
      "add frame-ancestors 'none' (or 'self') to the Content-Security-Policy response header"
    );
  }

  if (findDirective(policy, "form-action") === null) {
    out.emit(
      "W209",
      "form-action",
      null,
      "form-action is not set (it never falls back to default-src) — an injected <form action=…> can submit user input, passwords included, anywhere",
      "add: form-action 'self'"
    );
  }

  if (findDirective(policy, "upgrade-insecure-requests") === null) {
    out.emit(
      "I304",
      "upgrade-insecure-requests",
      null,
      "upgrade-insecure-requests is not set — legacy http:// subresource URLs will be blocked as mixed content instead of quietly upgraded",
      "add: upgrade-insecure-requests"
    );
  }

  const hasReportTo = findDirective(policy, "report-to") !== null;
  const hasReportUri = findDirective(policy, "report-uri") !== null;
  if (!hasReportTo && !hasReportUri) {
    out.emit(
      "I303",
      null,
      null,
      "no report-to or report-uri — the policy will enforce, but you will never hear what it blocks (neither attacks nor your own broken deploys)",
      "add report-to (and report-uri for older browsers)"
    );
  } else if (hasReportUri && !hasReportTo) {
    out.emit(
      "I305",
      "report-uri",
      null,
      "report-uri is deprecated in CSP3 — fine to keep for compatibility, but newer browsers are moving to report-to",
      "add a report-to directive pointing at a Reporting-Endpoints group"
    );
  }
}

function checkPolicyHygiene(out: Emitter, policy: Policy): void {
  if (policy.reportOnly) {
    out.emit(
      "I309",
      null,
      null,
      "this policy is report-only: violations are reported, nothing is blocked — good for rollout, but it protects nobody by itself",
      "switch the header to Content-Security-Policy once the report stream is quiet"
    );
  }
}

// --- run assembly -----------------------------------------------------------

export interface CheckOptions extends AnalyzeOptions {
  /** Severity at or above which the run fails; default "warning". */
  failOn?: FailLevel;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 1, warning: 2, error: 3 };

/** Analyze several policies together and compute totals + pass/fail. */
export function checkPolicies(policies: readonly Policy[], options?: CheckOptions): CheckRun {
  const context = options?.context ?? "header";
  const failOn = options?.failOn ?? "warning";

  const reports: PolicyReport[] = policies.map((policy, i) => ({
    index: i + 1,
    policy,
    findings: analyzePolicy(policy, { context }),
  }));

  const totals = { error: 0, warning: 0, info: 0 };
  for (const report of reports) {
    for (const finding of report.findings) totals[finding.severity] += 1;
  }

  let ok = true;
  if (failOn !== "never") {
    const threshold = SEVERITY_RANK[failOn];
    ok = reports.every((report) =>
      report.findings.every((finding) => SEVERITY_RANK[finding.severity] < threshold)
    );
  }

  return { reports, totals, context, failOn, ok };
}
