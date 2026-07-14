/**
 * The `cspdoctor explain` knowledge base. One lookup resolves, in order:
 * a rule code (E110), a directive name (script-src), a keyword
 * (strict-dynamic, with or without quotes), or one of a few concept
 * topics (fallbacks, strict-csp, exit-codes). All content lives in the
 * registry and rule catalog so the docs can never drift from the code.
 */
import { DIRECTIVES, directiveNames } from "./directives.js";
import { nearest } from "./nearest.js";
import { RULES, ruleList } from "./rules.js";
import { KEYWORDS } from "./sources.js";

const KEYWORD_DOCS: Readonly<Record<string, string>> = {
  self:
    "'self' allows the page's own origin (same scheme, host and port). The " +
    "safe default for most directives — but note it does not cover " +
    "subdomains, and for scripts it still allows anything an attacker can " +
    "upload to your origin.",
  none:
    "'none' matches nothing. It must stand alone: combined with any other " +
    "source, browsers ignore it (cspdoctor flags that as W206). " +
    "object-src 'none' and base-uri 'none' are staples of a hardened policy.",
  "unsafe-inline":
    "Allows inline <script>/<style>, event handlers and javascript: URLs — " +
    "including injected ones, which is why it defeats CSP's XSS protection " +
    "(E110/W210). Once a nonce or hash is present in the same directive, " +
    "CSP2+ browsers ignore it, making it a safe legacy fallback (I301).",
  "unsafe-eval":
    "Allows eval(), new Function() and string arguments to timers. Any " +
    "injected string reaching those sinks becomes code (E111). " +
    "'wasm-unsafe-eval' is the narrower grant if only WebAssembly needs it.",
  "wasm-unsafe-eval":
    "Allows compiling WebAssembly from JavaScript without enabling eval(). " +
    "The right call when you ship wasm (I307).",
  "unsafe-hashes":
    "Lets hash sources match inline event handlers and javascript: " +
    "navigation, not just <script> blocks. Much safer than 'unsafe-inline'; " +
    "refactoring handlers to addEventListener removes the need (I308).",
  "strict-dynamic":
    "The heart of the strict-CSP pattern: trust starts at scripts carrying " +
    "a valid nonce or hash and propagates to whatever they load, while host " +
    "and scheme allowlists are ignored by CSP3 browsers (I302). Without any " +
    "nonce or hash it blocks every script (E106).",
  "report-sample":
    "Asks browsers to include the first bytes of the violating code in " +
    "violation reports — invaluable when hunting down which inline snippet " +
    "broke after a policy change.",
  "inline-speculation-rules":
    "Allows inline <script type=\"speculationrules\"> blocks (prefetch/" +
    "prerender hints) without allowing other inline scripts.",
  nonce:
    "'nonce-<base64>' allows exactly the elements carrying the matching " +
    "nonce attribute. The value must be fresh per response and carry at " +
    "least 128 bits of randomness (W213); a static nonce is no nonce. A " +
    "valid nonce also neutralizes 'unsafe-inline' in the same directive.",
  hash:
    "'sha256-<base64>' (or sha384/sha512) allows the element whose content " +
    "hashes to that digest — perfect for a fixed inline snippet you cannot " +
    "nonce. The digest must be base64 of the exact byte length (E104).",
};

const CONCEPT_DOCS: Readonly<Record<string, string>> = {
  fallbacks:
    "Fetch directives fall back when absent: most fall back to default-src; " +
    "script-src-elem/-attr fall back to script-src first; worker-src tries " +
    "child-src, then script-src, then default-src; frame-src tries " +
    "child-src. Crucially, base-uri, form-action and frame-ancestors fall " +
    "back to NOTHING — leaving them unset leaves those doors open (W207, " +
    "W209, W208). Run `cspdoctor coverage <policy>` to see the resolution.",
  "strict-csp":
    "The modern recipe: script-src 'nonce-<fresh>' 'strict-dynamic' plus " +
    "'unsafe-inline' and https: as inert fallbacks for old browsers, " +
    "object-src 'none', base-uri 'none', and frame-ancestors + form-action " +
    "set explicitly. It removes the host allowlist — and with it the " +
    "JSONP/gadget bypass class (W215). See examples/strict.txt.",
  "exit-codes":
    "0: no findings at or above --fail-on (default: warning). 1: findings " +
    "at or above the threshold. 2: usage or input error (unreadable file, " +
    "empty input, unknown flag). Wire `cspdoctor check` straight into CI " +
    "and the exit code is the gate.",
  meta:
    "Policies can be delivered in a <meta http-equiv> element, but " +
    "frame-ancestors, sandbox and report-uri only work from the HTTP " +
    "header (W204). Pass --context meta so cspdoctor grades what a <meta> " +
    "policy can actually enforce.",
  "report-only":
    "Content-Security-Policy-Report-Only evaluates the policy and sends " +
    "reports without blocking anything (I309). Deploy new policies " +
    "report-only, watch the reports, then flip to enforcing.",
};

function ruleEntry(code: string): string | null {
  const info = RULES.get(code.toUpperCase());
  if (info === undefined) return null;
  return `${info.code} (${info.severity}) — ${info.title}\n\n${info.explain}`;
}

function directiveEntry(name: string): string | null {
  const info = DIRECTIVES.get(name.toLowerCase());
  if (info === undefined) return null;
  const lines = [`${info.name} — ${info.kind} directive`, "", info.doc];
  if (info.fallback.length > 0) {
    lines.push("", `Fallback chain when absent: ${info.fallback.join(" -> ")}.`);
  } else if (info.sourceList) {
    lines.push("", "No fallback: when absent, this surface is unrestricted.");
  }
  if (!info.metaAllowed) {
    lines.push("", "Header-only: ignored when the policy is delivered in <meta>.");
  }
  if (info.deprecated !== null) {
    lines.push(
      "",
      `Deprecated: ${info.deprecated.note}` +
        (info.deprecated.replacement !== null ? ` Use ${info.deprecated.replacement}.` : "")
    );
  }
  return lines.join("\n");
}

function keywordEntry(topic: string): string | null {
  const bare = topic.replace(/^'+|'+$/g, "").toLowerCase();
  const alias =
    bare === "nonces" ? "nonce" : bare === "hashes" || /^sha(256|384|512)$/.test(bare) ? "hash" : bare;
  const doc = KEYWORD_DOCS[alias];
  if (doc === undefined) return null;
  const heading = alias === "nonce" || alias === "hash" ? `${alias} sources` : `'${alias}'`;
  return `${heading}\n\n${doc}`;
}

/**
 * Resolve an explain topic to its documentation, or null when unknown.
 * Callers decide how to report the miss; `explainSuggestion` helps.
 */
export function explainTopic(topic: string): string | null {
  const trimmed = topic.trim();
  if (/^[EWI]\d{3}$/i.test(trimmed)) return ruleEntry(trimmed);
  const concept = CONCEPT_DOCS[trimmed.toLowerCase()];
  if (concept !== undefined) return `${trimmed.toLowerCase()}\n\n${concept}`;
  return directiveEntry(trimmed) ?? keywordEntry(trimmed);
}

/** A did-you-mean candidate for a topic that did not resolve. */
export function explainSuggestion(topic: string): string | null {
  const candidates = [
    ...ruleList().map((rule) => rule.code),
    ...directiveNames(),
    ...KEYWORDS,
    "nonce",
    "hash",
    ...Object.keys(CONCEPT_DOCS),
  ];
  return nearest(topic.replace(/^'+|'+$/g, ""), candidates);
}

/** The topic classes `explain` accepts, for help and error text. */
export const EXPLAIN_TOPICS_HINT =
  "rule codes (E110), directives (script-src), keywords (strict-dynamic, nonce), " +
  "or concepts: fallbacks, strict-csp, exit-codes, meta, report-only";
