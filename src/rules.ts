/**
 * The rule catalog. Codes are stable API: a code is never renumbered or
 * repurposed, so scripts and suppressions can match on them forever.
 *
 *   E1xx — errors: the policy is weaker than written, or holds XSS open.
 *   W2xx — warnings: browsers will ignore something, or a defense is missing.
 *   I3xx — info: hardening opportunities and honest notices.
 *
 * `title` is the one-line label; `explain` is the longer text served by
 * `cspdoctor explain <code>`. Finding messages are composed in
 * analyze.ts because they interpolate the offending policy fragments.
 */
import type { Severity } from "./types.js";

export interface RuleInfo {
  code: string;
  severity: Severity;
  title: string;
  explain: string;
}

function rule(code: string, severity: Severity, title: string, explain: string): RuleInfo {
  return { code, severity, title, explain };
}

const CATALOG: readonly RuleInfo[] = [
  // --- E1xx: the policy does not say what its author thinks it says ------
  rule(
    "E101",
    "error",
    "keyword source written without quotes",
    "CSP keywords must be quoted. Browsers parse a bare `unsafe-inline` as a " +
      "host source named \"unsafe-inline\" — a host that will never exist — so " +
      "the keyword silently does nothing. This cuts both ways: a policy can be " +
      "accidentally stricter (a dead 'self') or the author may believe a " +
      "keyword is active when it is not. Quote it, then reconsider whether you " +
      "want it at all."
  ),
  rule(
    "E102",
    "error",
    "unknown quoted keyword",
    "The quoted token is not a keyword any CSP level defines, so browsers drop " +
      "it silently. Usually a typo — cspdoctor suggests the nearest real " +
      "keyword when one is plausible."
  ),
  rule(
    "E103",
    "error",
    "malformed nonce value",
    "A nonce source must carry a base64 payload ('nonce-<base64>'). This one " +
      "does not, so it can never match a script's nonce attribute: the source " +
      "is dead weight and anything relying on it is broken."
  ),
  rule(
    "E104",
    "error",
    "malformed hash source",
    "The hash algorithm is not one CSP supports (sha256, sha384, sha512), or " +
      "the digest is not base64 of the right length. Either way the hash can " +
      "never match any script or style, so it grants nothing."
  ),
  rule(
    "E105",
    "error",
    "unparseable source expression",
    "The token is not a keyword, scheme, or host source under the CSP grammar. " +
      "Browsers drop unparseable sources silently, so whatever this was meant " +
      "to allow is not allowed."
  ),
  rule(
    "E106",
    "error",
    "'strict-dynamic' without a nonce or hash",
    "'strict-dynamic' tells CSP3 browsers to ignore host and scheme sources " +
      "and trust only scripts that carry a valid nonce or hash (plus whatever " +
      "those scripts load). With no nonce or hash present there is no way to " +
      "grant initial trust — modern browsers will block every script on the page."
  ),
  rule(
    "E110",
    "error",
    "'unsafe-inline' allows injected scripts",
    "'unsafe-inline' in a script context permits every inline <script> block, " +
      "event handler and javascript: URL — including the ones an attacker " +
      "injects. It switches off the core XSS protection CSP exists to provide. " +
      "The escape path is nonces or hashes: once one is present, CSP2+ " +
      "browsers ignore 'unsafe-inline' and it becomes a harmless legacy fallback."
  ),
  rule(
    "E111",
    "error",
    "'unsafe-eval' allows string-to-code",
    "'unsafe-eval' permits eval(), new Function(), and string arguments to " +
      "setTimeout/setInterval. Any injected string that reaches one of those " +
      "sinks becomes running code. If only WebAssembly needs it, " +
      "'wasm-unsafe-eval' is the narrower grant."
  ),
  rule(
    "E112",
    "error",
    "wildcard source in a code-execution context",
    "`*` (or a `*` host) in a directive that governs scripts, workers, plugin " +
      "content or <base> means any origin on the internet can supply the " +
      "payload. An attacker only needs somewhere to host a file — the policy " +
      "stops nothing."
  ),
  rule(
    "E113",
    "error",
    "overly permissive scheme in a code-execution context",
    "A bare scheme source allows every origin reachable over that scheme. " +
      "`https:` is not \"HTTPS only\", it is the entire HTTPS internet; " +
      "`data:` needs no server at all (<script src=\"data:…\"> executes " +
      "inline); `blob:` lets injected code mint runnable URLs at runtime."
  ),
  rule(
    "E114",
    "error",
    "scripts are completely unrestricted",
    "Neither script-src (or script-src-elem) nor default-src is present, so " +
      "the policy places no restriction on script execution at all. Whatever " +
      "else it locks down, it does not mitigate XSS."
  ),
  rule(
    "E115",
    "error",
    "plugin content is unrestricted",
    "object-src is absent and there is no default-src to fall back on, so " +
      "<object> and <embed> can load from anywhere. Plugin content can " +
      "execute script, which bypasses everything script-src achieves. Every " +
      "hardened policy sets object-src 'none'."
  ),
  // --- W2xx: browsers ignore something, or a named defense is missing -----
  rule(
    "W201",
    "warning",
    "unknown directive",
    "The directive name is not one any CSP level defines; browsers ignore the " +
      "whole directive. Usually a typo — cspdoctor suggests the nearest real " +
      "directive when one is plausible."
  ),
  rule(
    "W202",
    "warning",
    "duplicate directive is ignored",
    "When a directive appears twice in one policy, browsers keep the first " +
      "occurrence and ignore the second completely — the two source lists are " +
      "NOT merged. Whatever the second occurrence was meant to add is inactive."
  ),
  rule(
    "W203",
    "warning",
    "deprecated directive",
    "The directive has been deprecated or removed from the spec. It may still " +
      "work in some browsers, but it is not a defense you can rely on; the " +
      "finding names the replacement when one exists."
  ),
  rule(
    "W204",
    "warning",
    "directive is ignored in <meta> delivery",
    "frame-ancestors, sandbox and report-uri only work when the policy " +
      "arrives in the Content-Security-Policy HTTP header. Inside a <meta> " +
      "element browsers ignore them, so the protection they promise is not " +
      "actually in force."
  ),
  rule(
    "W205",
    "warning",
    "empty source list",
    "A source-list directive with no value matches nothing — it behaves " +
      "exactly like 'none'. That may be intended, but write 'none' explicitly " +
      "so the next reader does not mistake it for an editing accident."
  ),
  rule(
    "W206",
    "warning",
    "'none' combined with other sources",
    "'none' only has meaning as the sole member of a source list. Combined " +
      "with anything else, browsers ignore the 'none' and enforce the other " +
      "sources — the directive is more permissive than it reads."
  ),
  rule(
    "W207",
    "warning",
    "base-uri is not set",
    "base-uri never falls back to default-src. Without it, a single injected " +
      "<base href> tag silently rebases every relative URL — including script " +
      "URLs — to an attacker's origin. This matters most in nonce-based " +
      "policies, where the rebased script would arrive with a valid nonce."
  ),
  rule(
    "W208",
    "warning",
    "frame-ancestors is not set",
    "Nothing restricts who may embed this page in a frame, which is the " +
      "clickjacking primitive. frame-ancestors never falls back to " +
      "default-src and must be delivered in the HTTP header (it is ignored in " +
      "<meta>). It obsoletes X-Frame-Options."
  ),
  rule(
    "W209",
    "warning",
    "form-action is not set",
    "form-action never falls back to default-src. Without it, an injected " +
      "<form action=…> — or a tampered action on your login form — submits " +
      "user input, passwords included, to any origin, even under an otherwise " +
      "strict policy."
  ),
  rule(
    "W210",
    "warning",
    "'unsafe-inline' allows injected styles",
    "In a style context, 'unsafe-inline' permits injected <style> blocks and " +
      "style attributes. Injected CSS can deface the page and exfiltrate " +
      "attribute values (passwords, CSRF tokens) via attribute selectors and " +
      "background-image beacons. Nonces and hashes work for styles too."
  ),
  rule(
    "W211",
    "warning",
    "wildcard source in a sensitive directive",
    "`*` here does not execute code directly, but it still gives an attacker " +
      "something valuable: connect-src * lets injected script exfiltrate data " +
      "anywhere, form-action * lets forms submit anywhere, frame-ancestors * " +
      "invites clickjacking, frame-src * embeds arbitrary content."
  ),
  rule(
    "W212",
    "warning",
    "source allows unencrypted transport",
    "An http:, ws: or ftp: source lets the resource travel in cleartext, " +
      "where an on-path attacker can read and rewrite it. For scripts that is " +
      "full compromise; for anything else it is still tampering. Loopback " +
      "hosts (127.0.0.1, localhost) are exempt."
  ),
  rule(
    "W213",
    "warning",
    "nonce is too short",
    "A nonce is only as good as its unpredictability. The spec recommends at " +
      "least 128 bits of randomness (16 bytes before base64). A short or " +
      "guessable nonce lets an attacker mint their own matching script tag."
  ),
  rule(
    "W214",
    "warning",
    "source has no effect in this directive",
    "The source expression is syntactically fine but meaningless where it " +
      "appears (for example 'unsafe-eval' in style-src, or a nonce in " +
      "frame-ancestors). Browsers ignore it silently; either it belongs in a " +
      "different directive or it can be deleted."
  ),
  rule(
    "W215",
    "warning",
    "allowlisted host is a known CSP bypass",
    "This host is publicly documented to defeat CSP when allowed in a script " +
      "context — it serves JSONP endpoints, gadget-rich frameworks such as " +
      "AngularJS, or arbitrary user-uploaded files. Allowlisting it re-opens " +
      "the XSS door the policy was meant to close. Self-host the files you " +
      "need, or move to a nonce-based policy where the allowlist stops mattering."
  ),
  // --- I3xx: notices and hardening opportunities --------------------------
  rule(
    "I301",
    "info",
    "'unsafe-inline' is neutralized by a nonce or hash",
    "Because a nonce or hash is present in the same source list, CSP2+ " +
      "browsers ignore 'unsafe-inline' entirely. Keeping it is the intended " +
      "compatibility pattern: ancient browsers that predate nonces fall back " +
      "to it instead of breaking. Nothing to fix."
  ),
  rule(
    "I302",
    "info",
    "allowlist is neutralized by 'strict-dynamic'",
    "With 'strict-dynamic' present, CSP3 browsers ignore host and scheme " +
      "sources in this directive; they exist only as a fallback for older " +
      "browsers. This is how the strict-CSP recipe is supposed to look — " +
      "listed so nobody is surprised the allowlist is inert."
  ),
  rule(
    "I303",
    "info",
    "no violation reporting is configured",
    "Neither report-to nor report-uri is set. The policy will enforce, but " +
      "you will never hear about what it blocks — neither the attack it " +
      "stopped nor the deploy it broke. Reporting is how a CSP is debugged " +
      "and monitored."
  ),
  rule(
    "I304",
    "info",
    "upgrade-insecure-requests is not set",
    "Any legacy http:// subresource URL left in your markup will be blocked " +
      "as mixed content instead of quietly upgraded to https://. One " +
      "valueless directive makes that whole bug class disappear."
  ),
  rule(
    "I305",
    "info",
    "report-uri without report-to",
    "report-uri is deprecated in CSP3 but still the most widely supported " +
      "reporting mechanism. Keep it — just add report-to alongside so " +
      "browsers that have moved on keep sending you reports."
  ),
  rule(
    "I306",
    "info",
    "wildcard source in a low-risk directive",
    "`*` in img-src, font-src or media-src is broad but rarely exploitable " +
      "by itself. Worth tightening for defense in depth once the error- and " +
      "warning-level findings are gone."
  ),
  rule(
    "I307",
    "info",
    "'wasm-unsafe-eval' is present",
    "'wasm-unsafe-eval' allows compiling WebAssembly from JavaScript without " +
      "allowing eval(). It is the right call when you ship wasm — this notice " +
      "exists so its presence is a decision, not an accident."
  ),
  rule(
    "I308",
    "info",
    "'unsafe-hashes' is present",
    "'unsafe-hashes' lets hash sources match inline event handlers and " +
      "javascript: navigation, not just <script> blocks. Far safer than " +
      "'unsafe-inline', but refactoring handlers to addEventListener removes " +
      "the need for it entirely."
  ),
  rule(
    "I309",
    "info",
    "policy is report-only",
    "This policy arrived via Content-Security-Policy-Report-Only: violations " +
      "are reported but nothing is blocked. Perfect for rollout, but remember " +
      "that a report-only policy protects nobody by itself."
  ),
];

/** Lookup by code (uppercase). */
export const RULES: ReadonlyMap<string, RuleInfo> = new Map(
  CATALOG.map((info) => [info.code, info])
);

/** Every rule, in catalog (code) order. */
export function ruleList(): readonly RuleInfo[] {
  return CATALOG;
}
