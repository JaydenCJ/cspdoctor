/**
 * Shared types for cspdoctor. Everything in this file is pure data:
 * the parser produces `Policy` values, the analyzer consumes them and
 * produces `Finding` values, and the renderers turn those into text or
 * JSON. No module in src/ touches the network, and only the CLI touches
 * the filesystem.
 */

/** Finding severity, from "fix this now" down to "worth knowing". */
export type Severity = "error" | "warning" | "info";

/** Where the policy is delivered; some directives are ignored in `<meta>`. */
export type DeliveryContext = "header" | "meta";

/** One parsed source expression, classified per the CSP3 grammar. */
export type SourceExpression =
  | {
      /** A quoted keyword the spec knows: 'self', 'unsafe-inline', … */
      kind: "keyword";
      raw: string;
      /** Keyword name, lowercased, without quotes. */
      name: string;
    }
  | {
      /** 'nonce-<base64-value>' */
      kind: "nonce";
      raw: string;
      /** The base64 payload after "nonce-". */
      value: string;
      /** False when the payload is not valid base64 (the nonce can never match). */
      valid: boolean;
      /** Decoded entropy in bits, when the payload is valid base64. */
      bits: number | null;
    }
  | {
      /** '<algorithm>-<base64-value>' */
      kind: "hash";
      raw: string;
      algorithm: string;
      value: string;
      /** False when the algorithm is unknown or the digest length is wrong. */
      valid: boolean;
      /** Human-readable reason when `valid` is false. */
      reason: string | null;
    }
  | {
      /** A bare scheme such as `https:` or `data:`. */
      kind: "scheme";
      raw: string;
      /** Scheme, lowercased, without the trailing colon. */
      scheme: string;
    }
  | {
      /** A host source: `[scheme://]host[:port][/path]`, or bare `*`. */
      kind: "host";
      raw: string;
      scheme: string | null;
      /** Host part, lowercased; `*` for the full wildcard. */
      host: string;
      port: string | null;
      path: string | null;
      /** True when the host is exactly `*` (matches every host). */
      wildcardHost: boolean;
      /** True when the host starts with `*.` (matches every subdomain). */
      wildcardSubdomain: boolean;
    }
  | {
      /** Quoted, but not a keyword/nonce/hash the spec knows: 'frobnicate'. */
      kind: "quoted-unknown";
      raw: string;
      /** Inner text without quotes, lowercased. */
      name: string;
    }
  | {
      /** Could not be parsed as any source expression; browsers drop it. */
      kind: "malformed";
      raw: string;
      reason: string;
    };

/** One directive as written in the policy, in policy order. */
export interface Directive {
  /** Directive name, lowercased (CSP directive names are case-insensitive). */
  name: string;
  /** Directive name exactly as written. */
  rawName: string;
  /** Raw value tokens, split on ASCII whitespace. */
  rawValues: string[];
  /** Classified source expressions (one per raw value token). */
  sources: SourceExpression[];
  /** Zero-based position within the policy. */
  index: number;
  /**
   * True when an earlier directive in the same policy has the same name.
   * Browsers keep the first occurrence and ignore this one entirely.
   */
  duplicate: boolean;
}

/** One parsed policy (one Content-Security-Policy header value). */
export interface Policy {
  directives: Directive[];
  /** True for Content-Security-Policy-Report-Only delivery. */
  reportOnly: boolean;
  /** The policy string exactly as received (header name stripped). */
  raw: string;
}

/** One diagnostic produced by the analyzer. */
export interface Finding {
  /** Stable rule code, e.g. "E110". Codes are never renumbered. */
  code: string;
  severity: Severity;
  /**
   * The directive the finding is about (lowercased name), or null for
   * policy-level findings. For missing-directive rules this is the name
   * of the directive that should exist.
   */
  directive: string | null;
  /** The offending source expression as written, when one exists. */
  source: string | null;
  /** What is wrong and why it matters, in one or two sentences. */
  message: string;
  /** A concrete, copy-pasteable remediation, when one can be derived. */
  fix: string | null;
}

/** Findings for one policy, in render order. */
export interface PolicyReport {
  /** One-based policy number within the run. */
  index: number;
  policy: Policy;
  findings: Finding[];
}

/** Totals across every policy in a run. */
export interface Totals {
  error: number;
  warning: number;
  info: number;
}

/** Severity threshold at or above which `check` exits 1. */
export type FailLevel = Severity | "never";

/** The result of checking one or more policies together. */
export interface CheckRun {
  reports: PolicyReport[];
  totals: Totals;
  context: DeliveryContext;
  failOn: FailLevel;
  /** True when no finding is at or above the fail level. */
  ok: boolean;
}
