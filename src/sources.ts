/**
 * Source-expression classification, straight from the CSP3 grammar.
 * A single whitespace-free token comes in; a tagged `SourceExpression`
 * comes out. Classification is deliberately forgiving in exactly the
 * ways browsers are (case-insensitive keywords, both base64 alphabets)
 * and strict in exactly the ways browsers are (an unquoted keyword is a
 * host source; a typo'd quoted keyword matches nothing).
 */
import type { SourceExpression } from "./types.js";

/** Keyword sources defined by CSP Level 3. Matched case-insensitively. */
export const KEYWORDS = [
  "self",
  "none",
  "unsafe-inline",
  "unsafe-eval",
  "wasm-unsafe-eval",
  "unsafe-hashes",
  "strict-dynamic",
  "report-sample",
  "inline-speculation-rules",
] as const;

const KEYWORD_SET: ReadonlySet<string> = new Set(KEYWORDS);

/** Hash algorithms CSP3 accepts, with the byte length of their digests. */
export const HASH_ALGORITHMS: Readonly<Record<string, number>> = {
  sha256: 32,
  sha384: 48,
  sha512: 64,
};

/**
 * base64-value per the CSP grammar: both the standard and the URL-safe
 * alphabet are allowed (and may even be mixed), plus up to two `=` pads.
 */
const BASE64_VALUE = /^[A-Za-z0-9+/\-_]+={0,2}$/;

/** True when `value` matches the CSP base64-value production. */
export function isBase64Value(value: string): boolean {
  return BASE64_VALUE.test(value) && value.replace(/=+$/, "").length % 4 !== 1;
}

/** Decoded byte length of a base64 payload (padding-insensitive). */
export function decodedByteLength(value: string): number {
  const stripped = value.replace(/=+$/, "");
  return Math.floor((stripped.length * 3) / 4);
}

/** scheme per RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
const SCHEME_SOURCE = /^([A-Za-z][A-Za-z0-9+.-]*):$/;

/**
 * host-source per CSP3: [ scheme "://" ] host [ ":" port ] [ path ].
 * Host labels are ALPHA/DIGIT/"-"; the host may be `*` or start `*.`.
 */
const HOST_SOURCE = new RegExp(
  "^(?:([A-Za-z][A-Za-z0-9+.-]*)://)?" + // optional scheme://
    "(\\*|(?:\\*\\.)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?" +
    "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*)" + // host
    "(?::(\\d+|\\*))?" + // optional :port
    "(/[^\\s]*)?$" // optional path
);

/** Classify one whitespace-free token as a CSP source expression. */
export function classifySource(token: string): SourceExpression {
  if (token.startsWith("'") || token.endsWith("'") || token.includes("'")) {
    return classifyQuoted(token);
  }

  const scheme = SCHEME_SOURCE.exec(token);
  if (scheme !== null && scheme[1] !== undefined) {
    return { kind: "scheme", raw: token, scheme: scheme[1].toLowerCase() };
  }

  const host = HOST_SOURCE.exec(token);
  if (host !== null && host[2] !== undefined) {
    const hostPart = host[2].toLowerCase();
    return {
      kind: "host",
      raw: token,
      scheme: host[1] !== undefined ? host[1].toLowerCase() : null,
      host: hostPart,
      port: host[3] ?? null,
      path: host[4] ?? null,
      wildcardHost: hostPart === "*",
      wildcardSubdomain: hostPart.startsWith("*."),
    };
  }

  return {
    kind: "malformed",
    raw: token,
    reason: "not a keyword, scheme, or host source",
  };
}

function classifyQuoted(token: string): SourceExpression {
  if (!(token.length >= 2 && token.startsWith("'") && token.endsWith("'"))) {
    return {
      kind: "malformed",
      raw: token,
      reason: "quotes must wrap the whole expression, e.g. 'self'",
    };
  }
  const inner = token.slice(1, -1);
  const lower = inner.toLowerCase();

  if (KEYWORD_SET.has(lower)) {
    return { kind: "keyword", raw: token, name: lower };
  }

  const nonce = /^nonce-(.*)$/i.exec(inner);
  if (nonce !== null) {
    const value = nonce[1] ?? "";
    const valid = value.length > 0 && isBase64Value(value);
    return {
      kind: "nonce",
      raw: token,
      value,
      valid,
      bits: valid ? decodedByteLength(value) * 8 : null,
    };
  }

  const hash = /^([A-Za-z0-9]+)-(.*)$/.exec(inner);
  if (hash !== null && hash[1] !== undefined && looksLikeHashAlgorithm(hash[1])) {
    return classifyHash(token, hash[1], hash[2] ?? "");
  }

  return { kind: "quoted-unknown", raw: token, name: lower };
}

/**
 * Treat 'sha…-', 'md5-' etc. as hash *attempts* so a wrong algorithm gets
 * a targeted diagnostic instead of a generic "unknown keyword".
 */
function looksLikeHashAlgorithm(candidate: string): boolean {
  const lower = candidate.toLowerCase();
  return lower in HASH_ALGORITHMS || /^(sha\d*|md5)$/.test(lower);
}

function classifyHash(token: string, algorithm: string, value: string): SourceExpression {
  const lower = algorithm.toLowerCase();
  const digestBytes = HASH_ALGORITHMS[lower];
  if (digestBytes === undefined) {
    return {
      kind: "hash",
      raw: token,
      algorithm: lower,
      value,
      valid: false,
      reason: `"${lower}" is not a CSP hash algorithm (use sha256, sha384 or sha512)`,
    };
  }
  if (value.length === 0 || !isBase64Value(value)) {
    return {
      kind: "hash",
      raw: token,
      algorithm: lower,
      value,
      valid: false,
      reason: "the digest is not valid base64",
    };
  }
  if (decodedByteLength(value) !== digestBytes) {
    return {
      kind: "hash",
      raw: token,
      algorithm: lower,
      value,
      valid: false,
      reason: `a ${lower} digest decodes to ${digestBytes} bytes, this one decodes to ${decodedByteLength(value)}`,
    };
  }
  return { kind: "hash", raw: token, algorithm: lower, value, valid: true, reason: null };
}

/**
 * True when a bare (unquoted) host token is almost certainly a keyword,
 * nonce or hash that lost its quotes — the classic CSP footgun: browsers
 * read `script-src unsafe-inline` as a host named "unsafe-inline".
 */
export function looksLikeUnquotedKeyword(source: SourceExpression): boolean {
  if (source.kind !== "host") return false;
  if (source.scheme !== null || source.port !== null || source.path !== null) return false;
  const text = source.host;
  return KEYWORD_SET.has(text) || /^(nonce|sha256|sha384|sha512)-/.test(text);
}

/** Schemes that mean "unencrypted transport" when used as a source. */
export const INSECURE_SCHEMES: ReadonlySet<string> = new Set(["http", "ws", "ftp"]);

/** Loopback hosts that are exempt from the insecure-transport warning. */
export function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1";
}
