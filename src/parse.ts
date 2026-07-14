/**
 * Policy parsing, following the "parse a serialized CSP" algorithm from
 * CSP Level 3: split on `;`, split each directive on ASCII whitespace,
 * lowercase the name, keep the first occurrence of a duplicate. Nothing
 * is thrown away — even tokens the grammar rejects are kept (classified
 * as `malformed`) so the analyzer can explain them.
 */
import { classifySource } from "./sources.js";
import type { Directive, Policy } from "./types.js";

const ASCII_WHITESPACE = /[\t\n\f\r ]+/;

/** Parse one serialized policy (a single header's value). */
export function parsePolicy(raw: string, options?: { reportOnly?: boolean }): Policy {
  const directives: Directive[] = [];
  const seen = new Set<string>();

  for (const segment of raw.split(";")) {
    const trimmed = segment.trim();
    if (trimmed === "") continue; // empty directives are legal and ignored

    const tokens = trimmed.split(ASCII_WHITESPACE);
    const rawName = tokens[0] ?? "";
    const name = rawName.toLowerCase();
    const rawValues = tokens.slice(1);

    const duplicate = seen.has(name);
    seen.add(name);

    directives.push({
      name,
      rawName,
      rawValues,
      sources: rawValues.map(classifySource),
      index: directives.length,
      duplicate,
    });
  }

  return { directives, reportOnly: options?.reportOnly ?? false, raw: raw.trim() };
}

/** One policy string pulled out of a block of input text. */
export interface ExtractedPolicy {
  raw: string;
  reportOnly: boolean;
}

const HEADER_LINE = /^[ \t]*content-security-policy(-report-only)?[ \t]*:[ \t]*(.*)$/i;

/**
 * Pull policy strings out of free-form input. Two shapes are accepted:
 *
 * 1. Text containing `Content-Security-Policy[-Report-Only]:` header
 *    lines (e.g. saved `curl -sI` output): every such line becomes a
 *    policy, and — per RFC 9110 header combination — a comma inside a
 *    header value splits it into multiple policies.
 * 2. Anything else: the whole text, trimmed, is one raw policy value.
 */
export function extractPolicies(text: string): ExtractedPolicy[] {
  const fromHeaders: ExtractedPolicy[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = HEADER_LINE.exec(line);
    if (match === null) continue;
    const reportOnly = match[1] !== undefined;
    for (const part of (match[2] ?? "").split(",")) {
      const raw = part.trim();
      if (raw !== "") fromHeaders.push({ raw, reportOnly });
    }
  }
  if (fromHeaders.length > 0) return fromHeaders;

  const raw = text.trim();
  return raw === "" ? [] : [{ raw, reportOnly: false }];
}
