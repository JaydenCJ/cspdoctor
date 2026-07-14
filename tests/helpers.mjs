// Shared factories for the test suite. Everything is deterministic and
// in-memory; only cli.test.mjs spawns a process, against its own temp dir.
import { analyzePolicy, parsePolicy } from "../dist/index.js";

/** Parse a raw policy string. */
export function policy(raw, options = {}) {
  return parsePolicy(raw, options);
}

/** Parse + analyze in one step. */
export function findings(raw, options = {}) {
  return analyzePolicy(parsePolicy(raw, options), options);
}

/** The rule codes of a findings list, in order. */
export function codes(list) {
  return list.map((finding) => finding.code);
}

/** Findings with a given code. */
export function byCode(list, code) {
  return list.filter((finding) => finding.code === code);
}

/** A 22-char base64 nonce payload decoding to exactly 128 bits. */
export const GOOD_NONCE = "Y2FmZWJhYmVjYWZlYmFiZQ";

/** A structurally valid sha256 source (44 base64 chars incl. padding). */
export const GOOD_SHA256 = "sha256-" + "A".repeat(43) + "=";
