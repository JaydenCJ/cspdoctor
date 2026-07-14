/**
 * Effective-policy resolution. CSP's fallback chains are the part humans
 * get wrong most often (worker-src falls back through child-src AND
 * script-src; base-uri falls back to nothing at all). This module
 * answers, for a parsed policy, "which directive actually governs each
 * kind of load?" — both for the analyzer and for `cspdoctor coverage`.
 */
import { CONTEXTS, DIRECTIVES } from "./directives.js";
import type { Directive, Policy } from "./types.js";

/** The directive that governs `context`, plus the name it was found under. */
export interface Governing {
  /** The directive name the chain resolved to (e.g. "default-src"). */
  name: string;
  directive: Directive;
}

/** First live (non-duplicate) directive with the given name, if any. */
export function findDirective(policy: Policy, name: string): Directive | null {
  for (const directive of policy.directives) {
    if (directive.name === name && !directive.duplicate) return directive;
  }
  return null;
}

/**
 * Resolve the fallback chain for a load context (a directive name from
 * `CONTEXTS`). Returns null when nothing in the policy governs it — for
 * base-uri / form-action / frame-ancestors that means "unrestricted".
 */
export function governing(policy: Policy, context: string): Governing | null {
  const info = DIRECTIVES.get(context);
  const chain = [context, ...(info?.fallback ?? [])];
  for (const name of chain) {
    const directive = findDirective(policy, name);
    if (directive !== null) return { name, directive };
  }
  return null;
}

/**
 * Invert `governing` over every context: for each directive that is
 * actually present, the list of contexts it ends up governing. A
 * directive that governs nothing is fully shadowed by more specific
 * directives.
 */
export function governedContexts(policy: Policy): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const context of CONTEXTS) {
    const resolved = governing(policy, context);
    if (resolved === null) continue;
    const existing = map.get(resolved.name);
    if (existing === undefined) {
      map.set(resolved.name, [context]);
    } else {
      existing.push(context);
    }
  }
  return map;
}

/** One row of the `cspdoctor coverage` table. */
export interface CoverageRow {
  /** The load context (a directive name). */
  context: string;
  /** Where the chain resolved, or null when nothing governs the context. */
  governedBy: string | null;
  /** True when the context is governed by a fallback, not itself. */
  viaFallback: boolean;
  /** The governing source list, serialized as written; null when ungoverned. */
  sources: string | null;
}

/** The full coverage table for a policy, in fixed context order. */
export function coverageRows(policy: Policy): CoverageRow[] {
  return CONTEXTS.map((context) => {
    const resolved = governing(policy, context);
    if (resolved === null) {
      return { context, governedBy: null, viaFallback: false, sources: null };
    }
    return {
      context,
      governedBy: resolved.name,
      viaFallback: resolved.name !== context,
      sources: resolved.directive.rawValues.join(" "),
    };
  });
}
