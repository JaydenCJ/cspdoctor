/**
 * A small, curated list of hosts that are publicly documented to defeat
 * CSP when allowlisted in a script context — because they serve JSONP
 * endpoints, gadget-rich libraries (AngularJS), or arbitrary
 * user-supplied files. The list is deliberately short and
 * high-confidence: every entry re-opens XSS on its own, no speculation.
 * Sources: the public CSP-bypass literature ("CSP Is Dead, Long Live
 * CSP!", the csp-evaluator bypass corpus) — all offline knowledge, no
 * lookups at runtime.
 */

export interface BypassHost {
  host: string;
  reason: string;
}

export const BYPASS_HOSTS: readonly BypassHost[] = [
  { host: "ajax.googleapis.com", reason: "hosts AngularJS and other gadget-rich libraries" },
  { host: "www.googleapis.com", reason: "exposes JSONP endpoints" },
  { host: "www.google.com", reason: "exposes JSONP endpoints" },
  { host: "accounts.google.com", reason: "exposes JSONP endpoints" },
  { host: "cdnjs.cloudflare.com", reason: "hosts AngularJS, Prototype and other bypass gadgets" },
  { host: "cdn.jsdelivr.net", reason: "serves arbitrary npm and GitHub content" },
  { host: "unpkg.com", reason: "serves arbitrary npm content" },
  { host: "code.jquery.com", reason: "hosts old library versions usable as gadgets" },
  { host: "raw.githubusercontent.com", reason: "serves arbitrary repository content" },
  { host: "s3.amazonaws.com", reason: "serves arbitrary user buckets" },
  { host: "storage.googleapis.com", reason: "serves arbitrary user buckets" },
];

/**
 * Match an allowlisted host expression against the bypass corpus.
 * `*.googleapis.com` matches every entry under that suffix; an exact
 * host matches itself. Paths are ignored on purpose: CSP path matching
 * is dropped after a redirect, so a path is not a real restriction.
 */
export function findBypassHosts(host: string, wildcardSubdomain: boolean): BypassHost[] {
  const lower = host.toLowerCase();
  if (wildcardSubdomain) {
    const suffix = lower.slice(1); // "*.googleapis.com" -> ".googleapis.com"
    return BYPASS_HOSTS.filter(
      (entry) => entry.host.endsWith(suffix) || entry.host === suffix.slice(1)
    );
  }
  return BYPASS_HOSTS.filter((entry) => entry.host === lower);
}
