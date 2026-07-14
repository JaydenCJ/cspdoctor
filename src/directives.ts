/**
 * The directive registry: every directive CSP Level 3 (plus the widely
 * deployed leftovers of Level 2) defines, with the metadata the analyzer
 * needs — fallback chains, delivery restrictions, deprecations, and
 * which keyword sources actually mean something where. This table is the
 * single source of truth; `docs/rules.md` and `cspdoctor explain` both
 * read from it.
 */

export type DirectiveKind = "fetch" | "document" | "navigation" | "reporting" | "other";

export interface DirectiveInfo {
  name: string;
  kind: DirectiveKind;
  /** True when the value is a CSP source list (vs tokens/URLs/nothing). */
  sourceList: boolean;
  /** Directives consulted, in order, when this one is absent. */
  fallback: readonly string[];
  /** False for directives browsers ignore inside a `<meta>` element. */
  metaAllowed: boolean;
  /** Set when the directive is deprecated or removed from the spec. */
  deprecated: { replacement: string | null; note: string } | null;
  /** One-paragraph documentation, used by `cspdoctor explain`. */
  doc: string;
}

function d(
  name: string,
  kind: DirectiveKind,
  options: Partial<Omit<DirectiveInfo, "name" | "kind">> & { doc: string }
): DirectiveInfo {
  return {
    name,
    kind,
    sourceList: options.sourceList ?? true,
    fallback: options.fallback ?? [],
    metaAllowed: options.metaAllowed ?? true,
    deprecated: options.deprecated ?? null,
    doc: options.doc,
  };
}

const REGISTRY: readonly DirectiveInfo[] = [
  // --- fetch directives -------------------------------------------------
  d("default-src", "fetch", {
    doc:
      "The fallback for every fetch directive that is not set explicitly. " +
      "It does NOT cover base-uri, form-action or frame-ancestors — those " +
      "never fall back, which is why cspdoctor checks them separately.",
  }),
  d("script-src", "fetch", {
    fallback: ["default-src"],
    doc:
      "Controls script execution: <script> elements, inline scripts, event " +
      "handlers and eval. The single most important directive in any policy; " +
      "the strict-CSP pattern is a per-response nonce plus 'strict-dynamic'.",
  }),
  d("script-src-elem", "fetch", {
    fallback: ["script-src", "default-src"],
    doc:
      "Controls <script> elements only (external and inline blocks). Falls " +
      "back to script-src, then default-src.",
  }),
  d("script-src-attr", "fetch", {
    fallback: ["script-src", "default-src"],
    doc:
      "Controls inline event handlers (onclick=…) and javascript: URLs. " +
      "Falls back to script-src, then default-src.",
  }),
  d("style-src", "fetch", {
    fallback: ["default-src"],
    doc:
      "Controls stylesheets: <link rel=stylesheet>, <style> blocks and " +
      "style attributes. Injected CSS can deface a page and exfiltrate " +
      "data through attribute selectors, so it deserves real sources too.",
  }),
  d("style-src-elem", "fetch", {
    fallback: ["style-src", "default-src"],
    doc: "Controls <style> elements and stylesheet links only.",
  }),
  d("style-src-attr", "fetch", {
    fallback: ["style-src", "default-src"],
    doc: "Controls inline style= attributes only.",
  }),
  d("img-src", "fetch", {
    fallback: ["default-src"],
    doc: "Controls image loads, including favicons.",
  }),
  d("font-src", "fetch", {
    fallback: ["default-src"],
    doc: "Controls web font loads (@font-face).",
  }),
  d("connect-src", "fetch", {
    fallback: ["default-src"],
    doc:
      "Controls script-initiated network: fetch, XHR, WebSocket, " +
      "EventSource, sendBeacon. This is the exfiltration directive — a " +
      "wildcard here lets injected script ship data anywhere.",
  }),
  d("media-src", "fetch", {
    fallback: ["default-src"],
    doc: "Controls <audio>, <video> and <track> loads.",
  }),
  d("object-src", "fetch", {
    fallback: ["default-src"],
    doc:
      "Controls <object> and <embed>. Plugin content can execute script, " +
      "so every hardened policy sets object-src 'none'.",
  }),
  d("child-src", "fetch", {
    fallback: ["default-src"],
    doc:
      "Legacy umbrella for frames and workers. In CSP3 it survives only as " +
      "the fallback for frame-src and worker-src; prefer setting those.",
  }),
  d("frame-src", "fetch", {
    fallback: ["child-src", "default-src"],
    doc: "Controls what may be embedded in <iframe>/<frame> on this page.",
  }),
  d("worker-src", "fetch", {
    fallback: ["child-src", "script-src", "default-src"],
    doc:
      "Controls Worker, SharedWorker and ServiceWorker script URLs. Falls " +
      "back through child-src and script-src to default-src.",
  }),
  d("manifest-src", "fetch", {
    fallback: ["default-src"],
    doc: "Controls web app manifest loads.",
  }),
  d("prefetch-src", "fetch", {
    fallback: ["default-src"],
    deprecated: {
      replacement: null,
      note: "removed from the spec; prefetches follow the fetched resource's own directive",
    },
    doc:
      "Controlled link-prefetch targets. Removed from CSP3 and dropped by " +
      "browsers; prefetches are now governed by the directive of the " +
      "resource type being prefetched.",
  }),
  // --- document directives ----------------------------------------------
  d("base-uri", "document", {
    doc:
      "Restricts what <base href> may point at. It never falls back to " +
      "default-src: leave it unset and one injected <base> tag rebases " +
      "every relative script URL on the page to an attacker's origin.",
  }),
  d("sandbox", "document", {
    sourceList: false,
    metaAllowed: false,
    doc:
      "Applies an iframe-style sandbox to the page itself, taking sandbox " +
      "flags (allow-scripts, allow-forms, …) rather than a source list. " +
      "Ignored when delivered in a <meta> element.",
  }),
  d("plugin-types", "document", {
    sourceList: false,
    deprecated: {
      replacement: "object-src 'none'",
      note: "removed from the spec along with plugins",
    },
    doc:
      "Restricted which plugin MIME types could load. Removed from CSP3; " +
      "set object-src 'none' instead.",
  }),
  // --- navigation directives ---------------------------------------------
  d("form-action", "navigation", {
    doc:
      "Restricts where forms may submit. It never falls back to " +
      "default-src: leave it unset and an injected <form action=…> can " +
      "send passwords anywhere, even under an otherwise strict policy.",
  }),
  d("frame-ancestors", "navigation", {
    metaAllowed: false,
    doc:
      "Restricts who may embed this page (the clickjacking defense; it " +
      "obsoletes X-Frame-Options). Never falls back to default-src and " +
      "only works from the HTTP header, never from <meta>.",
  }),
  d("navigate-to", "navigation", {
    deprecated: {
      replacement: null,
      note: "removed from the CSP3 draft before shipping in any browser",
    },
    doc:
      "Was going to restrict where the document may navigate. Removed from " +
      "the CSP3 draft; no browser ships it.",
  }),
  // --- reporting directives ----------------------------------------------
  d("report-uri", "reporting", {
    sourceList: false,
    metaAllowed: false,
    doc:
      "Legacy violation reporting endpoint (deprecated in CSP3 but still " +
      "the most interoperable option). Keep it alongside report-to during " +
      "the transition; browsers that understand report-to ignore report-uri.",
  }),
  d("report-to", "reporting", {
    sourceList: false,
    doc:
      "Names a Reporting-Endpoints group to receive violation reports — " +
      "the CSP3 replacement for report-uri. Requires a matching " +
      "Reporting-Endpoints (or Report-To) header.",
  }),
  // --- other directives --------------------------------------------------
  d("upgrade-insecure-requests", "other", {
    sourceList: false,
    doc:
      "Rewrites http:// subresource URLs to https:// before fetching — the " +
      "painless way to clean up legacy mixed content. Takes no value.",
  }),
  d("block-all-mixed-content", "other", {
    sourceList: false,
    deprecated: {
      replacement: "upgrade-insecure-requests",
      note: "obsolete; browsers block mixed content by default now",
    },
    doc:
      "Blocked all mixed content. Deprecated: browsers now block or " +
      "upgrade mixed content by default; use upgrade-insecure-requests.",
  }),
  d("require-trusted-types-for", "other", {
    sourceList: false,
    doc:
      "With the value 'script', forces DOM XSS sinks (innerHTML, eval-like " +
      "APIs) to accept only Trusted Types objects instead of strings.",
  }),
  d("trusted-types", "other", {
    sourceList: false,
    doc:
      "Allowlists the Trusted Types policy names the page may create; " +
      "pairs with require-trusted-types-for.",
  }),
  d("require-sri-for", "other", {
    sourceList: false,
    deprecated: {
      replacement: null,
      note: "removed from the spec; no browser ships it",
    },
    doc:
      "Was going to require Subresource Integrity for scripts/styles. " +
      "Removed from the spec.",
  }),
  d("referrer", "other", {
    sourceList: false,
    deprecated: {
      replacement: "the Referrer-Policy header",
      note: "dropped from CSP long ago",
    },
    doc:
      "Early mechanism for referrer control inside CSP. Long dead; send a " +
      "Referrer-Policy header instead.",
  }),
  d("webrtc", "other", {
    sourceList: false,
    doc: "Set to 'allow' or 'block' to control WebRTC transport setup.",
  }),
];

/** Lookup by lowercased directive name. */
export const DIRECTIVES: ReadonlyMap<string, DirectiveInfo> = new Map(
  REGISTRY.map((info) => [info.name, info])
);

/** Every known directive name, in registry (spec-section) order. */
export function directiveNames(): string[] {
  return REGISTRY.map((info) => info.name);
}

/**
 * The load contexts cspdoctor resolves and grades. Each entry is a
 * directive name whose fallback chain answers "what governs this kind of
 * load?". Deprecated fetch directives are not contexts.
 */
export const CONTEXTS: readonly string[] = [
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "worker-src",
  "object-src",
  "base-uri",
  "img-src",
  "font-src",
  "connect-src",
  "media-src",
  "frame-src",
  "manifest-src",
  "form-action",
  "frame-ancestors",
];

/** Contexts where an overly broad source means script execution or equivalent. */
export const CRITICAL_CONTEXTS: ReadonlySet<string> = new Set([
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "worker-src",
  "object-src",
  "base-uri",
]);

/** Contexts where a wildcard enables exfiltration, framing or CSS injection. */
export const MEDIUM_CONTEXTS: ReadonlySet<string> = new Set([
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "connect-src",
  "frame-src",
  "manifest-src",
  "form-action",
  "frame-ancestors",
]);

/** Contexts where a wildcard is broad but usually tolerable. */
export const LOW_CONTEXTS: ReadonlySet<string> = new Set([
  "img-src",
  "font-src",
  "media-src",
]);

/** Script-execution contexts (for 'unsafe-inline' / nonce reasoning). */
export const SCRIPT_CONTEXTS: ReadonlySet<string> = new Set([
  "script-src",
  "script-src-elem",
  "script-src-attr",
]);

/** Style contexts (for the CSS-injection variant of 'unsafe-inline'). */
export const STYLE_CONTEXTS: ReadonlySet<string> = new Set([
  "style-src",
  "style-src-elem",
  "style-src-attr",
]);

const SCRIPTISH = ["default-src", "script-src", "script-src-elem", "script-src-attr"];
const STYLISH = ["default-src", "style-src", "style-src-elem", "style-src-attr"];

/**
 * Directives where each keyword source has a defined effect. A keyword
 * outside its column is not an error in browsers — it is silently
 * ignored, which is exactly why cspdoctor warns about it (W214).
 */
const KEYWORD_HOMES: Readonly<Record<string, readonly string[]>> = {
  "unsafe-inline": [...SCRIPTISH, ...STYLISH.slice(1)],
  "unsafe-eval": ["default-src", "script-src"],
  "wasm-unsafe-eval": ["default-src", "script-src"],
  "unsafe-hashes": [...SCRIPTISH, ...STYLISH.slice(1)],
  "strict-dynamic": SCRIPTISH,
  "report-sample": [...SCRIPTISH, ...STYLISH.slice(1)],
  "inline-speculation-rules": ["default-src", "script-src", "script-src-elem"],
};

/** Directives where nonce-/hash-sources participate in matching. */
const NONCE_HASH_HOMES: readonly string[] = [...SCRIPTISH, ...STYLISH.slice(1)];

/** True when the given keyword source has any effect in `directive`. */
export function keywordMeaningfulIn(keyword: string, directive: string): boolean {
  if (keyword === "self" || keyword === "none") return true;
  const homes = KEYWORD_HOMES[keyword];
  if (homes === undefined) return true; // unknown keyword: judged elsewhere
  return homes.includes(directive);
}

/** True when a nonce or hash source has any effect in `directive`. */
export function nonceHashMeaningfulIn(directive: string): boolean {
  return NONCE_HASH_HOMES.includes(directive);
}
