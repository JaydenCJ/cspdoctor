# Directive fallback chains

The single most common CSP misunderstanding is "default-src covers
everything". It does not. This table is what `cspdoctor coverage`
resolves for you, and what the analyzer grades against.

## Fetch directives

A fetch directive that is absent is governed by the next directive in
its chain; only if the whole chain is absent is the load unrestricted.

| Load context | Chain (first present wins) |
|---|---|
| `script-src` | `script-src` → `default-src` |
| `script-src-elem` | `script-src-elem` → `script-src` → `default-src` |
| `script-src-attr` | `script-src-attr` → `script-src` → `default-src` |
| `style-src` | `style-src` → `default-src` |
| `style-src-elem` | `style-src-elem` → `style-src` → `default-src` |
| `style-src-attr` | `style-src-attr` → `style-src` → `default-src` |
| `worker-src` | `worker-src` → `child-src` → `script-src` → `default-src` |
| `frame-src` | `frame-src` → `child-src` → `default-src` |
| `img-src`, `font-src`, `connect-src`, `media-src`, `object-src`, `manifest-src` | directive → `default-src` |

`worker-src` is the one everybody forgets: a worker URL is checked
against **child-src**, then **script-src**, then `default-src`.

## The no-fallback trio

These never consult `default-src`. Leaving them out leaves the surface
completely unrestricted — which is why cspdoctor has a dedicated rule
for each:

| Directive | When absent | Rule |
|---|---|---|
| `base-uri` | any injected `<base href>` rebases every relative URL | W207 |
| `form-action` | forms may submit to any origin | W209 |
| `frame-ancestors` | any site may frame the page (clickjacking) | W208 |

## Delivery caveats

`frame-ancestors`, `sandbox` and `report-uri` only function when the
policy arrives in the `Content-Security-Policy` response header. In a
`<meta http-equiv>` element browsers ignore them — run cspdoctor with
`--context meta` to have that graded (W204).
