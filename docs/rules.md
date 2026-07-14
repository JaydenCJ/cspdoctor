# Rule catalog

Codes are stable API: a code is never renumbered or repurposed, so
scripts and suppressions can match on them forever. New findings get new
codes. `cspdoctor explain <code>` prints the long-form rationale for any
rule below.

Three severities:

- **Errors (E1xx)** — the policy is weaker than written, or it holds the
  XSS door open. Errors fail `check` at every `--fail-on` level except
  `never`.
- **Warnings (W2xx)** — browsers will silently ignore something the
  author wrote, or a named defense is missing. Warnings fail the run at
  the default `--fail-on warning`.
- **Info (I3xx)** — hardening opportunities and honest notices (including
  "this is fine, here is why" findings such as I301/I302, so nobody is
  surprised by inert-looking sources in a strict policy).

Severity is graded against the **effective** policy: cspdoctor first
resolves CSP's fallback chains, so `default-src *` is an error while it
governs scripts and drops to a warning or notice once `script-src`,
`object-src`, `base-uri` and `worker-src` override it. That grading is
the difference between a CSP linter and a header pretty-printer.

## Errors

| Rule | Fired by | Typical fix |
|---|---|---|
| E101 | keyword written without quotes (`script-src unsafe-inline`) | quote it — browsers parsed it as a host |
| E102 | quoted token that is no CSP keyword (`'unsafe-inlin'`) | `did you mean 'unsafe-inline'?` |
| E103 | nonce payload that is not base64 | regenerate: 16+ random bytes, base64, per response |
| E104 | unknown hash algorithm or wrong digest length | recompute the sha256/384/512 digest |
| E105 | token outside the source-expression grammar | rewrite; browsers dropped it silently |
| E106 | `'strict-dynamic'` with no valid nonce/hash | add `'nonce-…'` — otherwise all scripts are blocked |
| E110 | `'unsafe-inline'` governing scripts, not neutralized | move to nonces/hashes |
| E111 | `'unsafe-eval'` where it governs `eval` | remove; `'wasm-unsafe-eval'` if wasm needs it |
| E112 | `*` (or `*` host) governing scripts/workers/plugins/`<base>` | list real origins |
| E113 | `https:` `http:` `data:` `blob:` `filesystem:` in a critical context | name origins; never `data:` for scripts |
| E114 | no `script-src`/`script-src-elem` and no `default-src` | add one — scripts are unrestricted |
| E115 | no `object-src` and no `default-src` | add `object-src 'none'` |

## Warnings

| Rule | Fired by | Typical fix |
|---|---|---|
| W201 | unknown directive name | `did you mean script-src?` |
| W202 | duplicate directive (browsers keep the first) | merge the source lists |
| W203 | deprecated/removed directive | use the named replacement |
| W204 | `frame-ancestors`/`sandbox`/`report-uri` under `--context meta` | deliver via the HTTP header |
| W205 | empty source list (behaves like `'none'`) | write `'none'` explicitly |
| W206 | `'none'` combined with other sources | keep `'none'` alone, or delete it |
| W207 | `base-uri` missing (never falls back) | `base-uri 'none'` |
| W208 | `frame-ancestors` missing (never falls back) | `frame-ancestors 'none'` |
| W209 | `form-action` missing (never falls back) | `form-action 'self'` |
| W210 | `'unsafe-inline'` governing styles, not neutralized | nonce/hash styles too |
| W211 | `*` in `connect-src`/`form-action`/`frame-*`/`style-*`/`manifest-src` | list real origins |
| W212 | `http:`/`ws:`/`ftp:` sources (loopback exempt) | serve over https/wss |
| W213 | valid nonce below 128 bits | 16+ random bytes per response |
| W214 | source with no effect in that directive (`'unsafe-eval'` in `style-src`) | move or delete it |
| W215 | allowlisted host from the known-bypass corpus (JSONP/AngularJS/user content) | self-host, or go nonce + `'strict-dynamic'` |

## Info

| Rule | Fired by |
|---|---|
| I301 | `'unsafe-inline'` neutralized by a valid nonce/hash — the intended compat fallback |
| I302 | host/scheme allowlist inert because `'strict-dynamic'` is present |
| I303 | no `report-to`/`report-uri` — enforcement without visibility |
| I304 | `upgrade-insecure-requests` not set |
| I305 | `report-uri` without `report-to` |
| I306 | `*` in `img-src`/`font-src`/`media-src` — broad but low-risk |
| I307 | `'wasm-unsafe-eval'` present (deliberate, narrower than `'unsafe-eval'`) |
| I308 | `'unsafe-hashes'` present (safer than `'unsafe-inline'`; refactoring removes the need) |
| I309 | policy delivered as `Content-Security-Policy-Report-Only` |

## Notes on scope (0.1.0)

- The value grammar of non-source-list directives (`sandbox` flags,
  `report-uri` URLs, `trusted-types` names, `webrtc`) is not yet checked.
- The bypass corpus (W215) is deliberately short and high-confidence;
  see `src/intel.ts` for the entries and their reasons.
- When a site sends several policies, browsers enforce all of them
  (a load must pass every policy). cspdoctor checks each policy
  independently, so a deliberately narrow second policy will still be
  told what it does not cover — read multi-policy reports per policy.
