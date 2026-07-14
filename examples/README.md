# Examples

Three policies you will recognize from real audits. `weak.txt` is a saved
`curl -sI` response whose policy makes the five classic mistakes
('unsafe-inline', 'unsafe-eval', a bare `https:`, an unquoted keyword, a
wildcard `object-src`). `legacy.txt` is a tidy-looking allowlist policy
whose problems are subtler — a bypassable CDN host, a truncated hash, a
duplicate directive, a deprecated directive. `strict.txt` is the
nonce-plus-'strict-dynamic' recipe and exits 0.

The test suite and `scripts/smoke.sh` both run against these files, so
they are guaranteed to stay accurate.

## Try it

```bash
# from the repository root, after `npm install && npm run build`
node dist/cli.js check --file examples/weak.txt     # exit 1: 5 errors, 4 warnings
node dist/cli.js check --file examples/legacy.txt   # exit 1: 1 error, 8 warnings
node dist/cli.js check --file examples/strict.txt   # exit 0: info only
node dist/cli.js coverage --file examples/strict.txt
```

## What the seeded weaknesses demonstrate

| Weakness in `weak.txt` | Rule | Why it matters |
|---|---|---|
| `script-src … 'unsafe-inline'` | E110 | injected `<script>` runs — the thing CSP exists to stop |
| `script-src … 'unsafe-eval'` | E111 | injected strings become code via `eval` |
| `script-src … https:` | E113 | "https:" allows every HTTPS origin on the internet |
| `script-src … ajax.googleapis.com` | W215 | known JSONP/AngularJS bypass host |
| `style-src … unsafe-inline` (no quotes) | E101 | parsed as a host named "unsafe-inline"; keyword inert |
| `object-src *` | E112 | any origin may serve plugin content |
| no `base-uri` / `frame-ancestors` / `form-action` | W207–W209 | these never fall back to `default-src` |

## CI gate

`ci-gate.sh` shows the intended CI wiring: save the response headers of
the deployment you are gating, run `cspdoctor check` over them, and let
the exit code decide. Run it from the repository root:

```bash
bash examples/ci-gate.sh
```
