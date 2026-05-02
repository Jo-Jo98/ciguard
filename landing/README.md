# ciguard.dev landing page

Static site for `ciguard.dev`, built with Astro 4.x. Output is
plain HTML/CSS in `dist/` — no client-side JS, no runtime, no
analytics. Cloudflare Pages serves the built directory directly.

## Local development

```bash
cd landing
npm install
npm run dev          # http://localhost:4321
```

`npm run build` produces a static `dist/` directory.
`npm run preview` serves the built output locally for sanity-checking.

## Deploy on Cloudflare Pages

Wire `landing/` as a Pages project:

| Setting          | Value                       |
|------------------|-----------------------------|
| Build command    | `npm run build`             |
| Build output dir | `dist`                      |
| Root directory   | `landing`                   |
| Node version     | `20` (engines pin in `package.json`) |

Custom domain `ciguard.dev` (already at Cloudflare Registrar) attaches
to the Pages project. The existing CNAME redirect to the GitHub repo
is replaced once Pages is live.

`public/_headers` ships the security-header set Cloudflare honours
(CSP, HSTS, no-cohort, frame-deny). Hashed assets under `_assets/`
get a far-future immutable cache.

## Brand mark

- Visual logo: **CIGuard** (uppercase CI + uppercase G) — used in
  hero, footer, OG images
- Identifier: lowercase `ciguard` — used in code (`pip install
  ciguard`, `ghcr.io/jo-jo98/ciguard`, repo path)

Same dark-mode palette as the in-app HTML deliverables
(`html_interactive.py` / `topology_html.py` / `inventory_html.py` /
`org_audit_html.py`) so the brand reads as one family across the
marketing surface and the audit artifacts.
