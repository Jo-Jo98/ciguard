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

Deploys are infrastructure-as-code: every push to `main` that touches
`landing/**` triggers `.github/workflows/landing-deploy.yml`, which
builds `dist/` on a fresh runner and uploads it to Cloudflare Pages
project `ciguard` via `wrangler-action@v3` (SHA-pinned). Build
settings live in `landing/wrangler.jsonc` so future changes go
through PR review.

### One-time bootstrap (cutover)

The workflow can't run until the Cloudflare side is wired up. Steps:

1. **Mint a scoped Cloudflare API token.** Dashboard → My Profile →
   API Tokens → Create Token → "Custom token" with these scopes (and
   nothing else):
   - **Account** → **Cloudflare Pages** → **Edit**
   - **Zone** → **DNS** → **Edit** (for `ciguard.dev` only — restrict
     under "Zone Resources")

   This is much narrower than the global API key and revocable
   independently if it leaks.

2. **Add two repo secrets** at
   <https://github.com/Jo-Jo98/ciguard/settings/secrets/actions>:
   - `CLOUDFLARE_API_TOKEN` — the token from step 1
   - `CLOUDFLARE_ACCOUNT_ID` — visible on the Cloudflare dashboard
     home (right sidebar)

3. **Create the Pages project** (one-time; subsequent deploys are
   automatic). Either:
   - Dashboard: Pages → Create project → Direct Upload → name `ciguard`
     → "Create empty project". The first GitHub Actions run will
     populate it.
   - Or via the GitHub Actions tab: trigger
     `Landing page (ciguard.dev) deploy` via `workflow_dispatch` —
     wrangler creates the project on first deploy.

4. **Attach the custom domains.** Pages → `ciguard` project →
   Custom domains → Add → `ciguard.dev` (and again for
   `www.ciguard.dev`). Cloudflare swaps the existing CNAME records
   automatically because registrar = pages provider.

5. **Delete the old redirect rule.** Cloudflare dashboard → Rules →
   Redirect Rules → delete the `ciguard.dev → github.com/Jo-Jo98/ciguard`
   rule. DNS now resolves to the Pages deployment.

6. **Verify.** `curl -sI https://ciguard.dev` should return
   `HTTP/2 200`, the response should carry the security headers from
   `public/_headers` (HSTS, X-Frame-Options DENY, CSP, etc.), and
   <https://securityheaders.com/?q=ciguard.dev> should grade A.

After the bootstrap, every push to `main` that changes `landing/**`
auto-deploys; PRs against `landing/**` get preview deployments at
`<branch>.<project>.pages.dev`.

### Deploy settings recorded as code

| Setting          | Value                                |
|------------------|--------------------------------------|
| Project name     | `ciguard`                            |
| Build command    | `npm run build` (in `landing/`)      |
| Build output dir | `dist`                               |
| Root directory   | `landing`                            |
| Node version     | `22` (workflow + `engines` pin in `package.json`) |
| Production branch| `main`                               |

`public/_headers` ships the security-header set Cloudflare honours
(CSP, HSTS, no-cohort, frame-deny). Hashed assets under `_assets/`
get a far-future immutable cache.

### Manual deploy (rarely needed)

```bash
cd landing
npm ci
npm run build
npx wrangler pages deploy dist --project-name=ciguard
```

Requires `wrangler login` (interactive browser auth) or
`CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` env vars.

## Brand mark

- Visual logo: **CIGuard** (uppercase CI + uppercase G) — used in
  hero, footer, OG images
- Identifier: lowercase `ciguard` — used in code (`pip install
  ciguard`, `ghcr.io/jo-jo98/ciguard`, repo path)

Same dark-mode palette as the in-app HTML deliverables
(`html_interactive.py` / `topology_html.py` / `inventory_html.py` /
`org_audit_html.py`) so the brand reads as one family across the
marketing surface and the audit artifacts.
