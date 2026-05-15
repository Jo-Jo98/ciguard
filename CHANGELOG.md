# Changelog

All notable changes to `ciguard` will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security disclosures (post-release CVE allocation)

- **Three of the four 2026-04-27 Cycle 1 GHSAs were assigned CVE identifiers on 2026-05-05** by GitHub via MITRE in a sequential block. These reference vulnerabilities that were already fixed in v0.8.2; no new code change. Downstream consumers (Snyk / Tenable / NVD-driven tooling) can now correlate to CVE records:
  - [GHSA-jrm4-4pcf-4763](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-jrm4-4pcf-4763) — Container image runs as root → **[CVE-2026-44218](https://www.cve.org/CVERecord?id=CVE-2026-44218)** (Low)
  - [GHSA-xw8c-rrvx-f7xq](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-xw8c-rrvx-f7xq) — SCA HTTP client reads response body without size cap → **[CVE-2026-44219](https://www.cve.org/CVERecord?id=CVE-2026-44219)** (Low)
  - [GHSA-8cxw-cc62-q28v](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-8cxw-cc62-q28v) — `discover_pipeline_files` follows symlinks out of scan root → **[CVE-2026-44220](https://www.cve.org/CVERecord?id=CVE-2026-44220)** (Low — see `Pentest Reports/2026-05-12-cycle-1.md` § 12 for the v3.1-vs-v4.0 severity drift)
  - [GHSA-7ww3-xvf5-cxwm](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-7ww3-xvf5-cxwm) — Web UI missing HTTP defence-in-depth headers (Medium) — **CVE pending** as of 2026-05-15.

## [0.11.2] — 2026-05-03

**Highlights:** Cycle 1.5 cleanup release — closes the four follow-up issues filed at v0.11.1 (#20–#23). One small defence-in-depth code change in the App private-key loader, one belt-and-braces strict-OWS check on the webhook signature header, and two documentation patches. No new features. Test count: 977 → 985 (+8).

### Security / hardening

- **Issue [#22](https://github.com/Jo-Jo98/ciguard/issues/22) — App private-key file mode lint (Cycle 1.5 finding A1).** `tokens.py::_load_private_key()` now `os.stat()`s the path supplied via `CIGUARD_APP_PRIVATE_KEY_PATH` and emits a `WARNING` if the mode permits group or world access (i.e. `mode & 0o077 != 0`). The warning recommends `chmod 600` and uses the basename only — never the full path. **Warns, does NOT raise** — dev workflows often run with whatever mode the secret-injector landed; the operator's filesystem permissions are still the primary control. Defence-in-depth so a CI-deployed `.pem` accidentally landed at 0644 is surfaced at startup rather than silently. Four new tests cover 0644 / 0640 / 0600 / no-path-leak invariants.
- **Issue [#23](https://github.com/Jo-Jo98/ciguard/issues/23) — Strict-OWS rejection on `X-Hub-Signature-256` (Cycle 1.5 finding F-9.1.1).** `webhook.py::_verify_signature()` now raises 401 if the supplied header value differs from `value.strip()` — leading or trailing ASCII OWS is no longer accepted. **Important honesty note:** under the canonical Uvicorn-on-h11 deploy, this check is a **no-op** because h11 strips OWS per RFC 7230 Section 3.2.4 *before* the ASGI handler ever sees the value (empirically verified during this fix). The check is load-bearing if a future deploy switches ASGI server (Hypercorn, Daphne, a pure-asyncio stack) or fronts the App with a quirky proxy that doesn't strip. Operators who want WAF-aligned strict parsing in the canonical Uvicorn deploy should add the new nginx / Apache snippets in `DEPLOYMENT.md` Section 5 ("Strict-OWS rejection at the proxy"). The HMAC over the request body remains the load-bearing control either way; F-9.1.1 was Info severity (CVSS 0.0) with no exploitation chain. Three new direct unit tests + one path-pinning test + a standalone PoC at `tests/regression/cycle1.5/F-9.1.1-ows-signature.py`.

### Documentation

- **Issue [#20](https://github.com/Jo-Jo98/ciguard/issues/20) — `Actions: read` removed from the App permission spec (Cycle 1.5 finding A2).** `THREAT_MODEL.md` Surface 9 row, the manifest at `deploy/app/manifest.yml`, the README "Register the App" section, and the `DEPLOYMENT.md` manifest-drift callout all now reflect the four-permission spec the registered ciguard App on github.com actually runs under (`Contents: read`, `Pull requests: write`, `Checks: write`, `Metadata: read`). The v0.11.x scan executor reaches workflow YAML via the tarball clone (covered by `Contents: read`) — the Actions API is never called. The `DEPLOYMENT.md` "manifest drift" warning callout that promised this patch is removed.
- **Issue [#21](https://github.com/Jo-Jo98/ciguard/issues/21) — `_enforce_size_cap()` docstring expanded (Cycle 1.5 row 10.6 Info).** The MCP redaction layer's response-cap function now documents the behavioural delta surfaced during Cycle 1.5: when the cap fires, list-shaped sub-payloads are clipped to a fixed 25-element slice rather than packed-to-just-under-cap, plus the empirical 1.6 MB → ~27 KB example from row 10.6. Behaviour unchanged — the docstring now matches the long-standing intent (a fixed marker forces consumers to detect "this is not the full set" deterministically).

### Engineering hygiene

- **Test count:** 977 → 985 (+8). Four `_load_private_key` mode-warning tests, three `_verify_signature` OWS-rejection tests, one path-pinning test for the existing internal-whitespace-via-mismatch case.
- **Cycle 1.5 backlog:** all four post-cycle issues now closed. Cycle 1.5 self-pentest closes fully green; the next reportable surface is Cycle 2 on 2026-10-15.

## [0.11.1] — 2026-05-03

**Highlights:** The GitHub App receiver now ships a real scan executor — v0.10.0's stub is gone. On every webhook, the App mints an installation token, fetches the repo tarball at the head SHA from `GET /repos/{o}/{r}/tarball/{ref}`, extracts it under a `tempfile.TemporaryDirectory()` with per-member validation, runs `repo_scan.scan_repo(include_findings=True)` against the extracted tree, and posts the findings back as a Check Run + PR comment. v0.11.1 also closes the only finding from the Cycle 1.5 self-pentest (F-9.6.1, NUL bytes in `_safe_md_inline`), adds a 12-section production-deploy guide (`DEPLOYMENT.md`), and fixes a CodeQL `py/tarslip` advisory by switching `tar.extractall()` to per-member `tar.extract()`. Test count: 962 → 977 (+15).

### Security

- **F-9.6.1 — `_safe_md_inline()` now strips ASCII NUL + remaining C0 control chars.** Surfaced by Cycle 1.5 self-pentest (2026-05-03). The inline PR-comment sanitiser previously stripped CR/LF/tab and HTML-encoded `<>` but let `\x00` through. CWE-158 (Improper Neutralization of Null Byte). CVSS v3.1 3.7 (Low). The block-level sibling `_safe_md_block()` was already safe via its 4-backtick fence wrapping. New regression PoC at `tests/regression/cycle1.5/F-9.6.1-null-byte-inline.py` locks the fix in CI. Disclosure: same-day publishable per `feedback_coordinated_disclosure_window.md` rationale (verified ~zero installs at test time); no GHSA filed.
- **CodeQL `py/tarslip` (CWE-22) advisory closed** — v0.11.1's clone executor previously called `tar.extractall(path=dest)` after a manual member-validation pass; CodeQL pattern-matches `extractall()` regardless of preceding validation, AND `extractall` operates on the live `members` list which a hostile `tarfile` subclass could re-mutate between validation and extraction. Now validates AND extracts one member at a time via `tar.extract(member, path=dest)` — TOCTOU window closed, CodeQL silenced. On Python 3.12+ also passes `filter="data"` belt-and-braces.
- **Cycle 1.5 self-pentest closed green.** 21 of 21 in-scope rows Verified across Surface 9 (GitHub App receiver, 13 STRIDE rows) + Surface 10 (MCP redaction, 7 PoC rows) + 4-row Cycle-1 regression retest. All four 2026-04-27 GHSAs remain CLOSED in v0.11.1. Full CREST-style report at `Pentest Reports/2026-05-03-cycle-1.5.md` in the planning vault. Two reportable findings: F-9.6.1 (Low, fixed) + F-9.1.1 (Info, ASCII OWS in signature header — issue [#23](https://github.com/Jo-Jo98/ciguard/issues/23), defence-in-depth observation only, no exploitation chain).

### Added — GitHub App scan executor

- **`clone_and_scan_executor`** in `src/ciguard/app/clone_executor.py` — replaces v0.10.0's `_stub_scan_executor` as the default in `factory.py`. Pipeline: mint installation token → `GET /repos/{o}/{r}/tarball/{ref}` with `Authorization: token <ghs_…>` (token in header, never URL) → extract under `tempfile.TemporaryDirectory()` with per-member safety validation → `repo_scan.scan_repo(include_findings=True)` → translate to PR-comment-renderer shape. Stub kept available for tests via `create_app(scan_executor=...)` injection.
- **Why tarball, not `git clone`:** no `git` binary in the deploy image (smaller container, fewer CVEs to patch); single HTTP request instead of multi-stage clone+fetch+checkout; tarball auto-derived from the ref so no "did the shallow clone include this SHA?" edge cases; smaller transfer (no `.git/objects`).
- **Threat-model controls landed:** 200 MB streaming size cap (`TarballTooLarge`) closes Surface 9 row "Webhook handler DoS"; token in `Authorization` header (never URL) closes Surface 9 row "Installation token leakage"; per-member `extract()` after validation closes archive-injection sub-row of "Multi-tenant baseline.json bleed"; HTTP 401 from tarball API triggers `tokens.invalidate_token()` to honour Surface 9 row "Cached installation token used after revocation".
- **`repo_scan.scan_repo(include_findings=True)`** — new opt-in keyword. Default off preserves v0.9.x dict shape that the CLI scan-repo + MCP scan_repo tool depend on. With it on, the result dict gains `findings` (flat list across all files), per-file `findings`, and aggregate `risk_score` / `grade` (worst per-file score gates the repo).

### Added — `DEPLOYMENT.md`

- **12-section production-deploy guide** at `DEPLOYMENT.md` — operator-facing companion to README. Covers: what you're deploying (single-process, in-memory queue, 200 MB cap), App registration via `deploy/app/manifest.yml`, secret material + file-mode hygiene, dedicated non-root UID (`useradd --system ciguard`), reverse proxy + TLS (full nginx `/webhook` block with `request_buffering off` so raw bytes reach HMAC unmodified), systemd unit with the hardening directives that close Surface 9 row "App private key exposure" (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `ProtectKernel*`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, `ReadWritePaths` bound to storage), container layout (`--cap-drop=ALL --security-opt no-new-privileges`, read-only root), storage layout `<root>/<install_id>/<owner>/<repo>/baseline.json` + backup posture, observability (logger map + what to alert on), upgrades + rollback (Sigstore + PEP 740 verification snippets), full env-var contract for all 12 `CIGUARD_*` vars, 11-box pre-flight checklist.
- README "Running the GitHub App" section bumped from v0.10.0 to v0.11.1; stub-status callout removed; cross-reference to `DEPLOYMENT.md` added.

### Cycle 1.5 follow-up issues filed (no time pressure; ship in next minor)

- **[#20](https://github.com/Jo-Jo98/ciguard/issues/20)** — Drop `Actions: read` from `THREAT_MODEL.md` Surface 9 + `deploy/app/manifest.yml` (the v0.11 stub-and-real scan paths don't use it; tarball clone carries workflow files anyway). Documentation patch.
- **[#21](https://github.com/Jo-Jo98/ciguard/issues/21)** — Document MCP redaction-layer truncation behaviour (`_enforce_size_cap` collapses to a marker rather than packing-to-fit when the cap fires). Docstring expansion.
- **[#22](https://github.com/Jo-Jo98/ciguard/issues/22)** — Lint `.pem` file mode in `_load_private_key()` — defence-in-depth (operator's filesystem permissions are the primary control, but `os.stat() & 0o077 == 0` would surface misconfigurations earlier). Hardening.
- **[#23](https://github.com/Jo-Jo98/ciguard/issues/23)** — Permissive ASCII OWS in `X-Hub-Signature-256` header (F-9.1.1 from the cycle 1.5 report — Info, CVSS 0.0). Library-level OWS-strip per RFC 7230 §3.2.4 means leading SPACE/TAB in the signature value is silently accepted. HMAC over the body is unaffected; defence-in-depth concern only. Address only on a concrete WAF/IDS gap report.

### Engineering hygiene

- **Per-member `tar.extract()`** in `clone_executor` — cleaner than `extractall()` because the validation and extraction happen on the same `member` object reference. No risk of TOCTOU if a hostile `tarfile` subclass remutates `members` between validation pass and extraction.
- **`assert sys.version_info >= (3, 12)`** removed from `clone_executor` import time — was blocking 3.10/3.11 test runs (the package's declared `python_requires=">=3.10"` envelope). Replaced with manual `_safe_extract` that works on all supported Pythons; 3.12+ still gets `filter="data"` belt-and-braces.
- **`# nosec B310`** annotation on the single `urllib.request.urlopen` call site, with rationale: URL constructed from the hardcoded `GITHUB_API_BASE` constant + caller-controlled owner/repo/ref; scheme always https; no file:// or custom-scheme exposure.
- **§ → "Section" sweep** across DEPLOYMENT.md and the Cycle 1.5 vault docs — long-standing user preference (not legalistic). Memory `feedback_documentation_conventions.md` strengthened with the second-time-broke-it warning + reset recipe.

## [0.11.0] — 2026-05-03

**Highlights:** This release matures ciguard from per-pipeline scanner to org-wide audit deliverable. Slices 14b/14c/15/16/17 add cross-pipeline topology with live-API verification, an org-level dashboard with per-repo D3 drill-downs, MCP redaction + audit-log hardening, and three pin-discipline rules. Slice 10 ships ciguard.dev — a static landing page on Cloudflare Pages with CAA pinning, DMARC/SPF email-spoofing lockdown, 404 page, robots, and sitemap. Atheris weekly fuzz finding #18 (pyyaml RecursionError on deeply-nested input) is fixed. Test count: 743 → 962 (+219).

### Security

- **Fuzz #18 — pyyaml RecursionError now wrapped as ValueError on every yaml.safe_load site.** Atheris weekly run (2026-05-03) found a 1915-byte deeply-nested YAML input that escaped each parser's `yaml.YAMLError` handler. Production sites in `parser/github_actions.py`, `parser/gitlab_parser.py`, `ignore.py`, and `topology/loader.py` now wrap `RecursionError` as the same `ValueError` / `TopologyLoadError` they emit for malformed YAML. The Atheris harness's `EXPECTED` tuple gains `RecursionError` so the harness keeps catching new crash classes. Severity assessment: low for the CLI (trusted file input), but real-DoS for the GitHub App webhook + MCP server paths that ship in this release. Original Atheris artifact preserved at `tests/fixtures/fuzz/recursion-yaml-issue-18.bin`; regression test pins the bug class with a synthetic 2000-deep nest. Closes #18.

### Added — Slice 17 (org-level audit dashboard — three sessions)

#### Session 1 — repo enumeration + scan + rollup

- **`ciguard audit-org --org <name>`** walks every repo in a GitHub organisation, fetches pipeline files via the Contents API, materialises them to a tempdir per repo, runs `scan_repo()` against the tempdir, and rolls per-repo results into one `OrgAuditReport`. Routing through the same `scan_repo()` helper the CLI + MCP scan_repo tool already use means every per-file finding the org dashboard reports is the same finding `scan-repo` would have reported run locally.
- **`OrgProvider` Protocol** (`list_repos(org)` + `fetch_pipeline_files(repo)`) keeps platform-specific wiring isolated. `GitHubOrgProvider` is the only concrete implementation today; GitLab / Bitbucket / Azure DevOps fit the same shape. Pagination via `?page=N&per_page=100` up to 5,000 repos; user-vs-org fallback when the slug isn't an org; 404 → None for soft-miss handling on root-level pipeline file probes (.gitlab-ci.yml / Jenkinsfile most repos won't have).
- **Filtering:** `--include` / `--exclude` regex on `owner/name`, `--limit` caps the audit universe (after filtering). Forks + archived repos honoured by Contents API behaviour. `CIGUARD_GITHUB_TOKEN` for auth; `CIGUARD_GITHUB_API_URL` override for GHE.
- **Output:** text-format dashboard summary by default; `--format html` writes a self-contained dark-mode org dashboard (severity chips, grade distribution, platform mix, skipped/error tracking) reusing the existing visual vocabulary; `--format json` emits the full `OrgAuditReport`.

#### Session 2 — image inventory + pin-discipline rollup

- **`OrgAuditReport.image_inventory`** — list of one record per distinct image-name (dedup key is the bare name, not the full `image:tag` string, because the auditor's question is "how many flavours of python are we running"). Each record carries the set of repos using it, distinct tag values seen, pin-status mix, registries seen, and total reference count.
- **`OrgAuditReport.image_inconsistencies`** — subset where `distinct_tag_count > 1`, the headline auditor callout ("twelve flavours of python across fifty services"). Sorted by descending repo-count then ascending name.
- **`OrgAuditReport.pin_discipline`** — counts + 1-decimal percentages for digest / tag / mutable across every image reference in every scanned repo. The denominator the audit-scope spec wanted.
- **Implementation** in new `audit_org/images.py` re-parses each pipeline file in the materialised tempdir and calls the existing `extract_image_references()` from sca_rules, so the digest/tag/mutable classification matches what the per-pipeline scan reports — single source of truth.
- **Dashboard surfaces:** image-inventory panel with the multi-variant inconsistencies upfront; text summary gains a pin-discipline percentage line + an inconsistency call-out listing the top 5 multi-variant images with their tag set.

#### Session 3 — per-repo drill-down maps

- **`ciguard audit-org --output-dir DIR`** writes the dashboard to `<DIR>/dashboard.html` and one `html-interactive` pipeline map per discovered pipeline file under `<DIR>/repos/<owner>__<name>/<stem>.html`. Dashboard repo rows render link chips for each rendered map so an auditor can drill from the org view straight into a specific pipeline's D3 visualisation.
- **Filesystem layout** chosen so relative `<a href>` from the dashboard resolves without a server (works in `file://` mode), browsable via `ls`, no nested-deep paths that confuse operators copying the deliverable to a fileshare. Slash in `owner/name` collapsed to `__` (avoids needing to mkdir a subdirectory per owner).
- **CLI surface:** `--output-dir DIR` flag. When set, the dashboard always writes to `<DIR>/dashboard.html`; explicit `--output` is honoured only when `--output-dir` is unset (preserves the session-1 single-file behaviour).

**Test count across Slice 17:** 874 → 965 (+91) — 23 audit-org orchestrator tests, 14 image-inventory tests, 5 drill-down tests, 8 dashboard-rendering tests, 11 reporter tests, plus Contents API materialisation integration coverage.

### Added — Slice 16 session 4 (topology live-API verification)

- **`ciguard topology --verify`** cross-checks the operator-asserted topology against the live SCM platform on the gate dimension, complementing session 3's drift panel on the file dimension. Surfaces three drift kinds: environment-not-found (asserted env doesn't exist), gate-not-actual (asserted protection missing on the live env), gate-actual-not-asserted (live env has a rule the topology under-claims).
- **`GitHubProvider` implementation** reads `/repos/{owner}/{repo}/environments` and `/repos/{owner}/{repo}/branches/{default}/protection`, normalising GitHub's protection-rule shape onto ciguard's gate vocabulary (`required_reviewers` → `manual_approval` + `required_reviewer`; `wait_timer` → `wait_timer`; `branch_policy` → `deployment_environment_protection`). Token via `CIGUARD_GITHUB_TOKEN`; `CIGUARD_GITHUB_API_URL` override for GHE.
- **Provider is a Protocol** (single `fetch(repo) → RepoSnapshot` method) so GitLab / Bitbucket can plug in later without reshaping the verifier. Verifier is pure orchestration — tests inject a stub Provider, no network.
- **Renders into the topology HTML** via a "Live verification" panel (drift table + per-repo snapshot table + unverifiable list), into the JSON output via a `verification` field, and into the text summary via a posture line + per-record breakdown. Panel omitted when `--verify` is off or every check is clean.
- **Test count: 874 → 907 (+33)** — 25 verify tests covering provider mapping, branch-protection 401/404 handling, drift detection across all three kinds, branch-level vs env-level gate routing, repo dedup, unverifiable edges. 8 HTML panel tests covering omission, danger/warning styling, per-repo snapshot table, summary count, HTML escaping.

### Added — Slice 16 session 3 (cross-pipeline scan overlay)

- **`ciguard topology --scan-output <json>`** — pair a `scan-repo` aggregate with the topology to overlay per-environment + per-(service, env) severity chips on the swimlane HTML page. Every cell that maps to a scanned pipeline gets compact severity chips (`1 C`, `2 H`, `1 L` ...); each environment header carries per-environment totals across every pipeline that deploys to that env. Cells with zero findings get a small `clean` marker so the operator can distinguish "scanned and clean" from "no scan data".
- **`ciguard topology --scan-repo <path>`** — convenience flag that runs `scan-repo` internally and feeds the result. Mutually exclusive with `--scan-output`. Errors degrade gracefully: failure to read the scan output / failure of the internal scan-repo prints a warning and renders without the overlay rather than failing the whole operation.
- **Drift panel** added to the topology HTML page — surfaces asserted-vs-actual mismatches: pipelines the topology declares but `scan-repo` didn't find (renames / deletions) AND scanned pipelines that no `DeployEdge` claims (orphan workflows). Both are auditor-relevant. Panel is omitted entirely when the asserted topology and the scanned files are perfectly aligned.
- **New aggregator module** at `src/ciguard/topology/aggregate.py` — pure function `aggregate_scan_into_topology(topology, scan_result) -> dict` returning `{by_env, by_edge, unmatched_pipelines, unmatched_files}`. Composite keys serialise as `"<service>::<env>"` so the result is JSON-clean. `--format json` now embeds this under `scan_aggregate` when an overlay was requested.
- **Test count: 856 → 874 (+18)** — 14 aggregator tests covering per-edge counts, per-env totals, drift detection, shared-pipeline edge cases, empty inputs; plus 8 HTML overlay tests covering severity chip rendering, env-header totals, summary line, clean-cell marker, drift panel presence/absence, backwards-compat with `aggregate=None`.

### Added — Slice 16 session 2 (topology HTML swimlane reporter)

- **`ciguard topology --format html --output topology.html`** — self-contained dark-mode swimlane page rendering the cross-pipeline graph: services × environments grid with promotion-transition arrows showing which gates protect each step, plus secret-scope blast-radius and network-reachability panels. Same visual vocabulary as `inventory_html.py` and `html_interactive.py` so the audit deliverables are coherent. Print-friendly via `@media print`. Pure function in new `src/ciguard/reporter/topology_html.py` — no JavaScript, no dependencies, unit-tested on the rendered string.
- **Layout decisions:** environments order left-to-right by tier (development → test → staging → production); production-tier columns get a red-tinted header so they're always findable; deploys to production with no gates render with a red border + danger-tinted background; gateless promotion transitions render with a red `→` arrow and explicit `no gates` chip in the inter-column transition row.
- **Top-of-page warnings banner** enumerates the auditor's highest-signal red flags: gateless deploys to production-tier environments AND gateless transitions whose `to_env` is production-tier. Operators see the worst posture issues without scrolling. Banner is omitted entirely when there are none — clean topologies stay quiet.
- **Bottom panels:** secret-scope blast radius (which environments + services share each scope?) and network reachability (transitive closure of `can_reach` per segment, marked `isolated` when empty). Both omitted when their underlying entity collection is empty.
- **Why standalone vs embedded** in the per-pipeline visualiser: topology is per-org, the visualiser is per-pipeline. Embedding the same topology page in every pipeline's HTML would duplicate the data N times. Slice 17's org-level audit will combine both into one page.
- **Test count: 836 → 856 (+20)** — `tests/test_topology_html.py` exercises document shape, swimlane ordering + production highlighting, deploy-cell + empty-cell + danger states, transition-row arrow direction, warnings-banner presence/absence, secret + network panels, HTML escaping for operator-supplied evil, and `write_report` directory creation.

### Added — Slice 16 session 1 (topology data model + YAML loader)

- **`ciguard topology` CLI verb** — validates and summarises a `ciguard.topology.yml` file (the cross-pipeline graph: services, environments, deploy edges, promotion gates, secret scopes, network segments). Auto-discovers from cwd upward, same convention as `.ciguardignore`. Text format prints an auditor-focused posture summary (production deploy targets + their gates, gateless promotions called out in yellow, secret-scope blast radius, network reachability per segment); `--format json` emits the full validated `Topology` model for downstream tooling.
- **Topology data model** in `src/ciguard/models/topology.py` — six pydantic entities (`Service`, `Environment`, `DeployEdge`, `EnvTransition`, `SecretScope`, `NetworkSegment`) + `Topology` aggregate root. Cross-reference integrity validated at construction time: a typo in a service id, environment id, or network segment fails loud at load, not at query time.
- **Query helpers** on `Topology` answering the auditor questions named in the audit-scope spec: `pipelines_for_environment(env)`, `services_sharing_secret(scope)`, `transitions_without_gates()`, `reachable_segments(segment)` (transitive closure of `can_reach`), `production_environments()` (matches `prod` / `production` / `live` tiers, case-insensitive).
- **YAML loader** in `src/ciguard/topology/loader.py` — `load(path)` returns a validated `Topology`; `discover(start)` walks up from a directory looking for `ciguard.topology.yml`, stopping at `.git` or filesystem root. Single `TopologyLoadError` wraps every failure mode (missing file, YAML parse error, schema mismatch, cross-reference violation) with the file path prepended so error messages point at the actual `.yml` file.
- **Sample fixture** at `tests/fixtures/topology/sample.topology.yml` — realistic 3-service / 4-environment shape exercising every entity type, including the deliberate `worker → prod` edge with no gates and the `dev → prod` transition with no approval gate so the auditor warnings have something to flag.
- **Test count: 805 → 836 (+31)** — model construction + cross-reference validation + every query helper + every loader error mode + discovery walk semantics.

### Deferred to follow-on Slice 16 sessions

- **Auto-discovery from `scan-repo` output** — derive a partial topology from pipeline files alone, no operator YAML required. Useful first-run experience.
- **Live-API verification** — cross-check the asserted topology against GitHub deployment-environments + branch-protection APIs (and GitLab equivalents) to flag drift between asserted and actual.
- **Visual rendering** — a topology HTML page (probably standalone like the inventory page) showing environment swimlanes, deploy-edge graph, gate annotations, network-segmentation overlays.
- **Cross-pipeline aggregation** — feed a `scan-repo` output into the topology to compute per-environment finding counts.

### Added — Slice 14b (infrastructure inventory — first 3 probes)

- **`ciguard inventory` CLI verb** — live admin-API audit of CI/CD tooling, distinct from the pipeline-file scanning the rest of ciguard does. Reads operator-supplied env vars, calls each tool's admin API for version + edition, cross-references with endoflife.date for EOL/EOS warnings.
- **Three priority probes shipped:**
  - **Jenkins** (`/api/json`) — `CIGUARD_JENKINS_URL` + `_USER` + `_TOKEN`. HTTP Basic auth.
  - **GitLab self-host** (`/api/v4/version`) — `CIGUARD_GITLAB_URL` + `_TOKEN`. `PRIVATE-TOKEN` header. Distinguishes CE vs EE.
  - **GitHub Enterprise** (`/api/v3/meta`) — `CIGUARD_GHE_URL` + `_TOKEN`. Bearer `token` auth.
- **Probe protocol** in `src/ciguard/inventory/probes.py` — `Probe` Protocol + `InventoryRunner` orchestrator + `register()` decorator + shared `http_get_json()` HTTP helper (8s timeout, 5 MB response cap, clear error messages on 401 / 404 / non-JSON / oversize).
- **Auth model** — strict env-var gate. Missing vars → `configured=False`, no network call, silent skip. Configured probe with API failure → `error` field populated, runner never crashes.
- **EOL enrichment** — `enrich_with_eol()` looks up each tool's version against endoflife.date (`jenkins`, `gitlab`, `github-enterprise-server` slugs). Falls back to major.minor matching when patch versions don't have their own cycle entry. Reuses the existing `~/.ciguard/cache/` directory and `--offline` flag.
- **Output formats** — coloured text table by default (`tool`, `version`, `edition`, `status`, `notes`), `--format json` for the full `InventoryReport` model, `--output PATH` to write to file (ANSI codes stripped on file write). `--fail-on {none,approaching-eol,end-of-support,end-of-life,error}` exit-code gate for CI use.
- **Status taxonomy** — five states: `unconfigured` / `ok` / `approaching-eol` (≤180 days) / `end-of-support` / `end-of-life` / `error`. Single source of truth in `InventoryEntry.status`.
- **README "Infrastructure inventory" section** + Network egress table updated to include the operator-supplied admin-API destinations.
- **Test count: 743 → 777 (+34)** — per-probe happy-path + error-mode tests, runner orchestration tests, EOL enrichment tests, registry drift guard, HTTP helper micro-tests covering the size cap + auth header + 401 messaging.

### Added — Slice 14b session 2 (5 incremental probes + standalone HTML)

- **Five remaining probes shipped:**
  - **Sonatype Nexus** (`/service/rest/v1/system/info`, falls back to `/status/check` on 403) — `CIGUARD_NEXUS_URL` + `_USER` + `_PASSWORD`. HTTP Basic. Surfaces `edition` (PRO/OSS) when available.
  - **JFrog Artifactory** (`/api/system/version`, auto-prefixes `/artifactory/` when missing) — `CIGUARD_ARTIFACTORY_URL` + (`_TOKEN` for 7.x **OR** `_USER` + `_PASSWORD` for 6.x). Surfaces `license` as `edition`.
  - **SonarQube** (`/api/server/version`, plain-text response) — `CIGUARD_SONAR_URL` + `_TOKEN`. HTTP Basic with token-as-username (SonarQube convention).
  - **ArgoCD** (`/api/version`) — `CIGUARD_ARGOCD_URL` + `_TOKEN`. Bearer JWT. Strips leading `v` from version (`v2.10.4` → `2.10.4`) so endoflife matching works.
  - **Harbor** (`/api/v2.0/systeminfo`) — `CIGUARD_HARBOR_URL` + `_USER` + `_PASSWORD`. HTTP Basic. Strips `v` prefix AND build hash (`v2.10.1-abc1234` → `2.10.1`).
- **Standalone HTML inventory** — new `ciguard inventory --format html` writes a self-contained dark-mode page with the same visual vocabulary as the pipeline visualiser (chip-style status badges, severity colours, print-friendly via `@media print`). Right shape for the "email this to a client" deliverable. Implementation in new `src/ciguard/reporter/inventory_html.py` — pure function, no JavaScript, no dependencies.
- **Test count: 777 → 805 (+28)** — 17 new probe tests + 11 HTML reporter tests (drift-guard for all 8 probes registering rolled into the existing TestProbeRegistry class).
- **Bug fix during the slice:** Artifactory probe's URL path-detection (`"/artifactory" in base`) wrongly matched `https://artifactory.example` because the `//` substring satisfied the leading `/`. Replaced with a proper `urlsplit().path` check.

### Deferred — `Project ciguard/PROJECT-STATE.md` for current scope

- Plugin inventory for Jenkins (`/pluginManager/api/json?depth=1`) — needs `Overall/Administer` permission; opt-in flag rather than default. Not a blocker for the audit deliverable.

### Added — Slice 15 (MCP hardening)

- **`CIGUARD_MCP_REDACT_LEVEL=full|partial|raw` env var, default `full`.** Every MCP tool response now passes through a per-level redaction layer in `src/ciguard/mcp/redaction.py` before reaching the LLM client. At `full` (default), every finding's `evidence` field is replaced by a stable 8-char SHA-256 fingerprint (`redacted:abc12345`) — LLM still gets actionable rule_id + severity + location + remediation, but the underlying string never crosses the boundary. Absolute paths (`pipeline_name`, `file_path`, `baseline_path`, etc.) collapse to basenames. Response capped at 256 KB. `partial` keeps evidence + rewrites paths relative to `CIGUARD_MCP_ROOT` (1 MB cap). `raw` is full passthrough (10 MB safety cap). Unknown / typo'd values fall back to `full` — fail-safe.
- **MCP audit log at `~/.ciguard/mcp-audit.jsonl`.** Every invocation appends one JSONL record `{ts, tool, redact_level, args, response_bytes, had_error}`. The `args` object is redaction-aware — what the audit log captures matches what the response leaked, no more. Path overridable via `CIGUARD_MCP_AUDIT_PATH`; opt-out via `CIGUARD_MCP_AUDIT_DISABLED=1` (mirrors the `CIGUARD_MCP_DISABLED` truthy convention). Audit failures never poison the response — best-effort with stderr-only error logging.
- **README "What ciguard MCP can see" section** — explicit per-tool exposure table at every redaction level. The disclosure table is the user-facing contract; if a future tool is added, this table is the first thing that updates.
- **Threat model Surface 10 (MCP-mediated data exfiltration)** added to `Project ciguard/THREAT_MODEL.md` with 7 STRIDE rows + DREAD scoring + new trust-boundary edges. Three CYCLE-1.5 self-pentest PoC checks lined up: default-level resolution, level-cannot-be-downgraded-by-tool-arg, audit-log written even on mid-response crash.
- **`tests/conftest.py`** — autouse fixture redirects MCP audit log to a per-test tempfile so test runs don't accumulate records in `~/.ciguard/`.

### Added — Slice 14c (pin-discipline rule emitters)

- **`SCA-PIN-002` — Image Uses Mutable Tag** (High). Cross-platform supply-chain rule. Fires for image references using a mutable tag name (`:latest`, `:stable`, `:edge`, `:prod`, `:production`, `:main`, `:master`, `:dev`, `:development`, `:nightly`) or no tag at all (Docker resolves bare names to `:latest`). Severity High by default — this is the OWASP CICD-SEC-3 / tj-actions-changed-files-style attack surface. Standards mapping: SLSA Level 2+, NIST SSDF PW.4.1, CIS Docker 4.7. Intentionally overlaps with the per-platform `PIPE-001` / `GHA-PIPE-001` / `JKN-PIPE-001` `:latest` checks — same surface, two perspectives (platform-rule + cross-platform supply-chain). Operators who find the duplicate noisy can `.ciguardignore` either side.
- **`SCA-PIN-004` — Helm Chart Pulled Without Pinned Version** (Medium). Cross-platform script-content rule. Fires for `helm install` / `helm upgrade` / `helm pull` invocations inside any job script that lack a `--version` flag, or where `--version` is set to a mutable label (`latest`, `stable`, `main`, `master`, `dev`, `*`). `helm template` and `helm upgrade --reuse-values` are skipped — they're legitimate version-not-required patterns. Standards mapping: OWASP CICD-SEC-3, PCI DSS 4.0 Req 6.3.

### Deferred

- `SCA-PIN-003` (cross-pipeline drift detection) was scoped in Slice 14c but requires aggregating image references across multiple pipeline files in a single scan — that lives in `repo_scan.py`, not the per-pipeline rule contract. Will land alongside cross-pipeline aggregation plumbing in a follow-up.

### Added — Slice 10 (ciguard.dev landing page — two sessions)

#### Session 1 — landing page MVP

- **Astro 6.x static landing page** for ciguard.dev. Output is plain HTML/CSS in `dist/` — no client-side JS, no analytics, no runtime, no telemetry. Cloudflare Pages serves the built directory directly.
- **Page structure** (single `index.astro`): hero with brand mark + dual CTA (docs + GitHub); "What it produces" four cards (pipeline visualiser, infra inventory, multi-env topology, org-level dashboard); capability snapshot — 6 stats + 8 CLI verbs grid; "How it ships" four install tiles (PyPI, PyPI[mcp], GHCR, pre-commit); supply-chain provenance row (Sigstore, SBOM attestations, public Cycle 1 report); final CTA strip + footer.
- **Visual coherence:** same dark-mode palette + typography as the in-app HTML deliverables (`html_interactive.py`, `topology_html.py`, `inventory_html.py`, `org_audit_html.py`) so the brand reads as one family across the marketing surface and the audit artifacts. Brand mark `CIGuard` (uppercase G with sky→indigo gradient) for the wordmark; identifier `ciguard` for code paths.
- **Self-contained:** no external scripts, no fonts, no analytics. CSP in `public/_headers` reflects that — `default-src 'self'`, plus a documented `'unsafe-inline'` exception on `style-src` because Astro inlines per-component styles (LANDING-003, accepted architectural).

#### Session 2 — Cloudflare Pages auto-deploy

- **`.github/workflows/landing-deploy.yml`** — checkout → setup-node@22 → npm ci → npm run build → verify dist/index.html present → wrangler-action pages deploy. SHA-pinned actions: `actions/checkout v6.0.2`, `actions/setup-node v6.4.0`, `cloudflare/wrangler-action v3.15.0`. Concurrency group `landing-deploy` (last-push-wins). `paths-filter` scoped to `landing/**` so engine commits don't trigger marketing redeploys.
- **Permissions trimmed** to `contents: read` + `deployments: write` (the Pages deployment record). Repo secrets: `CLOUDFLARE_API_TOKEN` (Pages:Edit + Zone:DNS:Edit, restricted to ciguard.dev) + `CLOUDFLARE_ACCOUNT_ID`. Scoped token rather than global API key matches the v0.9.1 deployment-hardening posture (least-privilege, revocable independently if leaked).
- **`landing/wrangler.jsonc`** — Pages config as code: project name `ciguard`, output dir `./dist`, `compatibility_date 2026-05-02`. Build-settings changes go through PR review rather than dashboard hunting.
- **`landing/README.md` rewritten "Deploy" section** — explicit 6-step cutover bootstrap (mint scoped Cloudflare API token → add 2 repo secrets → click "Add custom domain"). Workflow is dormant until secrets are present, so the commit doesn't change any external state on its own.
- **Workflow does NOT gate** the engine's required status checks. CI / CodeQL / Dogfood / Code Scanning gate are unaffected by changes under `landing/**`.

### Fixed — Slice 10 follow-up

- **Brand mark applied to all six prose mentions** — header, hero lede, supply-chain provenance paragraph, final CTA, footer mark, footer copyright line (`© 2026 CIGuard contributors`). CSS adjustment: `.brand-mark` no longer hardcodes 20px so inline prose mentions inherit surrounding font size; header keeps the larger 20px via `.brand .brand-mark` scoped rule, footer keeps its existing `.footer-mark` 18px override.
- **LANDING-001 — 404 page + robots.txt + sitemap.xml.** Layer-1 pentest of the deployed site (close-out at `Project ciguard/Pentest Reports/2026-05-02-landing-page.md`) flagged that all unknown paths returned HTTP 200 with the homepage body — Cloudflare Pages was doing SPA-style fallback because `dist/` had no `404.html`. Symptoms: search-engine duplicate content, masked recon probes (`/admin`, `/.git`, `/.env` all returning 200), confused operators on mistyped URLs. Three artifacts added: `src/pages/404.astro` (Astro auto-generates `dist/404.html`, served with real HTTP 404 when no other route matches; reuses Base layout so brand + headers stay consistent), `public/robots.txt` (explicit `User-agent: * / Allow: /` plus a `Sitemap:` pointer), `public/sitemap.xml` (single-URL sitemap). Mozilla Observatory grade unchanged at A+ (10/10, score 120) — this commit closes the recon-surface gap that Observatory's rubric doesn't measure but auditors do. LANDING-002 (CAA) remediated separately below; LANDING-003 (CSP `'unsafe-inline'` on style-src) accepted as Astro architectural.
- **LANDING-002 — Cloudflare DNS-hardening helper** at `scripts/cloudflare_setup_ciguard_dev.sh`. One-shot, idempotent helper: adds CAA records pinning cert issuance to Google Trust Services + Let's Encrypt + DigiCert (matching Cloudflare Pages's auto-provisioner) plus an `iodef` reporting channel; optional `--enable-dnssec` toggle for the natural follow-on (closes the "hijack DNS, remove CAA, then issue rogue cert" path that CAA alone leaves open). Re-running detects existing matching records and skips, so it's safe in CI / cron / on-call runbooks. Looks up zone id by name (survives zone recreation). `--dry-run` for safe preview before committing changes. The script does NOT publish the DNSSEC DS record at the registrar — it prints the DS string + a deeplink to the Cloudflare registrar panel where you paste it (one-click since registrar = Cloudflare).
- **pyjq tokeniser fix** in `scripts/cloudflare_setup_ciguard_dev.sh`. The pyjq helper was splitting the path expression on `|` only, never on `.` — so `.result.expires_on` was looked up as a single key `'result.expires_on'` on the response object instead of `result` then `expires_on`. The zone-resolve path `.result.[].id` happened to coincide with the correct token sequence by accident; `.result.expires_on` (and any other purely-dotted path) silently returned `{}`. Fix: tokenise into a flat list where `[]` is its own item and every other piece is dot-split. Verified end-to-end with a real run on ciguard.dev — 4 CAA records added, public DNS confirms via 1.1.1.1 + 8.8.8.8, idempotent re-run shows ✓ already present for all four.

### Maintenance

- **378 pytest DeprecationWarning hits → 0.** Three sites switched from `datetime.utcnow()` to `datetime.now(tz=timezone.utc)`: `models/pipeline.py` (`Report.scan_timestamp`), `models/inventory.py` (`InventoryReport.scan_timestamp`), `reporter/pdf_report.py` (PDF footer). Format shifts from `2026-05-02T13:00:00` to `2026-05-02T13:00:00+00:00` — functionally identical; downstream consumers slice `[:19]` / `[:10]` for display so rendered output is unchanged.
- **Code-scanning quality alerts swept:**
  - **#30** (py/unused-local-variable, `test_app_scheduler.py:86`) — real bug: the `_inner()` async test body was defined but never invoked via `_run(_inner)`. Test was passing vacuously. Added the missing call; assertions actually run now (and pass — the underlying fix from `1f65836` was correct).
  - **#32 + #33** (py/unused-global-variable, `html_interactive.py:90, 97`) — vestigial `_SEVERITY_COLOURS` / `_NEUTRAL_BORDER` constants from an early Slice 14a draft; the palette was inlined into `_VIEWER_CSS` once the visual language stabilised.
  - **#35** (py/repeated-import, `html_interactive.py:1582`) — local `import re as _re` shadowing the module-level alias.
  - **#40** (py/ineffectual-statement, `inventory/probes.py:49`) dismissed in-API as documented false positive — `...` is the canonical PEP 544 Protocol-stub idiom.
- **ruff F401/F841/E402 cleared, CI lint green.** 8 × F401 unused imports, 1 × F841 unused local in `sca_rules.py`, 1 × E402 import-not-at-top in `reporter/html_interactive.py`. Local pytest had been passing because lint isn't in the local test loop; CI's `checks/lint` step had been failing on every push since Slice 14b session 1.
- **CodeQL py/bad-tag-filter regex tightening** (alerts #31 + #50). `test_no_external_script_references_in_html` matcher made case-insensitive (defensive — we ship lowercase, spec allows uppercase). `</script>` close-tag matcher broadened from `</script\s*>` to `</script[^>]*>` (matches HTML5-spec close tags carrying garbage attributes — `\s*` doesn't). Two CodeQL alerts dismissed in-API as documented false positives (#47, #48): both flag `secret_scopes` as "sensitive data" but the field carries operator-supplied LABELS for groups of secrets, never credential values.

### Documentation

- Rule numbering convention ratified in the audit-scope memory: ciguard rule IDs follow the `<FAMILY>-<SUBFAMILY>-<NNN>` flat-counter pattern (Pattern 2 — Checkov / Bandit style). Severity, sub-classification, and standards mappings live in metadata fields on the `Finding` object, not encoded in the ID. Earlier audit-scope spec had `SCA-PIN-001` = mutable tag (High); corrected to keep the existing v0.6.0 digest rule at `SCA-PIN-001` and add the new mutable-tag rule at the next free number.

## [0.10.0] — 2026-04-30

**GitHub App — receiver wired, threat-modelled, ready for self-pentest.** ciguard now ships a FastAPI webhook receiver that scans PRs and posts results back as Check Runs + PR comments. Six build steps shipped over two days; 11 of 13 Surface 9 STRIDE rows closed in code (the other 2 close architecturally — no OAuth callback in the manifest install flow, manifest scope is the minimal permission set). The actual scan-against-real-repo execution is stubbed in this release; v0.10.1 will wire the clone-and-scan path. The stub posts an honest "scan execution lands in v0.10.1" notice on every Check Run so deployers can verify wiring end-to-end without being misled into thinking they're getting fake findings.

### Threat model written first

[`Project ciguard/THREAT_MODEL.md`](https://github.com/Jo-Jo98/ciguard/blob/main/Project%20ciguard/THREAT_MODEL.md) Surface 9 was drafted ahead of any App code (per Pentest Plan recommendation #2). 13 STRIDE rows covering webhook signature bypass, IDOR on installation_id, multi-tenant baseline bleed, webhook replay, payload DoS, PR-comment markdown injection, token leakage, App private key exposure, OAuth callback CSRF, Check Run state confusion, concurrent webhook race, manifest over-scope, post-revocation cached token. Five up-front design commitments locked the architecture before code: HMAC fail-closed, JWT broker isolation, sync-ack/async-scan, per-install storage namespace, minimal manifest.

### What shipped (`src/ciguard/app/`, ~1,300 LOC + ~1,650 LOC tests)

- **`webhook.py`** — HMAC-SHA256 over raw body, `hmac.compare_digest`, fail-closed 401 on every failure mode. X-GitHub-Delivery dedup against a 1h TTL cache. 25 MB body cap. 202 ack within milliseconds. CR/LF-stripped log values defeat log-injection.
- **`tokens.py`** — JWT signing isolated to `_mint_jwt()` (RS256, 9-min lifetime, `iat` backdated 30s for clock skew). Per-installation token cache, 30-min TTL (half of GitHub's 1h default). Logger emits `ghs_a3df…` prefixes only — never full tokens, JWTs, or private keys. 401 from any GitHub API call invalidates the cached token.
- **`scheduler.py`** — Async scan scheduler. Idempotency key `(installation_id, head_sha)` collapses duplicate same-SHA deliveries. Per-`(installation_id, repo)` `asyncio.Lock` serialises baseline writes (different repos run in parallel). Bounded queue (128) + bounded worker pool (2 default). Queue overflow surfaces as 503 backpressure.
- **`checks.py`** — GitHub REST helpers + markdown sanitisers. Evidence wrapped in 4-backtick fences with backtick-run neutralisation; inline values backslash-escape markdown specials and HTML-encode `<>`. PR comment upsert via hidden `<!-- ciguard:pr-marker:v1 -->` HTML-comment marker so retries / concurrent events don't stack duplicates. 401 → token invalidate contract.
- **`scan_runner.py`** — `run_scan()` orchestrator: create `in_progress` Check Run → execute → finalize. Every exception path routes through `set_check_run_failed()`; the Check Run never remains `in_progress` after a crash and never silently flips to `success`. Tested with five exception shapes (executor raises, complete raises, comment-post raises, set_failed itself fails, malformed repo).
- **`storage.py`** — Per-installation storage namespacing. Every read/write requires `verified_installation_id: int` keyword-only — positional / string / `bool` / zero / negative all reject. Storage layout `<storage_root>/<installation_id>/<owner>/<repo>/baseline.json`. Atomic write-via-tempfile-rename. Path traversal in repo names rejected via regex + defensive `..` reject + resolved-path-under-root assert.
- **`factory.py`** — FastAPI app factory + lifespan that wires `ScanScheduler` to `app.state` on startup, drains on shutdown. Stub `_stub_scan_executor` for v0.10.0; real executor injection point ready for v0.10.1.
- **`ciguard app` CLI subcommand** — uvicorn launcher with pre-flight env-var check (refuses to start if `CIGUARD_APP_WEBHOOK_SECRET` / `CIGUARD_APP_ID` / private-key env are missing). Yellow warning when binding non-loopback. Same shape as `ciguard mcp` and `ciguard web`.
- **`deploy/app/manifest.yml`** — Reviewable App registration manifest. Exact permission set: `Actions: read`, `Contents: read`, `Pull requests: write`, `Checks: write`, `Metadata: read`. No org / admin / repo-write outside the comment surface. Any expansion is a manifest-diff review.
- **`README.md`** — New "Running the GitHub App" section: install via `pip install 'ciguard[app]'`, manifest registration walkthrough, env config, security-posture summary.

### Test count progression

502 (v0.9.4 baseline) → 621 (+119 across 7 new test files in `tests/test_app_*.py`). Every test docstring names the Surface 9 STRIDE row(s) it covers.

### Pentest cadence

Cycle 2's regular cadence (2026-10-15) is too late to gate the App's first public install. **CYCLE-1.5 self-pentest** runs against the App in the lab before the install link is shared more broadly: scope = the 13 Surface 9 threats; method = same Cycle 1 methodology compressed for narrow scope; lab = ephemeral DigitalOcean droplet via `pentest-lab/` Terraform; report at `Project ciguard/Pentest Reports/<date>-cycle-1.5.md`. External pentest stays an aspirational option, not a sequencing precondition.

### What's next (v0.10.1)

The real scan executor: clone the repo via `git clone https://x-access-token:<installation-token>@github.com/...`, run `ciguard scan-repo` against the local checkout, render results into the Check Run + PR comment. Plumbing work, not architecture — the threat model + framework are stable.

## [0.9.4] — 2026-04-29

**Drop-in CI templates — Slice 9 carve-out.** Pre-built workflow files for the three supported platforms (GitHub Actions, GitLab CI, Jenkins) so users can wire ciguard into their CI in one paste. No Python source changes; this release is templates-only.

### Added

- **`templates/github-actions/ciguard-scan.yml`** — minimal scan + JSON artifact, informational. Zero-config first run.
- **`templates/github-actions/ciguard-scan-baseline.yml`** — full v0.5 baseline workflow showcase. Diffs against `.ciguard/baseline.json`, fails on new High+, uploads SARIF to GitHub Code Scanning.
- **`templates/github-actions/ciguard-scan-repo.yml`** — monorepo template. Auto-discovers every recognised pipeline file under the repo root via the v0.9.0 `scan-repo` verb.
- **`templates/gitlab-ci/ciguard.gitlab-ci.yml`** — GitLab CI job snippet. Drop into `.gitlab-ci.yml` or pull via `include:` from a remote URL. `CIGUARD_OFFLINE=1` CI variable for air-gapped runners.
- **`templates/jenkins/Jenkinsfile.ciguard`** — Jenkins declarative pipeline stage running ciguard via the official multi-arch GHCR image. No Python toolchain needed on the agent.
- **README "Drop-in CI templates" section** — table linking all five templates with the right "use case" framing.
- **`tests/test_templates.py` (22 tests)** — guards templates against drift. YAML validity, GitHub Actions SHA-pinning (dogfoods our own GHA-IAM-006 rule), pinned-version sync with `pyproject.toml`, ciguard-flag round-trip via subprocess against the real CLI.

### Why templates first (and not the GitHub App)

Slice 9 has two halves: reusable templates and the GitHub App. Templates are zero-attack-surface — just YAML users copy into their own repos — and they directly answer the "removing the upload friction" question raised in the original PRD. Shipping them now gets adoption signal flowing while the App is built secure-by-default in v0.10.0 (threat model, OAuth + webhook signature handling, mini self-pentest sub-cycle before public install link goes live).

### Notes for users upgrading templates

All templates pin `ciguard==0.9.4` (or the GHCR image at `v0.9.4`). When you upgrade your installation, bump the pin in your copy of the template too — the version pin is intentional, not a lazy default.

## [0.9.3] — 2026-04-28

**Supply-chain attestation — closes issue #14.** From this release onwards every container image is **Sigstore-signed (keyless)** and carries **CycloneDX + SPDX SBOM attestations**; every PyPI distribution carries **PEP 740 attestations**. No long-lived signing keys; no separate key-management surface.

> **Note on v0.9.2 — TAGGED BUT NEVER PUBLISHED.** v0.9.2 was the first attempt at this slice and shipped only partially: the cosign sign step succeeded (the GHCR image at the v0.9.2 SHA digest was correctly signed), but the SBOM-attestation step failed because `mkdir -p sbom` was missing from the new `attest` job. Concurrently, the PyPI publish job stalled on the `pypi` GitHub environment's `required_reviewers` rule (auto-cleared on previous releases for unclear reasons; this run actually blocked). Tag deleted from remote + local; v0.9.3 is the first successful release of this slice. Same pattern as v0.8.0 → v0.8.1.

### Added

- **Sigstore keyless image signing.** New `attest` job in `release.yml` runs cosign against the multi-arch GHCR image after publish. Signs by **digest** (immutable bytes) rather than tag (mutable) — a re-pushed `:vX.Y.Z` cannot replay a previous signature. Identity = the workflow that ran (`Jo-Jo98/ciguard/.github/workflows/release.yml@refs/tags/v0.9.2`); short-lived cert issued by Sigstore Fulcio over GitHub Actions OIDC; signature + cert recorded in [Sigstore's Rekor public transparency log](https://search.sigstore.dev/).
- **CycloneDX + SPDX SBOMs** as cosign attestations on the image. Generated by [syft](https://github.com/anchore/syft) (via `anchore/sbom-action`) against the actual built layers — high-fidelity package / version / license manifests. Both formats because consumers vary: CycloneDX is what most SAST / SCA tooling speaks; SPDX is what regulators (US EO 14028, ISO/IEC 5962) ask for. Producing both costs ~10 s and avoids future format conversion.
- **Python-package CycloneDX SBOM** (via `CycloneDX/gh-python-generate-sbom`) generated from `requirements.txt` during the PyPI publish job. Uploaded as a workflow artifact (`sbom-python-cyclonedx`, 90-day retention).
- **PEP 740 PyPI attestations.** Bumped `pypa/gh-action-pypi-publish` to v1.14.0 — every wheel + sdist now ships a Sigstore-signed PEP 740 attestation, visible at https://pypi.org/project/ciguard/#files. Verifies the distribution was built by *this* workflow, not republished by a compromised maintainer account.
- **SLSA build provenance** via `docker/build-push-action`'s `provenance: true` + `sbom: true` parameters. Adds in-toto SLSA provenance + a buildkit-generated SBOM as image attestations alongside the cosign signature — defence-in-depth from a different angle (build-tool-attested vs. workflow-attested).
- **README "Verifying releases (Sigstore + SBOMs)" section** — copy-paste recipe for `cosign verify` + `cosign verify-attestation` (CycloneDX + SPDX), plus what each layer protects against. The 3-line cosign verify command is the headline: anyone consuming ciguard can prove cryptographically that the image they pulled was built by *this* workflow at *this* tag.

### Internals

- New `attest` job depends on `ghcr` (image build) + reads its `digest` output; `trivy` continues to depend on `ghcr` only (independent — runs in parallel with `attest`). Adds ~2 min to the release flow; releases are rare; the cost is justified by the verifiability gain.
- The `pypi` job's SBOM is written to `sbom/` (not `dist/`) — anything in `dist/` gets uploaded by `gh-action-pypi-publish` as a release distribution and would break PyPI publishing on first run.

### Why this matters strategically

ciguard's narrative is "static security auditor for CI/CD pipelines." From this release, ciguard signs and SBOMs its own releases — and a future ciguard rule will flag pipelines pushing to a registry without doing the same (issue #14's optional follow-up: "eats own dogfood"). Worth its own ship event + blog post.

## [0.9.1] — 2026-04-28

**Deployment hardening — five small fixes from the external LLM-assisted code review.** The static analyser core was already in good shape; the surfaces around it that activate when people *deploy* ciguard (web UI, MCP server, LLM enrichment, container base, scanner egress) are the gap this slice closes. All five tracked in the v0.8.4 milestone (issues #9–#13); shipped as v0.9.1 since v0.9.0 already shipped earlier today.

### Added

- **`CIGUARD_WEB_TOKEN` bearer-token auth on the web API (issue #9).** New `src/ciguard/web/auth.py`. Default behaviour unchanged — auth is opt-in via the env var, so the local-dev path stays frictionless. When set, every `/api/scan`, `/api/report/*`, and `/report/*` request requires `Authorization: Bearer <token>`; constant-time compare prevents timing-recovery. `/api/health` is deliberately ungated (k8s probes / load balancers). `python -m ciguard.web.app` prints a yellow startup warning when binding to a non-loopback host without a token.
- **`CIGUARD_MCP_ROOT` workspace allowlist on MCP scan tools (issue #10).** Defence-in-depth on Cycle 1's CYCLE-1-001 ([GHSA-8cxw-cc62-q28v](https://github.com/Jo-Jo98/ciguard/security/advisories/GHSA-8cxw-cc62-q28v)) — the symlink fix prevented escape *within* the scan root; this prevents the scan root itself being attacker-influenced via an adversarial MCP-client prompt ("scan /etc/...", "scan ~/.aws/..."). When set, `_tool_scan` / `_tool_scan_repo` / `_tool_diff_baseline` refuse paths outside the allowlist (after `expanduser` + `resolve` to collapse `..` traversal). Default: no restriction (preserves v0.8.x behaviour).
- **`--no-scanners` CLI flag + `CIGUARD_NO_SCANNERS` env var (issue #13).** Master kill-switch for external-binary scanner integrations (Semgrep, OpenSSF Scorecard, GitLab native). `run_all_scanners()` short-circuits to an empty list when set. Pair with `--offline` for fully hardened, network-free runs:
  ```bash
  ciguard scan-repo . --offline --no-scanners
  ```
  Available on both `scan` and `scan-repo` subcommands.
- **`--llm-consent` consent gate + `--redact-locations` privacy mode (issue #12).** `--llm` without `--llm-consent` now refuses to call the LLM and prints exactly what would be sent (rule names, locations, descriptions, compliance mappings — evidence is still always stripped). `--redact-locations` hashes finding locations + pipeline name to stable 8-char SHA-256 prefixes (`redacted:abc12345`) before send; insights stay rule-level actionable but the LLM never sees customer file paths.
- **README "Network egress" section** enumerating every outbound call ciguard can make (OSV.dev, endoflife.date, Anthropic / OpenAI, Semgrep registry, Scorecard) with the disable-flag for each.

### Changed

- **Docker base `python:3.14-slim` → `python:3.13-slim` (issue #11).** Stability + reproducibility — 3.13 has mainstream wheel availability across all our deps. CI matrix never included 3.14 anyway, so the Docker image was the only place 3.14 actually ran. CYCLE-1-002 PoC re-runs against the new image confirm `USER ciguard` (uid=999) is preserved.

### Internals

- 21 new tests in `tests/test_deployment_hardening.py` covering all four env-var/flag surfaces plus the LLM redaction + consent gate (459 → **480 passing**).
- `src/ciguard/scanners/runner.py` gains `_scanners_disabled()` + a docstring section explaining the env var. No behaviour change when the var is unset.
- `src/ciguard/llm/enricher.py` adds `redact_locations` parameter to `enrich_report()` + helper `_redact()` (stable SHA-256 prefix). `_sanitise_finding()` already stripped evidence; redaction is opt-in on top of that.
- `src/ciguard/mcp/server.py` adds `_enforce_workspace()` helper called at every path-accepting tool entrypoint. Reads `CIGUARD_MCP_ROOT` per-call (no module-level caching) so tests can monkey-patch.

### Why this design

- **Env vars over config files** — every operator already has a path to set env vars (k8s Secret env, systemd `Environment=`, container `--env`, MDM, shell profile). The whole policy surface for these flags is on/off (web auth) or a single path (MCP root) or boolean (no-scanners) — a config file's loader/precedence/schema machinery would be unjustified weight.
- **Default-off for all gates.** Existing users see no behaviour change. The hardening lights up the moment the operator opts in. Matches the `CIGUARD_MCP_DISABLED` precedent set in v0.8.x.
- **`--llm-consent` is hard-required, not a warning.** A warning users skim past is not a privacy boundary. An exit-1 with the explainer printed once changes that — the user has to type the flag to send anything.
- **Redaction stops at locations.** Rule names / severities / compliance mappings are tool metadata; they don't reveal customer pipeline structure. Hashing them would make insights useless. The threat model is "LLM operator could see my file paths and infer my project structure," not "LLM operator could see what rules ciguard has."

## [0.9.0] — 2026-04-28

**Slice 9 carve-out — `ciguard scan-repo` CLI subcommand.** Discovery foundation shipped with v0.8.x for the MCP `scan_repo` tool; this slice exposes it as a first-class CLI verb. Scans every recognised pipeline file under a directory, prints a per-file table + aggregate severity counts, and exits non-zero when `--fail-on=<severity>` is breached.

### Added

- **`ciguard scan-repo <path>` subcommand.** Auto-discovers `.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile` / `*.jenkinsfile`, and `*.groovy` files containing pipeline markers, then scans each with the platform-appropriate parser. Terminal output is a path / platform / grade / findings table followed by an aggregate severity breakdown. Designed for monorepo CI: drop one job in your pipeline that scans the whole tree.
  - `--fail-on Critical|High|Medium|Low|Info|none` — gate the build on aggregate severity. Default `none` makes the command informational (exit 0 unless an error occurred).
  - `--output PATH` — write the aggregate JSON (per-file summaries + totals + by-severity counts) for downstream tooling.
  - `--offline` — disable SCA HTTP lookups (endoflife.date / OSV.dev). Required for air-gapped runners.
  - `--no-ignore-file` — skip `.ciguardignore` discovery and processing across every file in the walk.
- **`src/ciguard/repo_scan.py`** — shared helper module containing `scan_repo()` and `scan_one()`. Both the CLI subcommand and the existing MCP `ciguard.scan_repo` tool delegate to it, so behaviour stays in lock-step.

### Internals

- 12 new tests in `tests/test_repo_scan.py` covering the helper's threshold logic + the CLI's exit codes, JSON output, missing-path handling, and empty-repo case (447 → **459 passing**).
- `_tool_scan_repo` in `src/ciguard/mcp/server.py` collapsed from ~50 lines to a 6-line delegation; `_scan_one` and the platform detection logic moved out of the MCP module since they were never MCP-specific. No behavioural change to MCP clients.

### Why this design

- A single CLI verb was the smallest, highest-leverage piece of Slice 9 to ship first. The remaining Slice 9 work (GitHub App + reusable CI workflow templates) is sequenced after this lands so users have something to invoke from those templates.
- The `repo_scan.py` extraction was opportunistic — the MCP tool already had the right shape; lifting it out costs nothing and keeps the two callers from drifting.
- `--fail-on` defaults to `none` rather than `High`. Users adopting `scan-repo` for the first time should see findings before being broken on them; the threshold is opt-in via CI config.

## [0.8.3] — 2026-04-27

**Cycle 1 follow-up — CI regression coverage + weekly fuzz cron.** No code changes to `src/ciguard/`; this release wires the four Cycle 1 PoC scripts in as permanent CI regression gates and adds the weekly atheris fuzz schedule, both recommended in the Cycle 1 final report.

### Added

- **`tests/regression/cycle1/`** — the four Cycle 1 PoC scripts copied in as live regression tests (CYCLE-1-001 symlink escape, -002 container as root, -003 SCA unbounded read, -004 missing security headers). Each script's exit code encodes outcome: `0 = EXPLOIT_CONFIRMED` (regression), `1 = EXPLOIT_FAILED` (fix in place). The vault retains the originals as historical Cycle 1 engagement artefacts.
- **`regression-cycle1` job in `_checks.yml`** — runs all four PoCs on every push/PR via CI, and on every release tag via Release. Inverts each script's exit code so the build fails only when a regression appears. The container PoC builds the image locally first so the gate fires before publish, not after.
- **`.github/workflows/atheris-fuzz.yml`** — weekly cron (Sunday 06:00 UTC) running 1M-iteration coverage-guided fuzz across the three parsers (`GitLabCIParser`, `GitHubActionsParser`, `JenkinsfileParser`). Per-input timeout 10 s, total budget 30 min. Crash → uploads the crashing input as a 30-day artifact + opens an issue tagged `security` + `fuzz-finding`. Manual `workflow_dispatch` accepts a custom iteration count.
- **`tests/fuzz/fuzz_parsers.py`** — atheris harness dispatching a single `FuzzedDataProvider` stream into one of the three parsers.
- **`fuzz` extra in `pyproject.toml`** — `pip install -e ".[fuzz]"` adds atheris (kept optional so the base install stays lean).

### Internals

- Test count unchanged at 447 (regression PoCs are wired as workflow steps, not pytest tests — each is a self-contained shell script with explicit exit-code semantics, deliberately mirroring how the original engagement reproduced them).
- Cycle 1 final report Recommendations #2 + #3 are now closed.
- **Node 24 action upgrades ahead of June 2026 deprecation.** Bumped `actions/checkout` v4 → v6.0.2 and `actions/setup-python` v5 → v6.2.0 in the bandit + pip-audit jobs (they had lagged behind the test/lint jobs which were already on v6). Bumped `actions/upload-artifact` v4.6.0 → v7.0.1 and `actions/github-script` v7.0.1 → v9.0.0 in the new atheris-fuzz workflow. Bumped `docker/setup-qemu-action` v3 → v4.0.0 in release.yml. All other action pins were already on Node 24-capable versions. SHA pins updated; semver comments preserved.

## [0.8.2] — 2026-04-27

**Security hotfix.** Closes the four findings from ciguard's first self-conducted penetration test cycle (Cycle 1, 2026-04-26 → 2026-05-12). Methodology: PTES + OWASP TG v4.2 + CREST report framing. No Critical or High findings; all four below are Low/Medium. Public advisories will be filed as private GitHub Security Advisories at the time of fix-ship and disclosed 14 days after.

### Fixed

- **CYCLE-1-001 (Medium, CVSS 5.7, CWE-59) — `discover_pipeline_files` followed symlinks out of scan root.** An attacker who can plant a symlink in a directory the user (or AI agent via the `mcp.scan_repo` tool) scans could cause discovery to walk into the symlink target. Realistic threat: MCP confused-deputy via adversarial repo clone fed to AI agent. Fix at `src/ciguard/discovery.py`: new `follow_symlinks: bool = False` parameter (the new default refuses to descend into symlinked directories OR symlinked files); belt-and-braces filter that drops any result whose `.resolve()` lies outside the scan root, applied even when callers opt in to `follow_symlinks=True`. Three new tests in `tests/test_discovery.py::TestSymlinkSafety`.

- **CYCLE-1-002 (Low, CVSS 3.4, CWE-269) — Container image ran as root.** The published `ghcr.io/jo-jo98/ciguard` image inherited the default root user (no explicit `USER` directive). Defence-in-depth gap if any future container-runtime escape CVE landed. Fix in `Dockerfile`: create a `ciguard` system user, `chown` writable mount points, switch to `USER ciguard` before `CMD`. Port 8080 still works (>1024). Trivy DS-0002 misconfig clears.

- **CYCLE-1-003 (Low, CVSS 3.1, CWE-770) — SCA HTTP client read response bodies unbounded.** Both `src/ciguard/analyzer/sca/osv.py` and `src/ciguard/analyzer/sca/endoflife.py` called `resp.read()` with no size cap. A hostile or successfully MITM'd OSV.dev / endoflife.date could return a multi-GB body and OOM-kill ciguard. Fix: new `MAX_RESPONSE_BYTES = 5 * 1024 * 1024` constant in both modules; `resp.read(MAX_RESPONSE_BYTES + 1)` with overflow check returns `None` (caller falls back to stale cache). Three new tests in `tests/test_sca_rules.py::TestSCAResponseSizeCap`.

- **CYCLE-1-004 (Low, CVSS 4.3, CWE-693) — Web UI missing HTTP defence-in-depth headers.** OWASP ZAP baseline scan flagged 11 alerts: missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP. Defence-in-depth gap; would matter the moment anyone hosts ciguard publicly. Fix: new `SecurityHeadersMiddleware` at `src/ciguard/web/security_headers.py`, registered in `app.py`. Per-path CSP carve-out for `/api/docs` and `/api/redoc` (Swagger UI / ReDoc load assets from cdn.jsdelivr.net). Six new tests in `tests/test_web.py::TestSecurityHeaders`.

### Internals

- 12 new tests added (435 → **444 passing**) covering all four fixes.
- All four [Phase 4 PoC scripts](https://github.com/Jo-Jo98/ciguard) (committed as part of the cycle's vault docs) re-run after this release should flip from `EXPLOIT CONFIRMED` to `EXPLOIT FAILED`.
- Methodology + findings docs live at `Project ciguard/Pentest Reports/2026-05-12-cycle-1.md` (vault) — full CREST-style report.

## [0.8.1] — 2026-04-26

**CI hotfix for v0.8.0.** v0.8.0 was tagged but never published — the test job in `_checks.yml` ran without the `[mcp]` extra installed, so two MCP-SDK-dependent tests (`test_all_five_tools_registered`, `test_build_server_returns_server_instance`) failed across all four Python versions. The release workflow's `needs: checks` gate correctly blocked PyPI + GHCR publish jobs (the v0.7.0 hardening is doing its job). v0.8.1 is the first successful release of the MCP slice.

### Fixed
- `_checks.yml` test job now installs `pip install -e ".[dev,mcp]"` so the MCP SDK (`mcp>=1.0`) is available when running the test suite.
- `tests/test_mcp_server.py` SDK-dependent tests are now decorated with `@pytest.mark.skipif(not _MCP_AVAILABLE, ...)`. Defensive: tests still pass cleanly when a user runs the suite without the `[mcp]` extra installed; only the dispatch tests run, the SDK ones skip with a clear reason.

Everything else is exactly the v0.8.0 scope (below).

## [0.8.0] — 2026-04-26 — TAGGED BUT NEVER PUBLISHED (see v0.8.1 above)

**Strategic differentiator release.** ciguard now ships a Model Context Protocol server, exposing its scanning capabilities as tools any AI client (Claude Desktop, Claude Code, Cursor, VS Code MCP extensions) can invoke. First-mover positioning while the AI-native devsecops space is empty.

### Added
- **MCP server (`pip install 'ciguard[mcp]'`)** at `src/ciguard/mcp/server.py`. Stdio transport (the standard for local MCP servers). Five tools registered:
  - `ciguard.scan(file_path, platform, offline, ignore_file, no_ignore_file)` — scan a single pipeline file, return the full Report dict (findings / risk_score / summary / suppressed / etc.)
  - `ciguard.scan_repo(repo_path, fail_on, offline, no_ignore_file)` — auto-discover every pipeline file in a directory tree, scan all, return per-file summary + aggregated severity counts + `fails_threshold` boolean
  - `ciguard.explain_rule(rule_id)` — return canonical metadata for a rule (name, description, severity, category, remediation, compliance mappings, platforms, sample evidence)
  - `ciguard.diff_baseline(file_path, baseline_path, platform, offline)` — run a scan and compute the v0.5 baseline delta. Returns `new` / `resolved` / `unchanged_count` / `score_delta`
  - `ciguard.list_rules(platform=None, severity=None)` — enumerate the catalog with optional filters
- **Enterprise gate `CIGUARD_MCP_DISABLED`** — sysadmins managing corporate fleets can prevent local ciguard MCP servers via MDM (Jamf, Intune), `/etc/environment`, Group Policy, or shell profile. When set to `1` / `true` / `yes` / `on` (case-insensitive), `ciguard mcp` exits 2 with a clear policy message before starting the server. Designed for orgs standardising on a centralised MCP gateway that proxies, audits, and authorises tool traffic.
- **`ciguard mcp` subcommand** to launch the stdio server. No flags currently — stdio is the only transport. Future SSE/HTTP transports would extend this command.
- **Auto-discovery (`src/ciguard/discovery.py`)** — proto-Slice-9. Walks a directory tree and returns every recognised pipeline file: `.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile` / `*.jenkinsfile`, and `*.groovy` files containing pipeline markers (`pipeline {` or `node('...') {` — stricter than `looks_like_jenkinsfile` to avoid false-positives in Gradle/Spring/Grails projects). Excludes `.git`, `node_modules`, virtualenvs, build/cache dirs by default. Used by `ciguard.scan_repo` MCP tool; will also back the `ciguard scan-repo` CLI subcommand in v0.9.0.
- **Rule catalog (`src/ciguard/rule_catalog.py`)** — harvested at startup by scanning the labelled bad fixtures and capturing the first emission per `rule_id`. 34 of 44 rules are covered (the missing ~10 — PIPE-004, RUN-001, DEP-002, GHA-IAM-002/003/005, JKN-IAM-002, JKN-PIPE-002, all 6 SCA-*) don't fire on the bad fixtures and aren't yet enumerated. `explain_rule` returns a clear hint for unknown IDs. The catalog is the canonical source for `list_rules`, `explain_rule`, and any future docs / VS Code extension / web UI.

### Internals
- New optional dependency: `mcp>=1.0` (only pulled in by the `[mcp]` extra — the base install stays lean for CI use).
- 46 new tests (389 → **435**): 25 for MCP tool dispatch, 11 for the `CIGUARD_MCP_DISABLED` gate, 10 for discovery.

### Why this design
- Stdio transport because every desktop MCP client expects the `command` + `args` config pattern.
- 5 tools chosen to support the highest-value workflows: *"explain this finding"* (`scan + explain_rule`), *"draft a PR description"* (`scan + diff_baseline`), *"audit this whole repo"* (`scan_repo`).
- Rule catalog harvested rather than hand-extracted — avoided refactoring four analyzer modules to introduce a separate rule registry. The analyzer remains the source of truth for what a Finding's metadata looks like.
- Env-var gate over config file because the entire policy surface for v0.8.0 is "on" or "off" — env vars give operational flexibility (per-machine, per-process, MDM-friendly) without the loader / precedence-rules / schema-validation cost of a full config file. If real enterprise feedback later demands granular per-tool controls, a config file earns its complexity.

## [0.7.0] — 2026-04-26

Polish slice — answers two adoption-blocking gaps. **Renamed from "v0.5.1" during planning** because v0.6.0 + v0.6.1 had shipped in the meantime; per semver, `.ciguardignore` is a new on-disk format with new CLI semantics, so this is a minor bump rather than a backwards 0.5.x patch on top of 0.6.1.

### Added
- **`.ciguardignore` — file-based finding suppression with mandatory rationale.** YAML list at the repo root (or alongside the pipeline file). Modelled on Bandit's `# nosec` pattern but adapted for the YAML / external-file shape since pipeline files have no universal inline-comment convention. **Every entry must include a written `reason`** of at least 10 characters — naked rule-id-only disables are rejected at load time. This stops the "developer just disables the rule that fired" antipattern. Optional fields: `location` (substring filter on the finding location) and `expires` (ISO date — emits a warning when past, but still suppresses). New module `src/ciguard/ignore.py`. Discovery walks up from the input file until it finds a `.ciguardignore` or hits a `.git` directory; override with `--ignore-file <path>`, disable entirely with `--no-ignore-file`.
- **Suppressed findings remain visible in every report.** New `Suppressed` section in HTML, PDF, and SARIF outputs with the count and source path. JSON auto-serialises the new `Report.suppressed` / `Report.ignore_warnings` / `Report.ignore_file_path` fields. SARIF emits suppressed findings as results with the native `suppressions[]` array (kind=`external`), which GitHub Code Scanning renders as auto-closed "Suppressed" alerts rather than active ones. Suppressed findings do **not** contribute to the risk score or trigger CI failure exit codes.
- **PDF reporter delta section** (deferred from v0.5.0). Mirrors the HTML "Delta vs Baseline" section: 4-tile summary (new / resolved / unchanged / score Δ) followed by tables of new + resolved findings. Renders only when `--baseline` is supplied.
- **Pre-commit hook entry** at `.pre-commit-hooks.yaml`. Users can wire ciguard into `pre-commit` chains in three lines:
  ```yaml
  repos:
    - repo: https://github.com/Jo-Jo98/ciguard
      rev: v0.7.0
      hooks:
        - id: ciguard
  ```
  The hook auto-matches `.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile`, and `*.groovy`. Blocks commits on Critical / High findings via existing exit codes.
- **`ciguard scan` accepts positional file paths** in addition to `--input`. Multiple paths scan in sequence; exit code is the worst across the batch (Critical > High > clean). Required for the pre-commit hook integration; backward-compatible for existing `--input` callers.

### Internals
- New `Report` fields: `suppressed: List[Finding]`, `ignore_warnings: List[str]`, `ignore_file_path: Optional[str]`.
- Suppression runs *before* baseline diff so suppressed findings don't appear as `new` against an old baseline that pre-dated the suppression.
- Risk score and summary are recomputed after suppression so the post-suppression posture is reflected in terminal output, exit code, baseline comparison, and reporters.
- 30 new tests for ignore loader / validator / discovery / apply, plus 1 SARIF suppression rendering test. Total: **389 passing** (was 358 in v0.6.1).

## [0.6.1] — 2026-04-26

Second post-PRD release, completes the SCA story started in v0.6.0. Adds **GitHub Actions CVE awareness**, **graduated EOL runway tiers**, and **end-of-active-support detection**. All three changes share the v0.6.0 caching + offline infrastructure — no new external dependencies beyond OSV.dev.

### Added
- **`SCA-CVE-001` — GHA action / reusable workflow has known security advisory.** Queries OSV.dev's `GitHub Actions` ecosystem for advisories affecting `uses: actions/checkout@v4.1.0` and `uses: org/repo/.github/workflows/x.yml@v1` references. Severity inherited from the advisory (CVSS / GHSA label), defaulting to Medium when no signal is present. Multiple advisories on the same action aggregate to a single finding at the highest severity.
- **`SCA-EOS-001` — End of active support** (Low). Fires when an image / runtime is past end-of-active-support (vendor stops bug fixes / minor releases) but before end-of-security-life. Uses endoflife.date's `support` field where present (Java LTS, Python, Node have one; most distros don't). Silent skip when no `support` field — no false positives on Alpine/Debian/Ubuntu.
- **OSV.dev client** at `src/ciguard/analyzer/sca/osv.py`. Mirrors the v0.6.0 `EndOfLifeClient` pattern: `~/.ciguard/cache/osv-github-actions-<package>-<version>.json`, 24h TTL, `--offline` flag, in-memory dedup within a scan, network-error fallback to stale cache. POST-based query against `https://api.osv.dev/v1/query` with the same User-Agent header convention.
- **GHA action extractor** at `src/ciguard/analyzer/sca/action_extractor.py`. Pulls `uses:` references from both step-level (`steps[*].uses`) and job-level (`jobs.<id>.uses` reusable workflow) positions. Skips SHA-pinned refs (Dependabot lane), local refs (`./...`), Docker actions (`docker://...`), and branch-style refs (`@main`/`@master`).

### Changed (BREAKING for SCA-EOL-003 severity)
- **`SCA-EOL-003` severity is now graduated** rather than always Info. New runway tiers:
  - EOL ≤ 90 days away → **High** (was Info)
  - EOL in 91-180 days → **Medium** (was silent — NEW signal)
  - EOL in 181-365 days → **Low** (was silent — NEW signal)
  - EOL > 365 days away → silent (unchanged)
- This addresses real-world feedback: the v0.6.0 single-tier Info was too coarse; teams want "≤6 months = higher alert, ≤12 months = warning." If you depend on SCA-EOL-003 always being Info, your `--fail-on-new` thresholds may behave differently — review baselines before upgrading. Most users will see *more* findings (the 91-365 day window is now visible) but at lower severity.

### Internals
- `SCARuleFunc` signature changed from `(target, eol)` to `(target, eol, osv)` — both clients are now passed to every SCA rule. Rules that don't need OSV (`rule_sca_eol`, `rule_sca_pin_001`, `rule_sca_eos_001`) explicitly `del osv`. Rules that don't need EOL (`rule_sca_cve_001`) `del eol`.
- `AnalysisEngine` constructs both clients with the same `cache_dir` + `offline` flags so a single `--offline` run uses cached data from both sources consistently.
- 40 new tests (318 → 358) covering OSV client cache + offline, action extractor (every `uses:` shape), graduated tier dispatch, EOS detection, and CVE-001 end-to-end. Network mocked via seeded cache directories — fully offline / deterministic.

### Not in scope (rationale recorded for posterity)
- **Container base CVE lookup** was originally PRD'd as `SCA-CVE-002` but dropped after redesign — that's the Trivy/Grype lane (layer-by-layer package scanning). ciguard would compete and lose. The EOL tier graduation gives most of the same risk signal at the cycle level without overlap.
- **Application package CVEs** (`pip install requests==2.20.0`) — Snyk/Dependabot lane, unchanged.

## [0.6.0] — 2026-04-26

First release after the original PRD closed. Adds **SCA enrichment** — CVE/EOL awareness for the container images and language runtimes referenced inside the pipeline. ciguard remains a *pipeline-configuration* scanner; this release adds *dependency awareness* to existing findings without overlapping with full SCA tools (Snyk / Dependabot / Nexus IQ). The headline use-case is end-of-life detection: pipelines silently accumulate `python:3.9`, `node:16`, `alpine:3.16`, `debian:11` references that go EOL and stay in production for years afterwards.

### Added
- **`SCA-EOL-001` — End-of-Life Container Base Image** (Critical past 90d EOL, High past EOL ≤90d). Fires on Alpine, Debian, Ubuntu, CentOS, Rocky, AlmaLinux, Fedora image bases whose cycle has reached upstream end-of-life.
- **`SCA-EOL-002` — End-of-Life Language Runtime** (same severity scheme as 001). Fires on Python, Node, Ruby, Go, Java (OpenJDK / Eclipse Temurin / Amazon Corretto), Rust, PHP image tags whose runtime cycle is past EOL.
- **`SCA-EOL-003` — Container Image Approaching End-of-Life** (Info, ≤90 days remaining). Advance warning so EOL upgrades can be planned, not reactive. Deliberately Info-level to avoid alert fatigue.
- **`SCA-PIN-001` — Image Pinned by Tag, Not by Digest** (Low). Catches the gap between PIPE-001 (which fires on `:latest` / no tag) and true content immutability. Tags are mutable in most registries; digest pinning (`@sha256:...`) is the only way to be sure the same image runs on every CI invocation. Deliberately Low — most teams accept this trade-off knowingly, but high-trust pipelines should pin to digest.
- **`endoflife.date` integration** as the EOL data source. Free, vendor-neutral, ~250 products covered. ciguard caches the per-product JSON at `~/.ciguard/cache/endoflife-<product>.json` with a 24h TTL — pipeline scans stay fast, and the cache survives across runs and across pipelines on the same machine.
- **`--offline` CLI flag** on `ciguard scan` — disables all SCA network lookups, uses cache only. Required for air-gapped CI environments. Cache misses + offline = silent skip (not a finding); we never fabricate EOL data.
- **`AnalysisEngine(enable_sca=False)`** opt-out for callers that want strict platform-rule-only behaviour (and for tests).
- **Cross-platform image extraction** — SCA rules run for GitLab CI (job `image:`), GitHub Actions (`jobs.<id>.container` + `services`), and Jenkins (Declarative agents at top-level + per-stage + parallel children). One SCA module, three platforms.

### Why we stop here (and what's NOT in scope)
- **NOT general SCA** on the user's project dependencies (`requirements.txt`, `package.json`, `pom.xml`, etc.). That's the Snyk / Dependabot / Nexus IQ space — they have years of vulnerability database curation and we'd lose head-on. ciguard scans what's *referenced in the pipeline*, not what runs at application runtime.
- **NOT writing our own vulnerability database.** OSV.dev (planned for v0.6.1 CVE work) and endoflife.date are exhaustive and free.
- **NOT licence compliance.** Different user persona; separate adjacent product.

### Validation
- **318 / 318 tests passing** (was 288 in v0.5.0; +30 new tests in `test_sca_rules.py` covering image-reference parsing, EndOfLifeClient cache + offline behaviour, EOL severity dispatch, digest-pinning nudge logic, and engine opt-out).
- All existing fixtures pass with `enable_sca=False` — no regression to the 17-project GitLab corpus, the 14-project Jenkins corpus, or the labelled fixture validator (still 100% recall, 0 FP across 10 fixtures).
- Real-world smoke (against a deliberately-bad fixture with `python:3.9-slim`, `alpine:3.16`, `node:18-alpine`): all three correctly flagged Critical with accurate EOL date evidence (`python:3.9` EOL 2025-10-31, `alpine:3.16` EOL 2024-05-23, `node:18` EOL 2025-04-30).
- Lint clean.

### Roadmap context
This release implements PRD Slice 14 (SCA enrichment, originally planned as v0.7.0; brought forward in response to user prioritisation 2026-04-26). CVE lookup against OSV.dev + GitHub Advisory DB is **deferred to v0.6.1** — same infrastructure (HTTP client, cache, offline flag), different data source, deserves its own focused session.

## [0.5.0] — 2026-04-25

This release closes the original PRD with the last outstanding feature: **baseline / delta reports** for incremental scanning. Teams can now seed a baseline of acknowledged findings, and subsequent scans report only what *changed* — new findings appearing, prior findings resolved — rather than re-flagging the same set of known issues every CI run.

### Added
- **Stable finding fingerprints.** Every `Finding` now exposes a `fingerprint` field — a 16-char SHA-256 hash of `rule_id + location-without-line-numbers + evidence-normalized`. Fingerprints survive cosmetic drift (line shifts, whitespace changes, evidence case differences) so the same finding is recognised across runs even when the underlying file is reformatted. Severity and category are intentionally NOT in the hash — re-tuning a rule's severity should not invalidate its baseline entries.
- **Baseline JSON format** at `.ciguard/baseline.json` (default location, configurable via `--baseline`). Stores the full Finding payload plus metadata (`format_version`, `scanner_version`, `scan_timestamp`, `pipeline_name`, `platform`, `overall_score`, `grade`). Format version is `1`; the loader rejects future versions cleanly so users know to upgrade ciguard rather than getting silent partial behaviour.
- **`Delta` model** on `Report.delta` — populated when a scan is run with `--baseline`. Surfaces three lists (`new`, `resolved`, `unchanged`), the score delta against baseline, and `Delta.new_at_or_above(severity)` for CI gating logic.
- **`ciguard baseline` subcommand** — runs a scan and writes the baseline JSON without producing a full report. Use this once to seed the baseline; thereafter `ciguard scan --baseline <path>` diffs against it.
- **`ciguard scan` flags:**
  - `--baseline <path>` — diff against this baseline. Findings absent from the baseline appear as `new`; findings only in the baseline as `resolved`.
  - `--update-baseline` — after the scan, write the current findings as the new baseline (acknowledges everything currently surfaced).
  - `--fail-on-new={Critical,High,Medium,Low,Info,none}` — exit non-zero if any *new* finding at this severity or above appears since baseline. `none` disables severity-based exit codes entirely. Designed for CI: a clean delta = exit 0 even if absolute findings exist, because they were already in the baseline.
- **Reporter integration** — every existing reporter renders delta information when present:
  - **HTML** — new "Delta vs Baseline" section above the Findings table, with summary tiles (new / resolved / unchanged / score change) and per-list tables. Hidden when no baseline.
  - **JSON** — the `delta` field auto-serialises in the report payload.
  - **SARIF 2.1.0** — every result now carries `partialFingerprints["ciguard/v1"]` (the same 16-char fingerprint, suitable for SARIF consumers' own diffing). When a baseline is present, results gain SARIF's native `baselineState` field (`"new"` | `"unchanged"` | `"absent"`); resolved findings are emitted as separate `absent` results so GitHub Code Scanning auto-closes them.
  - **PDF** — no delta section yet (deferred to v0.5.1 — the reportlab layout needs targeted work).
- **`Report.scanner_version`** — every report now records the ciguard version that produced it. Stored in baselines too, for forward-compatibility checks.

### Changed
- `Finding` is now a `pydantic.computed_field` for `fingerprint` — non-breaking; existing serialisations gain the field, existing readers ignore it.

### Validation
- **288 / 288 tests passing** (was 267 in v0.4.1; +21 tests across `test_baseline.py` (17) and `test_sarif_report.py::TestSARIFBaselineState` (4)).
- Labelled-fixture validation: 100% recall, 0 FP across all 6 Jenkins + 4 GitLab fixtures.
- End-to-end smoke: empty baseline marks all findings as `new`; identical scan against own baseline reports zero changes; pipeline edits show the right new/resolved partition; `--fail-on-new=High` correctly returns exit 1 when a new High appears.
- Lint clean. No regressions to the 17-project GitLab corpus run.

### PRD status
With v0.5.0 the original PRD's Slice 6 — Multi-Platform Expansion — is complete: GitHub Actions (v0.2.x), SARIF (v0.3.0), Jenkins Declarative + Scripted (v0.4.0/v0.4.1), and now baseline/delta reports. **The original PRD scope is fully shipped, ahead of the 2026-05-31 due date.**

## [0.4.1] — 2026-04-25

### Added
- **Minimal Scripted Pipeline support.** The Jenkins parser now recognises four shapes (in priority order): `declarative` (existing `pipeline {}` path), `node-scripted` (top-level `node('label') { stage('…') { sh '…' } }` blocks), `shared-library` (a single top-level `buildPlugin(...)`-style call, optionally preceded by `@Library('lib') _`), and `scripted-unparseable` (free-form Groovy with `def` / control flow / multiple statements — out of scope, the engine produces an empty report and the CLI emits a clearer warning). The `Jenkinsfile.style` field exposes which path was taken.
- **`JKN-LIB-001` — Shared-Library Delegation** (Info, Pipeline Integrity). Fires when a Jenkinsfile is exclusively a shared-library call. The actual pipeline body lives in the library's `vars/<name>.groovy` and ciguard cannot audit that from this file alone — the finding flags the coverage gap so a clean report is not silently mistaken for a clean build. Severity is Info (1-pt deduction, capped at 5/category).
- **Real-world corpus validator** at `scripts/validate_jenkins_corpus.py`. Mirrors the GitLab-side `validate_corpus.py`: fetches Jenkinsfiles from public GitHub repos, runs them through the parser + engine, writes `tests/corpus_results/JENKINS_SUMMARY.md` with shape breakdown, finding counts, and timings. Cache at `tests/corpus_jenkins/` (gitignored).
- **Labelled-fixture validation extended to Jenkins.** `scripts/validate_fixtures.py` now dispatches by `kind` (`gitlab` vs `jenkins`) and includes recall + precision checks for all six Jenkins fixtures (declarative, node-scripted, shared-library, free-form Scripted — bad and good of each shape where applicable). All six pass at 100% recall, zero false positives.

### Changed
- **`is_scripted` semantics narrowed.** The flag now means *only* "free-form Scripted Groovy that ciguard cannot model" (`style == "scripted-unparseable"`). Node-style Scripted and shared-library calls — which `v0.4.0` would have flagged the same way — are now in scope and produce real findings or coverage-gap signals. Backwards compatible: existing callers that gated on `is_scripted` see the same boolean for the genuinely-unparseable case.
- **CLI summary line for Jenkinsfiles** distinguishes the four shapes with appropriate WARN/OK colouring instead of the previous Declarative-vs-bail dichotomy.

### Validation
- **267 / 267 tests passing** (was 249 in `v0.4.0`; +18 for the new shapes and `JKN-LIB-001`).
- **Real-world corpus impact on a 14-Jenkinsfile sample**: in-scope coverage rose from 2 / 14 (14%) to 11 / 14 (79%); silent-empty reports went from 12 / 14 to 0 / 14. The 3 remaining out-of-scope files (`jenkinsci/jenkins`, `jenkinsci/docker`, `jenkinsci/docker-agent`) are genuinely free-form Groovy with top-level `def` / `properties([...])` / dynamic `combinations { }` blocks. Parser remained crash-free across all 14 inputs.

## [0.4.0] — 2026-04-25

### Added
- **Third platform: Jenkins Declarative Pipelines.** ciguard now scans `Jenkinsfile` (Groovy DSL) sources alongside GitLab CI YAML and GitHub Actions workflows. Platform is auto-detected from filename (`Jenkinsfile`, `*.jenkinsfile`, `*.groovy`) or content sniff (`pipeline {` at top level), falling back to YAML shape detection for the YAML platforms. Scripted Pipelines (no `pipeline {}` block) are flagged with a parse warning — out of scope for this release.
- **Six Jenkins security rules** covering the GitLab/GHA-equivalent threat surface plus two Jenkins-specific rules:
  - `JKN-PIPE-001` — **Unpinned container agent image** (High). `agent { docker { image '...' } }` references must pin to a digest or specific tag; `:latest` and bare names allow upstream replacement.
  - `JKN-IAM-001` — **Hardcoded secret in `environment` block** (High). Secret-shaped keys with literal values; the safe pattern is `KEY = credentials('id')`.
  - `JKN-RUN-001` — **Unconstrained top-level `agent any`** (Medium). Build can land on any executor including shared general-purpose nodes.
  - `JKN-RUN-002` — **Privileged docker agent** (Critical). `args` containing `--privileged`, `--pid=host`, `--net=host`, `/var/run/docker.sock`, `--cap-add=ALL`, or `--user=root` — each lets a compromised build escape the container sandbox.
  - `JKN-SC-001` — **Dangerous shell pattern** in `sh`/`bat`/`powershell` step bodies (High). Same detection as PIPE-003 / GHA-SC-001: curl-pipe-bash, eval `$VAR`, PowerShell IEX cradles.
  - `JKN-SC-002` — **Dynamic Groovy `script { }` block inside steps** (Info). Bypasses the Declarative whitelist; surfaced for review rather than blocked outright.
- **Four Jenkins-aware built-in policies** (`POL-JKN-001` … `POL-JKN-004`) keyed off the Jenkins rule families and gated by `platforms: ["jenkins"]`. Mirrors the GHA policy bundle from v0.2.1.
- **Hand-rolled Groovy-aware parser** (`ciguard.parser.jenkinsfile`). Strips `//` and `/* */` comments without touching string contents; tracks brace + paren balance through single-, double-, and triple-quoted strings; depth-0 directive matching so per-stage `agent`/`environment` blocks don't shadow the top-level ones; captures `sh`/`bat`/`powershell` bodies in both bare-string and parenthesised named-arg (`sh(script: '...', returnStdout: true)`) forms; recognises `withCredentials([...]) { ... }` and `script { }` blocks; flattens nested `parallel { stage(...) { ... } }` into per-stage parallel children.

### Changed
- `--platform` CLI choice extended with `jenkins`. Auto-detect now sniffs filename + content before YAML parsing so Jenkinsfiles don't error out on `yaml.safe_load`.
- Web `/api/scan` upload endpoint accepts Jenkinsfiles; the original filename is preserved through the temp-file dance so the filename-based heuristic still fires.
- README + roadmap: ciguard now markets as a **three-platform** tool (was two).
- Total deterministic security rules across all three platforms: 31 → 37.
- Total built-in policies: 13 → 17.

### Internal
- 36 new tests (213 → 249 passing) covering: parser comment + brace + string handling, depth-0 block extraction, parallel-stage flattening, all six rule firings against the bad/good fixtures, end-to-end engine dispatch, and the `looks_like_jenkinsfile` heuristic.
- `Jenkinsfile` model joins `Pipeline` and `Workflow` as a third top-level analysis target. `AnalysisEngine.analyse()` dispatches on type; the Jenkins path synthesises a `Pipeline` shadow (each stage → job) so existing reporters and the web UI keep working unchanged.
- `_extract_block` rewritten to track brace + string state and only match at depth 0, fixing a class of false-positive directive matches that affected nested-stage parsing.

## [0.3.0] — 2026-04-25

### Added
- **SARIF 2.1.0 output format.** `ciguard scan --output report.sarif --format sarif` writes a fully-spec-compliant SARIF document. Uploading via `github/codeql-action/upload-sarif` surfaces findings in the GitHub **Security → Code scanning alerts** tab — same surface CodeQL uses, with PR-blocking gates available. Severity → SARIF level mapping: Critical/High → `error`, Medium → `warning`, Low/Info → `note`. Each result carries a numeric `security-severity` (9.5 / 7.5 / 5.0 / 3.0 / 0.0) so GitHub's ranking is sensible. Compliance framework refs (ISO 27001 / SOC 2 / NIST CSF) ride along on each rule's `properties.tags` so they're searchable in Code Scanning. Rule definitions are deduplicated across the run by `rule_id`.
- **Five advanced GitHub Actions security rules** taking the GHA catalogue from 7 to 12:
  - `GHA-PIPE-002` — **Unsafe `pull_request_target` event** (Critical). The canonical GitHub Actions RCE vector: `pull_request_target` runs in the base-repo context with write tokens, so combining it with any PR-author-derived input is dangerous.
  - `GHA-IAM-005` — **No `permissions:` block declared** (High). Workflow inherits the repository default which is frequently more permissive than needed; explicit declaration is reviewable.
  - `GHA-IAM-006` — **Token-theft risk in `pull_request_target` workflow** (Critical). `actions/checkout` without `persist-credentials: false` writes the GITHUB_TOKEN into `.git/config`; combined with `pull_request_target` this is a classic PR-author-RCE vector.
  - `GHA-RUN-003` — **Self-hosted runner without narrowing labels** (Medium). Bare `runs-on: self-hosted` accepts any repository workflow, including fork PRs, onto shared hardware.
  - `GHA-SC-003` — **`secrets: inherit` to non-SHA-pinned reusable workflow** (Critical). Forwards every repo secret to the callee; if the `uses:` ref is mutable, an upstream compromise replaces the implementation between runs and exfiltrates everything.
- New labelled fixture `tests/fixtures/github_actions/no_permissions.yml` covering `GHA-IAM-005` (which can't fire on `bad_actions.yml` because that fixture explicitly declares `permissions: write-all`).

### Changed
- `bad_actions.yml` extended with `pull_request_target` event + a bare `self-hosted` job to exercise PIPE-002 / IAM-006 / RUN-003. SC-003 was already covered by the existing `call-shared` reusable workflow with `secrets: inherit` + `@main`.
- README + USAGE.md updated: GHA rule count 7 → 12; report format count 3 → 4 (SARIF added); roadmap reshuffled (Jenkins moves from v0.3 to v0.4; baseline / delta from v0.4 to v0.5).
- Total deterministic security rules across both platforms: 26 → 31.

### Internal
- 22 new tests (198 → 213 passing): 7 covering the new GHA rules + fixture, 15 covering SARIF output shape, severity mapping, rule deduplication, compliance tags, and edge cases (empty report, Critical → `error` mapping with `security-severity = 9.5`).

## [0.2.1] — 2026-04-25

### Added
- **Six GitHub Actions built-in policies** (`POL-GHA-001` … `POL-GHA-006`) closing the v0.2.0 gap where GHA scans saw "no built-in policies":
  - `POL-GHA-001` All Action References Must Be SHA-Pinned (Critical via `GHA-SC-002`)
  - `POL-GHA-002` No Hardcoded Secrets in env (Critical via `GHA-IAM-001`)
  - `POL-GHA-003` Workflow Permissions Must Be Least-Privilege (High via `GHA-IAM-004`)
  - `POL-GHA-004` All Container Images Must Be Pinned (High via `GHA-PIPE-001`)
  - `POL-GHA-005` Deploy Jobs Must Declare a GitHub Environment (Critical via `GHA-DEP-001`)
  - `POL-GHA-006` No Privileged Service Containers (Critical via `GHA-RUN-002`)
- **`platforms: List[str]`** field on `PolicyDefinition`. Empty list = applies to all platforms (default for user-supplied custom policies). Built-ins now declare `platforms=["gitlab-ci"]` or `["github-actions"]`. The evaluator filters by `report.platform` before evaluating.
- **Web UI now accepts GitHub Actions workflow uploads.** `/api/scan` uses the `parse_file` auto-detect dispatcher; the response payload includes `platform`. The drag-and-drop UI Just Works for both formats.

### Changed
- `BUILTIN_POLICIES` count: 7 → 13 (7 GitLab + 6 GitHub Actions). Tests updated to count by-platform-applicability rather than the literal length.
- CLI no longer skips built-ins on GHA scans — all 13 are passed to the evaluator and platform filtering is applied internally.

### Internal
- 5 new tests covering the GHA built-ins + platform-filter behaviour. **191/191 total passing** (was 186 in v0.2.0).

## [0.2.0] — 2026-04-25

### Added
- **GitHub Actions support.** `ciguard scan --input .github/workflows/release.yml` now runs end-to-end. Format auto-detection inspects the YAML shape; `--platform gitlab-ci|github-actions|auto` overrides.
- **`Workflow` / `Job` / `Step` pydantic models** in `src/ciguard/models/workflow.py`. Separate from `Pipeline` because GHA's structure (events, matrix, reusable workflows, composite actions, step-level `uses`/`with`) doesn't map cleanly. The `Finding` / `Report` / risk-score / reporter stack is shared across both platforms.
- **Seven GHA security rules** (namespaced `GHA-*`):
  - `GHA-PIPE-001` — Unpinned container or service image
  - `GHA-IAM-001` — Hardcoded secret in workflow / job / step `env`
  - `GHA-IAM-004` — Excessive workflow / job permissions (`permissions: write-all`)
  - `GHA-RUN-002` — Privileged service container (DinD or `options: --privileged`)
  - `GHA-DEP-001` — Likely-deploy job without a GitHub `environment:` block (gates protection rules)
  - `GHA-SC-001` — Dangerous shell pattern in `run:` (`curl | bash`, `eval`, etc.)
  - `GHA-SC-002` — Action / reusable-workflow `uses:` not pinned to a 40-char commit SHA
- **Engine dispatch on input type** — `AnalysisEngine.analyse(target)` accepts either a `Pipeline` or a `Workflow`. Rules from `rules.py` (GitLab) and `gha_rules.py` (GHA) run independently; cross-platform contamination is impossible by construction.
- **`Report.platform` field** (`"gitlab-ci"` | `"github-actions"`) plus `Report.workflow: Optional[Workflow]` for full GHA fidelity. Existing reporters/web/PDF read `report.pipeline` (synthesised on the GHA path so job count + "Target" lines keep working).
- Labelled fixture pair `tests/fixtures/github_actions/{bad,good}_actions.yml` — used to validate PRD acceptance criteria 1 (recall) and 2 (zero FPs) for the GHA platform: bad fixture grades **D** with 9 Critical + 7 High; good fixture scores **100.0 (A)** with **zero findings**.

### Changed
- README + USAGE.md mark GitHub Actions as supported (was "in development"). Roadmap moved to v0.2.x = GHA-aware built-in policies + matrix-aware rules; v0.3 = Jenkins; v0.4 = baseline / delta.
- The 7 built-in policies remain GitLab-specific (`POL-001` etc. reference GitLab rule IDs). For GHA scans the CLI skips built-ins and runs custom user policies only — explicitly noted in the policy step output. GHA-aware built-ins are tracked for v0.2.x.

### Internal
- 19 new GHA rule tests + 29 GHA parser tests (Slice 6 part 1) → **186/186 total passing** (was 138 in v0.1.4).
- ruff, bandit (Medium+), pip-audit, Trivy gates all stay green for v0.2.0.

## [0.1.4] — 2026-04-25

### Changed
- **Minimum supported Python is now 3.10** (was 3.9). Python 3.9 reached EOL in October 2025; every CVE-fixed version of `python-multipart`, `Pillow`, `pytest`, and `python-dotenv` requires ≥3.10. CI matrix is now 3.10 / 3.11 / 3.12 / 3.13.

### Fixed
- Bumped pinned dependencies to versions without known CVEs:
  - `python-multipart` 0.0.20 → 0.0.26 (GHSA-wp53-j4wj-2cfg, GHSA-mj87-hwqh-73pj)
  - `pytest` 8.4.2 → 9.0.3 (GHSA-6w46-j5rx-g56g)
  - `Pillow` (transitive of `reportlab`) pinned ≥12.2.0 (GHSA-cfh3-3jmp-rvhc, GHSA-whj4-6x5x-4v2j)
  - `python-dotenv` (transitive of `uvicorn[standard]`) pinned ≥1.2.2 (GHSA-mf9w-mj56-hr94)

### Added
- **Bandit SAST job** in CI. Fails on Medium+ severity. Two intentional findings annotated with `# nosec`: `yaml.load(...Loader=_GitLabSafeLoader)` (the loader is a SafeLoader subclass), and the dev-only `host="0.0.0.0"` in `web/app.py`.
- **`pip-audit --strict -r requirements.txt`** job in CI. Fails on any known CVE in declared dependencies.
- **Trivy image scan** in the release workflow, gated on the GHCR push. Fails the release on HIGH/CRITICAL OS-package or Python-library CVEs that have an upstream fix (`ignore-unfixed: true`).
- **Dependabot security updates** enabled at the repository level (toggle was off; version updates were already running). Security PRs will now open automatically when a dependency advisory matches.
- **`SECURITY.md`** — vulnerability disclosure policy, supported versions, scope, and current scanning posture.

## [0.1.3] — 2026-04-25

### Fixed
- **POL-003 / SC-003 false-negative on `include: template:`** — pipelines that pulled in GitLab's `Security/SAST.gitlab-ci.yml`, `Security/Secret-Detection.gitlab-ci.yml`, or `Security/Dependency-Scanning.gitlab-ci.yml` via the `include:` block were still flagged as missing scanning, because the rules only inspected job names and script lines. Include directive values are now part of the search corpus, and the regex covers `secret-detection`, `gitleaks`, `trufflehog`, `detect-secrets`, and `gemnasium`.
- **SC-003 false signal on include-only manifests** — root pipelines that contain only `include:` directives (no jobs) parse to zero jobs locally; SC-003 used to fire anyway, even when the included files might run dependency scanning. SC-003 now skips when the pipeline has no jobs (matching ART-003's pattern). 4 corpus projects (`meltano`, `veloren`, `kicad`, `gitlab-org/gitlab-runner`) drop a spurious SC-003 finding as a result.

### Internal
- New `Pipeline.include_text()` helper flattens all `include:` directive values to a single string for keyword matching across rules.
- 5 new regression tests (133 → 138 total). Corpus aggregate Medium count: 225 → 221.

## [0.1.2] — 2026-04-25

### Fixed
- Container image now publishes for both `linux/amd64` and `linux/arm64`. v0.1.1 shipped amd64-only, which broke `docker pull ghcr.io/jo-jo98/ciguard:latest` on Apple Silicon Macs and arm64 servers (AWS Graviton, Ampere, Raspberry Pi) with `no matching manifest for linux/arm64/v8`.

### Internal
- All GitHub Actions are SHA-pinned (supply-chain hygiene; eat-our-own-dogfood — `ciguard` flags exactly this in GitLab CI as PIPE-002 / SC-002).
- Dependabot configured for github-actions, pip (grouped runtime + dev), and docker base image with weekly cadence.
- ruff now enforced in CI (was advisory in 0.1.1); 30 baseline issues resolved.
- Required-reviewer protection rule on the `pypi` GitHub environment — release publishes to PyPI now wait for one-click approval.

## [0.1.1] — 2026-04-24

### Fixed
- Container image build for GHCR — repository name is now correctly lower-cased so `ghcr.io/jo-jo98/ciguard:v0.1.1` and `:latest` actually publish on tag.

## [0.1.0] — 2026-04-24

Initial public release. Slice 1 (GitLab CI):

### Added
- GitLab CI (`.gitlab-ci.yml`) parser with support for `!reference` tags, anchors, includes, environments
- 19 deterministic security rules across 6 categories (Pipeline Integrity, Identity & Access, Runner Security, Artifact Handling, Deployment Governance, Supply Chain)
- Policy engine — 7 built-in organisational policies plus custom YAML policies (6 condition types)
- HTML report (dark, self-contained, no CDN dependency)
- JSON report (API-ready)
- PDF report (8 sections, audit-grade, via reportlab)
- Weighted A–F risk score with per-category breakdown
- Compliance mapping per finding: ISO 27001, SOC 2, NIST CSF
- LLM enrichment (Anthropic Claude + OpenAI, optional, graceful degradation)
- FastAPI web UI with drag-drop upload + REST API
- Scanner integrations: Semgrep CE, OpenSSF Scorecard, GitLab native security artifacts
- CLI: `ciguard scan --input <file> [--output ...] [--format ...] [--policies ...] [--llm]`
- Docker image (web UI on :8080) and `docker compose` services for web/cli/test

### Validated
- Recall: 100% (14/14) on labelled bad fixture
- False positives: 0 on labelled good fixture
- Performance: 166 ms mean parse + analyse on a synthetic 500-job pipeline
- 17 public real-world GitLab CI files across the corpus, all parsing cleanly
