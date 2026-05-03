# DEPLOYMENT.md — running ciguard in production

> Operator-facing companion to [README.md](README.md) (user-facing) and [USAGE.md](USAGE.md) (workflow walkthroughs). Covers the **GitHub App** deployment path as introduced in v0.11.1 (real scan executor). The CLI / Web UI / MCP server modes have their own footprints — those have lived under [README.md](README.md) since v0.1 and aren't repeated here.

## 1. What you're deploying

ciguard's **App receiver** is a FastAPI process that:

- Listens for GitHub webhooks at `POST /webhook` (HMAC-verified per `THREAT_MODEL.md` Surface 9 row 9.1)
- Mints installation tokens via the GitHub App JWT broker, fetches the repo tarball at the head SHA, scans it, and posts findings back as a Check Run + PR comment
- Stores per-installation baselines under `<storage_root>/<installation_id>/<owner>/<repo>/baseline.json`

Single-process. No database. No queue broker. The scheduler ships an in-memory bounded queue (default depth 128, 2 worker tasks) so any single-host install handles thousands of webhook deliveries per day without external dependencies.

| Component | Default | Tunable via |
|---|---|---|
| Bind host | `127.0.0.1` (loopback only) | `ciguard app --host` |
| Bind port | `8000` | `ciguard app --port` |
| Worker concurrency | 2 | not yet exposed; set `app.state.scheduler.workers` in a custom factory |
| Queue depth | 128 | same |
| Body cap | 25 MB | `MAX_BODY_BYTES` in `webhook.py` |
| Tarball cap | 200 MB | `MAX_TARBALL_BYTES` in `clone_executor.py` |
| Token TTL | 30 min | `INSTALLATION_TOKEN_TTL_SECONDS` |

## 2. Before you provision

You need:

1. A **GitHub App registration** in the org or personal account that will install it. Either:
   - Create from `deploy/app/manifest.yml` via `https://github.com/settings/apps/new` → "Create from manifest" (preferred — the manifest is the canonical permission set per `THREAT_MODEL.md` Surface 9), OR
   - Create manually with exactly these permissions: **Pull requests: Read+Write**, **Checks: Read+Write**, **Contents: Read**, **Metadata: Read** (and no others). Subscribe to events: `pull_request`, `push`, `check_run`, `check_suite`.

   > **⚠ Manifest drift note (cycle 1.5 follow-up — issue [#20](https://github.com/Jo-Jo98/ciguard/issues/20)):** the current `deploy/app/manifest.yml` lists `actions: read` for "Read workflow YAML on GitHub Actions repos." The v0.11.0 stub-scan path doesn't actually use this — workflow files come along in the tarball clone. Pending the manifest patch from issue #20, you can either accept the extra read scope (does no harm) or hand-edit the manifest before pasting.

2. Three secrets from the App registration page:
   - **App ID** (public, 6–7 digits)
   - **Webhook secret** (your choice — `openssl rand -hex 32` is the recommended generator)
   - **Private key** (downloaded as a `.pem` after registration — GitHub generates RSA-2048)

3. A **public HTTPS endpoint** that GitHub can reach. The App can run on plaintext HTTP for dev (and the Cycle 1.5 self-pentest used HTTP) but production webhooks require TLS — both for confidentiality of webhook payloads and because some compliance frameworks require it. Sections 5 and 6 cover the TLS-termination patterns.

4. A host or container with **Python 3.10+**.

## 3. Secret material

ciguard reads four env vars at startup. Process startup fails-closed if any are missing:

| Variable | Required | Purpose |
|---|---|---|
| `CIGUARD_APP_ID` | yes | App ID from registration |
| `CIGUARD_APP_WEBHOOK_SECRET` | yes | Webhook secret you generated |
| `CIGUARD_APP_PRIVATE_KEY` *or* `CIGUARD_APP_PRIVATE_KEY_PATH` | yes (one of two) | PEM bytes inline (suits secret managers that mount as env vars) **or** absolute path to the `.pem` on disk |
| `CIGUARD_APP_STORAGE_ROOT` | yes | Directory the App owns for baseline JSON. Must be writable by the process UID. |

### File-mode hygiene

When you take the `CIGUARD_APP_PRIVATE_KEY_PATH` route, **the operator is responsible for the file's permission bits**. ciguard's loader does not yet validate them (tracked under issue [#22](https://github.com/Jo-Jo98/ciguard/issues/22) as a defence-in-depth lint). Recommended:

```sh
chown ciguard:ciguard /etc/ciguard/private-key.pem
chmod 0600 /etc/ciguard/private-key.pem
```

The `.env` file (or whatever you use to inject env vars) deserves the same treatment — `0600` and owned by the process UID.

### Avoiding key bytes in process listings + logs

Pass the key via env or file path. **Don't pass it on the command line** — it'll appear in `ps`, `/proc/<pid>/cmdline`, and any process-list-capturing observability tool.

## 4. Run as a non-root UID

ciguard's lab during Cycle 1.5 ran as root (acceptable for a throwaway pentest droplet, NOT for production). For production:

```sh
# Create a dedicated UID with no login shell
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ciguard

# Pre-create the storage root with the right ownership
sudo install -d -o ciguard -g ciguard -m 0750 /var/lib/ciguard
```

`/proc/<pid>/mem` and `ptrace`-based key extraction are not in ciguard's threat model boundary (kernel-level isolation problem), but a non-root UID makes those attacks require either root or `CAP_SYS_PTRACE` on the same UID — much narrower than running as root.

## 5. Reverse proxy + TLS

Production webhooks require HTTPS. ciguard does not terminate TLS itself — front it with a reverse proxy that does, and bind the receiver to loopback only:

```sh
ciguard app --host 127.0.0.1 --port 8000
```

### nginx example

```nginx
server {
    listen 443 ssl http2;
    server_name ciguard.example.com;

    ssl_certificate     /etc/letsencrypt/live/ciguard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ciguard.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Webhook bodies are HMAC-bound to the raw bytes — do NOT enable
    # request-body buffering modifications (gzip/etc.) on this path.
    location = /webhook {
        client_max_body_size 30m;          # 5MB headroom over MAX_BODY_BYTES
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;       # stream the body straight through
    }

    location = /healthz {
        proxy_pass http://127.0.0.1:8000;
        access_log off;
    }
}
```

Optional: lock the public-facing webhook port to GitHub's published hook IP ranges (`https://api.github.com/meta` → `.hooks`). The Cycle 1.5 lab did this at the cloud-provider firewall layer — see `Project ciguard/pentest-lab/main.tf` for a Terraform reference. It's belt-and-braces; the HMAC verification is the load-bearing control.

## 6. systemd unit (recommended for bare-metal / VM)

`/etc/systemd/system/ciguard-app.service`:

```ini
[Unit]
Description=ciguard GitHub App receiver
Documentation=https://github.com/Jo-Jo98/ciguard
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=ciguard
Group=ciguard
WorkingDirectory=/var/lib/ciguard

# Secrets via EnvironmentFile (mode 0600, owned by ciguard:ciguard).
# CIGUARD_APP_PRIVATE_KEY_PATH should point INSIDE /etc/ciguard/.
EnvironmentFile=/etc/ciguard/app.env

ExecStart=/usr/local/bin/ciguard app --host 127.0.0.1 --port 8000

# Hardening — kernel-isolation primitives that close several
# THREAT_MODEL Surface 9 row "App private key exposure at rest" sub-cases.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# The App needs to write only to its storage root.
ReadWritePaths=/var/lib/ciguard

# Resource bounds — protect the host even if the App is wedged.
LimitNOFILE=4096
TasksMax=128
MemoryMax=1G

Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Bring up:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ciguard-app
sudo journalctl -u ciguard-app -f
```

## 7. Container deployment

The repo's existing `Dockerfile` builds the **Web UI** image (port 8080), not the App receiver. To run the App in a container, override the entrypoint:

```sh
docker run --rm -d \
  --name ciguard-app \
  --read-only --tmpfs /tmp:rw,mode=1777 \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8000:8000 \
  -v /etc/ciguard:/etc/ciguard:ro \
  -v ciguard-storage:/var/lib/ciguard \
  -e CIGUARD_APP_ID \
  -e CIGUARD_APP_WEBHOOK_SECRET \
  -e CIGUARD_APP_PRIVATE_KEY_PATH=/etc/ciguard/private-key.pem \
  -e CIGUARD_APP_STORAGE_ROOT=/var/lib/ciguard \
  ghcr.io/jo-jo98/ciguard:latest \
  ciguard app --host 0.0.0.0 --port 8000
```

Front this with the same reverse proxy from Section 5 (the proxy lives on the host or another container; the App container itself binds inside the user-defined network).

`--cap-drop=ALL` + `no-new-privileges` removes `CAP_SYS_PTRACE`, which is the primary kernel-level attack vector against the in-memory private key (per `THREAT_MODEL.md` Surface 9 row 9.8 / Cycle 1.5 Section 1.7 in the report).

## 8. Storage layout

`CIGUARD_APP_STORAGE_ROOT` is the App's owned writable directory. Layout:

```
$CIGUARD_APP_STORAGE_ROOT/
├── 129208018/                            # installation_id
│   └── jo-jo98/
│       └── target/
│           └── baseline.json              # mode 0640
└── 234567890/                            # next install
    └── another-org/
        └── another-repo/
            └── baseline.json
```

Per `THREAT_MODEL.md` Surface 9 row 9.3 + Cycle 1.5 row 9.3 evidence, every read + write is keyword-only on the *verified* installation_id (the one extracted from the HMAC-verified webhook payload). A baseline file written by install A is unreachable from any code path holding install B's id.

**Backups:** baseline JSON is the only persistent state. Treat it as recoverable by re-scanning, not load-bearing — it's a per-install delta marker, not a customer record. A nightly `tar` snapshot is sufficient; no point-in-time recovery needed.

## 9. Observability

ciguard logs to stderr in standard Python `logging` format. Loggers of interest:

| Logger | What it covers |
|---|---|
| `ciguard.app.webhook` | Each `POST /webhook` — event type, delivery id (truncated), accept/reject. Attacker-controlled fields are CR/LF-stripped via `_safe_for_log` |
| `ciguard.app.scheduler` | Enqueue / dedup / drain |
| `ciguard.app.scan_runner` | Job lifecycle — Check Run create/complete, exception routing |
| `ciguard.app.tokens` | JWT mint, install-token cache hit/miss/invalidate. **Tokens are 6-char-prefix-redacted** in log lines (`ghs_a3df…`) — never full tokens |
| `ciguard.app.clone_executor` | Tarball fetch + extract + scan handoff. Token never appears in logs |

### What to alert on

- **HTTP 401 rate** on `/webhook` — sustained > a few per minute suggests either webhook-secret rotation drift or an active probing attempt
- **HTTP 503 rate** on `/webhook` — queue overflow; scale workers or queue depth
- **Repeated `set_check_run_failed` log lines for the same install** — scan executor failing systematically (network, GitHub API rate limit, bad tarball)
- **Tarball-too-large rejections** — install pointed at a monorepo too big for the App; recommend that user run `ciguard scan-repo` locally

### What NOT to log

If you're piping logs to a third-party SIEM, double-check the SIEM doesn't decompose / re-tokenise your log lines and resurface fields. ciguard's own logger respects the redaction contracts (Surface 9 row 9.7), but a SIEM that does its own enrichment (reading PII in nearby fields) can defeat them. Audit before you forward.

## 10. Upgrades + rollback

`pip install --upgrade ciguard` for pip installs; `docker pull ghcr.io/jo-jo98/ciguard:<version>` for containers. The release lanes (`_release.yml`) sign every image with Sigstore (keyless) and attach SBOM attestations + PEP 740 PyPI provenance — verify before deploying:

```sh
# PyPI provenance (PEP 740)
pip install ciguard --require-hashes -r requirements.lock

# Container signature (cosign keyless)
cosign verify ghcr.io/jo-jo98/ciguard:v0.11.1 \
  --certificate-identity-regexp 'https://github.com/Jo-Jo98/ciguard/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Rolling back is the same operation in reverse. Baseline files written by a newer version remain readable by older versions (the schema has a `format_version` field; older code refuses to use baselines from a newer schema rather than mis-parsing them).

## 11. Reference: full env-var contract

| Variable | Component | Purpose |
|---|---|---|
| `CIGUARD_APP_ID` | App | App ID from GitHub registration |
| `CIGUARD_APP_WEBHOOK_SECRET` | App | Webhook secret for HMAC verification |
| `CIGUARD_APP_PRIVATE_KEY` | App | PEM bytes inline (mutually exclusive with `_PATH`) |
| `CIGUARD_APP_PRIVATE_KEY_PATH` | App | Path to .pem on disk |
| `CIGUARD_APP_STORAGE_ROOT` | App | Writable directory for per-install baseline JSON |
| `CIGUARD_MCP_REDACT_LEVEL` | MCP | `full` (default) / `partial` / `raw`; unknown values → `full` |
| `CIGUARD_MCP_AUDIT_DISABLED` | MCP | `1` to opt out of `~/.ciguard/mcp-audit.jsonl` |
| `CIGUARD_MCP_AUDIT_PATH` | MCP | Override audit path (default `~/.ciguard/mcp-audit.jsonl`) |
| `CIGUARD_MCP_DISABLED` | MCP | `1` to disable the MCP CLI subcommand entirely |
| `CIGUARD_MCP_ROOT` | MCP | Workspace allowlist — paths outside are rejected before redaction |
| `CIGUARD_WEB_TOKEN` | Web UI | Bearer token required on every Web UI request when set |
| `CIGUARD_NO_SCANNERS` | CLI | `1` to disable Semgrep / Scorecard / GitLab-native integrations |

## 12. Pre-flight checklist

Before opening the public install link:

- [ ] App registered with the four (not five) permissions from Section 2.1
- [ ] Cycle 1.5 self-pentest closed green (or the equivalent for your fork) — see `Project ciguard/Pentest Reports/2026-05-03-cycle-1.5.md` for the Cycle 1.5 reference
- [ ] Process running as a dedicated non-root UID (Section 4)
- [ ] Reverse proxy terminating TLS (Section 5)
- [ ] systemd hardening directives in place (Section 6) OR container running with `--cap-drop=ALL --security-opt no-new-privileges` (Section 7)
- [ ] `CIGUARD_APP_PRIVATE_KEY_PATH` file is `0600`-mode owned by the process UID (Section 3.1)
- [ ] Backup of `CIGUARD_APP_STORAGE_ROOT` configured (Section 8)
- [ ] Alerting on `/webhook` 401 rate, 503 rate, and repeated `set_check_run_failed` (Section 9)
- [ ] First webhook from a real install seen — `/healthz` returns 200, signed-ping returns 202, unsigned-ping returns 401

When all eleven boxes tick, the App is ready for production.
