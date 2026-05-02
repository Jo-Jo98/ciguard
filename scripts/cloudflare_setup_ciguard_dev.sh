#!/usr/bin/env bash
# Cloudflare DNS hardening for ciguard.dev — CAA + (optional) DNSSEC.
#
# Idempotent: re-running is safe. Existing matching records are detected
# and skipped rather than duplicated. New records are added; nothing is
# overwritten or deleted unless you pass --remove-extra (off by default).
#
# Why this exists:
#   The Layer-1 landing-page pentest (Pentest Reports/2026-05-02-landing-page.md)
#   flagged LANDING-002 — no CAA records on ciguard.dev — meaning any
#   publicly-trusted CA can issue a cert. CAA records pin issuance to a
#   named allowlist (Google Trust Services + Let's Encrypt + DigiCert
#   here, matching Cloudflare Pages's auto-provisioner) and add an
#   `iodef` reporting channel so unauthorised issuance attempts page us.
#
# Companion DNSSEC enable (opt-in via --enable-dnssec) closes the
# "hijack DNS, remove CAA, then issue rogue cert" path that CAA alone
# leaves open. DNSSEC requires a one-time DS-record publication at the
# registrar — since registrar = Cloudflare here, that's a one-click on
# the dashboard AFTER this script enables DNSSEC on the zone.
#
# Usage:
#   export CLOUDFLARE_API_TOKEN=cfut_...    # token with Zone:DNS:Edit
#                                            # (+ Zone:Zone Settings:Edit for DNSSEC)
#   ./scripts/cloudflare_setup_ciguard_dev.sh [--dry-run] [--enable-dnssec]
#
# Required token scopes:
#   - Zone → DNS → Edit on ciguard.dev (always)
#   - Zone → Zone Settings → Edit on ciguard.dev (only with --enable-dnssec)
#
# What this does NOT do:
#   - Does NOT publish the DS record at the registrar. After --enable-dnssec
#     enables DNSSEC on the zone, Cloudflare gives you a DS record value;
#     the script prints it and tells you exactly where to paste it.
#   - Does NOT remove existing records (unless --remove-extra is passed).
#     If you have CAA records already and want to fully reset, use the
#     dashboard.
#   - Does NOT issue/renew any certificates. CAA only affects FUTURE
#     issuance — existing certs keep working.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config — edit if you fork this for a different domain
# ---------------------------------------------------------------------------
ZONE_NAME="ciguard.dev"
IODEF_EMAIL="info@bleeblue.com"
ALLOWED_CAS=(
  "google.com"        # Google Trust Services — current cert issuer
  "letsencrypt.org"   # Let's Encrypt — Cloudflare alternative
  "digicert.com"      # DigiCert — Cloudflare fallback
)

# ---------------------------------------------------------------------------
# CLI flags
# ---------------------------------------------------------------------------
DRY_RUN=0
ENABLE_DNSSEC=0
REMOVE_EXTRA=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --enable-dnssec) ENABLE_DNSSEC=1 ;;
    --remove-extra) REMOVE_EXTRA=1 ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "Error: CLOUDFLARE_API_TOKEN env var is not set." >&2
  echo "Mint one at https://dash.cloudflare.com/profile/api-tokens" >&2
  echo "with scope: Zone → DNS → Edit (resource: $ZONE_NAME only)." >&2
  exit 1
fi

API="https://api.cloudflare.com/client/v4"
AUTH=(-H "Authorization: Bearer $CLOUDFLARE_API_TOKEN")

# ---------------------------------------------------------------------------
# Helper: cf_get / cf_post / cf_patch / cf_delete — wrap curl + jq-via-python3
# ---------------------------------------------------------------------------
cf_call() {
  local method="$1"; shift
  local path="$1"; shift
  local body="${1:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "${AUTH[@]}" -H "Content-Type: application/json" \
      "$API$path" -d "$body"
  else
    curl -sS -X "$method" "${AUTH[@]}" "$API$path"
  fi
}

# pyjq — extract a value from a Cloudflare API response.
#   pyjq '.result[].name' '<json>'
pyjq() {
  local expr="$1"; shift
  python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
expr = '''$expr'''
def walk(node, parts):
    if not parts: return [node]
    head, rest = parts[0], parts[1:]
    if head == '[]':
        out = []
        for item in (node or []): out.extend(walk(item, rest))
        return out
    return walk(node.get(head, {}) if isinstance(node, dict) else None, rest)
parts = [p for p in expr.lstrip('.').replace('[]', '|[]|').split('|') if p]
parts = [p.lstrip('.') if p != '[]' else p for p in parts]
result = walk(d, parts)
for r in result:
    if isinstance(r, (dict, list)): print(json.dumps(r))
    elif r is None: pass
    else: print(r)
"
}

# ---------------------------------------------------------------------------
# Token verify (fail-fast)
# ---------------------------------------------------------------------------
echo "==> Verifying API token..."
verify_resp=$(cf_call GET /user/tokens/verify)
if ! echo "$verify_resp" | python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get('success') else 1)"; then
  echo "Error: token verify failed:" >&2
  echo "$verify_resp" | python3 -m json.tool >&2
  exit 1
fi
expires=$(echo "$verify_resp" | pyjq '.result.expires_on')
echo "    token: active${expires:+, expires $expires}"

# ---------------------------------------------------------------------------
# Resolve zone ID by name (don't hardcode — survives zone recreation)
# ---------------------------------------------------------------------------
echo "==> Resolving zone id for $ZONE_NAME..."
zone_resp=$(cf_call GET "/zones?name=$ZONE_NAME")
ZONE_ID=$(echo "$zone_resp" | pyjq '.result.[].id' | head -1)
if [[ -z "$ZONE_ID" ]]; then
  echo "Error: zone $ZONE_NAME not found on this account, or token lacks zone:read." >&2
  exit 1
fi
echo "    zone id: $ZONE_ID"

# ---------------------------------------------------------------------------
# Read current CAA records on the apex
# ---------------------------------------------------------------------------
echo "==> Reading current CAA records..."
existing_resp=$(cf_call GET "/zones/$ZONE_ID/dns_records?type=CAA&name=$ZONE_NAME")
existing_count=$(echo "$existing_resp" | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('result',[])))")
echo "    found $existing_count existing CAA record(s)"
if [[ "$existing_count" -gt 0 ]]; then
  echo "$existing_resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d.get('result', []):
    data = r.get('data', {})
    print(f'    - flags={data.get(\"flags\",\"?\")} tag={data.get(\"tag\",\"?\"):8s} value={data.get(\"value\",\"?\")}')
"
fi

# ---------------------------------------------------------------------------
# Build desired record list + diff against existing
# ---------------------------------------------------------------------------
declare -a DESIRED=()
for ca in "${ALLOWED_CAS[@]}"; do
  DESIRED+=("issue|$ca")
done
DESIRED+=("iodef|mailto:$IODEF_EMAIL")

# Helper: existing-set check
record_exists() {
  local tag="$1"; local value="$2"
  echo "$existing_resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
target_tag = '$tag'
target_value = '$value'
for r in d.get('result', []):
    data = r.get('data', {})
    if data.get('tag') == target_tag and data.get('value') == target_value:
        sys.exit(0)
sys.exit(1)
"
}

echo
echo "==> Reconciling desired vs existing CAA records..."
for spec in "${DESIRED[@]}"; do
  tag="${spec%%|*}"
  value="${spec#*|}"
  if record_exists "$tag" "$value"; then
    echo "    ✓ already present: $tag $value"
    continue
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "    [dry-run] would add: $tag $value"
    continue
  fi
  echo "    + adding:           $tag $value"
  body=$(python3 -c "
import json
print(json.dumps({
    'type': 'CAA',
    'name': '$ZONE_NAME',
    'data': {'flags': 0, 'tag': '$tag', 'value': '$value'},
    'ttl': 3600,
}))
")
  add_resp=$(cf_call POST "/zones/$ZONE_ID/dns_records" "$body")
  if ! echo "$add_resp" | python3 -c "import json,sys;sys.exit(0 if json.load(sys.stdin).get('success') else 1)"; then
    echo "      Error adding record:" >&2
    echo "$add_resp" | python3 -m json.tool >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# DNSSEC (opt-in)
# ---------------------------------------------------------------------------
if [[ "$ENABLE_DNSSEC" -eq 1 ]]; then
  echo
  echo "==> DNSSEC: enabling on zone..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "    [dry-run] would PATCH /zones/$ZONE_ID/dnssec status=active"
  else
    dnssec_resp=$(cf_call PATCH "/zones/$ZONE_ID/dnssec" '{"status":"active"}')
    if echo "$dnssec_resp" | python3 -c "import json,sys;sys.exit(0 if json.load(sys.stdin).get('success') else 1)"; then
      echo "    DNSSEC enabled. Cloudflare-signed records ready."
      echo
      echo "    DS record to publish at registrar:"
      echo "$dnssec_resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)['result']
print(f'      key tag:     {d.get(\"key_tag\")}')
print(f'      algorithm:   {d.get(\"algorithm\")}')
print(f'      digest type: {d.get(\"digest_type\")}')
print(f'      digest:      {d.get(\"digest\")}')
print(f'      DS string:   {d.get(\"ds\")}')
"
      echo
      echo "    Since registrar = Cloudflare, paste this DS record at:"
      echo "    https://dash.cloudflare.com/?to=/:account/registrar/domains/$ZONE_NAME"
      echo "    Domain → DS Records tab → paste the DS string. One-click."
    else
      echo "    Error enabling DNSSEC (may need Zone:Zone Settings:Edit scope):" >&2
      echo "$dnssec_resp" | python3 -m json.tool >&2
      exit 1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Verify (read back)
# ---------------------------------------------------------------------------
echo
echo "==> Verifying final CAA state..."
final_resp=$(cf_call GET "/zones/$ZONE_ID/dns_records?type=CAA&name=$ZONE_NAME")
echo "$final_resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
records = d.get('result', [])
print(f'    {len(records)} CAA record(s) on $ZONE_NAME:')
for r in sorted(records, key=lambda x: (x.get('data',{}).get('tag',''), x.get('data',{}).get('value',''))):
    data = r.get('data', {})
    print(f'      flags={data.get(\"flags\")} tag={data.get(\"tag\"):8s} value={data.get(\"value\")}')
"

echo
echo "==> Independent verification (public DNS — may take 1-2 min to propagate):"
echo "    dig +short ciguard.dev CAA @1.1.1.1"
echo
echo "Done."
