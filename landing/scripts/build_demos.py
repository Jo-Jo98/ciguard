"""Build the demo HTML artifacts that ciguard.dev embeds + screenshots.

Runs against the self-contained fixtures under `landing/demo-fixtures/`
and writes outputs into `landing/public/demos/`. Re-runnable in CI from
the landing-deploy workflow before the Astro build, so the demos can
never go stale relative to the shipped engine version.

Outputs:
  - per-pipeline-bad.html   — html-interactive of the deliberately-flawed
                              GitLab pipeline (3a hero demo)
  - monolith.html           — html-interactive of the monolith fixture
                              pipeline (3c left)
  - microservices-worker.html
                            — html-interactive of the microservices worker
                              pipeline (3c right) — the one that drifts
  - topology.html           — topology --format html on the sample fixture
  - inventory.html          — synthetic InventoryReport rendered via the
                              real reporter (live admin APIs not required
                              for demo purposes; the shape is real)
  - org-dashboard.html      — synthetic OrgAuditReport built from the
                              monolith + microservices scans, rendered via
                              the real reporter

Run: `python landing/scripts/build_demos.py`
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ciguard.audit_org.images import extract_repo_images  # noqa: E402
from ciguard.repo_scan import scan_one, scan_repo  # noqa: E402
from ciguard.reporter import (  # noqa: E402
    html_interactive,
    inventory_html,
    org_audit_html,
    topology_html,
)
from ciguard.models.inventory import InventoryEntry, InventoryReport  # noqa: E402
from ciguard.models.org_audit import OrgAuditReport, RepoScanRecord  # noqa: E402
from ciguard.topology.loader import load as load_topology  # noqa: E402

FIXTURES = ROOT / "landing" / "demo-fixtures"
OUT = ROOT / "landing" / "public" / "demos"


def _per_pipeline_demo() -> None:
    report = scan_one(
        FIXTURES / "per-pipeline" / ".gitlab-ci.yml",
        offline=True,
    )
    (OUT / "per-pipeline-bad.html").write_text(
        html_interactive.render(report), encoding="utf-8"
    )


def _monolith_vs_microservices() -> None:
    mono_report = scan_one(
        FIXTURES / "monolith" / ".gitlab-ci.yml", offline=True,
    )
    (OUT / "monolith.html").write_text(
        html_interactive.render(mono_report), encoding="utf-8"
    )

    worker_report = scan_one(
        FIXTURES / "microservices" / "services" / "worker" / ".gitlab-ci.yml",
        offline=True,
    )
    (OUT / "microservices-worker.html").write_text(
        html_interactive.render(worker_report), encoding="utf-8"
    )


def _topology_demo() -> None:
    topology = load_topology(FIXTURES / "ciguard.topology.yml")
    (OUT / "topology.html").write_text(
        topology_html.render(topology), encoding="utf-8"
    )


def _inventory_demo() -> None:
    """Synthetic InventoryReport — the live probes need real admin APIs but
    the reporter is data-driven; we feed it a realistic snapshot of what an
    operator might see across a typical CI/CD estate."""
    today = datetime.now(timezone.utc)
    entries = [
        InventoryEntry(
            tool="jenkins", configured=True, base_url="https://jenkins.example.com",
            version="2.426.1", edition="LTS",
            eol_date="2026-04-30", days_until_eol=-3,
            notes=["Past LTS EOL — upgrade to 2.452.x recommended"],
        ),
        InventoryEntry(
            tool="gitlab-self-host", configured=True,
            base_url="https://gitlab.example.com",
            version="16.11.0", edition="Enterprise",
            eol_date="2026-09-22", days_until_eol=142,
            notes=["Within LTS support window"],
        ),
        InventoryEntry(
            tool="github-enterprise", configured=True,
            base_url="https://github.example.com",
            version="3.13.4",
            eol_date="2026-08-15", days_until_eol=104,
        ),
        InventoryEntry(
            tool="nexus", configured=True,
            base_url="https://nexus.example.com",
            version="3.67.1", edition="OSS",
            eol_date=None, days_until_eol=None,
            notes=["No EOL data — endoflife.date does not track Nexus OSS"],
        ),
        InventoryEntry(
            tool="artifactory", configured=True,
            base_url="https://artifactory.example.com",
            version="7.77.5", edition="Pro",
            eol_date="2027-01-15", days_until_eol=257,
        ),
        InventoryEntry(
            tool="sonarqube", configured=True,
            base_url="https://sonar.example.com",
            version="10.4.1", edition="Community",
            eol_date="2026-12-31", days_until_eol=242,
        ),
        InventoryEntry(
            tool="argocd", configured=True,
            base_url="https://argocd.example.com",
            version="2.10.5",
            eol_date="2026-08-30", days_until_eol=119,
        ),
        InventoryEntry(
            tool="harbor", configured=True,
            base_url="https://harbor.example.com",
            version="2.10.2",
            eol_date="2026-11-13", days_until_eol=194,
        ),
    ]
    report = InventoryReport(
        scan_timestamp=today.isoformat(),
        entries=entries,
    )
    (OUT / "inventory.html").write_text(
        inventory_html.render(report), encoding="utf-8"
    )


def _org_dashboard_demo() -> None:
    """Synthetic OrgAuditReport built from real scan-repo runs against
    the monolith + microservices fixtures. The org dashboard is then a
    real reporter rendering real scan output, just stitched into a
    synthetic org-shape rather than fetched from GitHub."""
    monolith_scan = scan_repo(FIXTURES / "monolith", offline=True)
    micro_scan = scan_repo(FIXTURES / "microservices", offline=True)

    # Populate per-repo image inventory so the dashboard's image-inventory
    # + pin-discipline panels render. Without this, the synthetic report
    # passes through but the cross-org drift visualisation is suppressed.
    monolith_images = extract_repo_images(FIXTURES / "monolith")
    micro_images = extract_repo_images(FIXTURES / "microservices")

    repos = [
        RepoScanRecord(
            repo="example-org/monolith",
            default_branch="main",
            description="Single-deployable monolithic application",
            scan=monolith_scan,
            pipeline_file_count=monolith_scan.get("files_scanned", 0),
            images=monolith_images,
        ),
        RepoScanRecord(
            repo="example-org/microservices",
            default_branch="main",
            description="Multi-service mesh with per-service pipelines",
            scan=micro_scan,
            pipeline_file_count=micro_scan.get("files_scanned", 0),
            images=micro_images,
        ),
    ]
    report = OrgAuditReport(
        org="example-org",
        provider="github",
        repos=repos,
    )
    (OUT / "org-dashboard.html").write_text(
        org_audit_html.render(report), encoding="utf-8"
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    print("Building demo HTML artifacts...")
    _per_pipeline_demo()
    print(f"  ✓ {OUT / 'per-pipeline-bad.html'}")
    _monolith_vs_microservices()
    print(f"  ✓ {OUT / 'monolith.html'}")
    print(f"  ✓ {OUT / 'microservices-worker.html'}")
    _topology_demo()
    print(f"  ✓ {OUT / 'topology.html'}")
    _inventory_demo()
    print(f"  ✓ {OUT / 'inventory.html'}")
    _org_dashboard_demo()
    print(f"  ✓ {OUT / 'org-dashboard.html'}")

    sizes = {p.name: p.stat().st_size for p in OUT.glob("*.html")}
    print(f"\nGenerated {len(sizes)} demos:")
    for name, size in sorted(sizes.items()):
        print(f"  {name:40s}  {size / 1024:6.1f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
