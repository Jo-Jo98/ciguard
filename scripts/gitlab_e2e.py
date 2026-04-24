"""
GitLab end-to-end driver for ciguard.

Pushes `tests/fixtures/realworld_demo.gitlab-ci.yml` to the project named in
GITLAB_PROJECT (env), waits for the resulting pipeline to finish, downloads
the `gl-*-report.json` artifacts produced by GitLab's built-in security
scanners, and runs ciguard's gitlab_native scanner against them.

Reads from `.env` at the project root: GITLAB_TOKEN, GITLAB_PROJECT.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


DEMO_FILE = ROOT / "tests" / "fixtures" / "realworld_demo.gitlab-ci.yml"
ARTIFACT_DIR = ROOT / "tests" / "corpus_results" / "gitlab_real_artifacts"

API = "https://gitlab.com/api/v4"
SECURITY_JOB_NAMES = ("sast", "secret_detection", "gemnasium-dependency_scanning")


def load_env() -> tuple[str, str]:
    env_path = ROOT / ".env"
    token = project = ""
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == "GITLAB_TOKEN":
            token = v.strip()
        elif k.strip() == "GITLAB_PROJECT":
            project = v.strip()
    if not token or not project:
        sys.exit("ERROR: GITLAB_TOKEN or GITLAB_PROJECT missing from .env")
    return token, project


def req(method: str, url: str, token: str, *, data: bytes | None = None,
        content_type: str | None = None, accept: str = "application/json") -> tuple[int, bytes]:
    req_obj = urllib.request.Request(url, method=method, data=data)
    req_obj.add_header("PRIVATE-TOKEN", token)
    if content_type:
        req_obj.add_header("Content-Type", content_type)
    req_obj.add_header("Accept", accept)
    try:
        with urllib.request.urlopen(req_obj, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def project_id(token: str, project: str) -> int:
    enc = urllib.parse.quote(project, safe="")
    code, body = req("GET", f"{API}/projects/{enc}", token)
    if code != 200:
        sys.exit(f"ERROR: GET project failed ({code}): {body[:300]!r}")
    return json.loads(body)["id"]


def file_exists(token: str, pid: int, path: str, branch: str) -> bool:
    enc = urllib.parse.quote(path, safe="")
    code, _ = req("GET", f"{API}/projects/{pid}/repository/files/{enc}?ref={branch}", token)
    return code == 200


def commit_files(token: str, pid: int, branch: str, files: dict[str, str], message: str) -> str:
    """Atomic multi-file commit. files = {path: content}. create-or-update per file."""
    actions = []
    for path, content in files.items():
        action = "update" if file_exists(token, pid, path, branch) else "create"
        actions.append({"action": action, "file_path": path, "content": content})
    body = json.dumps({"branch": branch, "commit_message": message, "actions": actions}).encode()
    code, resp = req("POST", f"{API}/projects/{pid}/repository/commits", token,
                     data=body, content_type="application/json")
    if code not in (200, 201):
        sys.exit(f"ERROR: commit failed ({code}): {resp[:500]!r}")
    return json.loads(resp)["id"]


# Minimal source-code companions so GitLab's SAST / Secret / Dependency templates
# have something to scan. Each file is intentionally bad in a small, obvious way.
_DEMO_BUNDLE = {
    "app.py": (
        "# Demo app for ciguard E2E. Intentionally contains issues so GitLab\n"
        "# Secret-Detection and SAST analyzers find real things.\n"
        "import sqlite3\n\n"
        "AWS_SECRET_ACCESS_KEY = \"<EXAMPLE-NOT-A-REAL-AWS-SECRET-KEY-PLACEHOLDER>\"  # secret-detection\n"
        "GITHUB_PAT = \"<EXAMPLE-NOT-A-REAL-GITHUB-PAT>\"  # secret-detection\n\n"
        "def get_user(conn, user_id):\n"
        "    # SAST: SQL injection via string concat\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE id = '\" + str(user_id) + \"'\")\n"
        "    return cur.fetchone()\n"
    ),
    "package.json": json.dumps({
        "name": "ciguard-e2e-demo",
        "version": "0.0.1",
        "private": True,
        "dependencies": {
            # Intentionally old version with known CVEs so gemnasium has something to flag.
            "lodash": "4.17.4",
            "minimist": "1.2.0",
        },
    }, indent=2) + "\n",
    "package-lock.json": json.dumps({
        "name": "ciguard-e2e-demo",
        "version": "0.0.1",
        "lockfileVersion": 1,
        "requires": True,
        "dependencies": {
            "lodash": {"version": "4.17.4", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz"},
            "minimist": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"},
        },
    }, indent=2) + "\n",
}


def get_pipeline_for_sha(token: str, pid: int, sha: str, max_wait: int = 60) -> dict:
    """Pipelines are created asynchronously after a push; poll briefly."""
    for _ in range(max_wait // 3):
        code, body = req("GET", f"{API}/projects/{pid}/pipelines?sha={sha}&per_page=1", token)
        if code == 200:
            arr = json.loads(body)
            if arr:
                return arr[0]
        time.sleep(3)
    sys.exit(f"ERROR: no pipeline appeared for sha {sha[:8]} within {max_wait}s")


def wait_for_pipeline(token: str, pid: int, pipeline_id: int, timeout: int = 900) -> dict:
    """Poll pipeline until it's in a terminal state."""
    terminal = {"success", "failed", "canceled", "skipped", "manual"}
    start = time.time()
    last_status = None
    while time.time() - start < timeout:
        code, body = req("GET", f"{API}/projects/{pid}/pipelines/{pipeline_id}", token)
        if code != 200:
            sys.exit(f"ERROR: pipeline poll failed ({code}): {body[:300]!r}")
        p = json.loads(body)
        if p["status"] != last_status:
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:>4d}s] pipeline status: {p['status']}", flush=True)
            last_status = p["status"]
        if p["status"] in terminal:
            return p
        time.sleep(10)
    sys.exit(f"ERROR: pipeline timed out after {timeout}s (last status: {last_status})")


def list_jobs(token: str, pid: int, pipeline_id: int) -> list[dict]:
    jobs = []
    page = 1
    while True:
        code, body = req("GET", f"{API}/projects/{pid}/pipelines/{pipeline_id}/jobs?per_page=100&page={page}", token)
        if code != 200:
            sys.exit(f"ERROR: jobs list failed ({code}): {body[:300]!r}")
        batch = json.loads(body)
        if not batch:
            break
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return jobs


def download_artifacts(token: str, pid: int, job_id: int, dest: Path) -> list[Path]:
    code, body = req("GET", f"{API}/projects/{pid}/jobs/{job_id}/artifacts", token,
                     accept="application/zip")
    if code == 404:
        return []
    if code != 200:
        print(f"  WARN: artifacts download for job {job_id} failed ({code})")
        return []
    extracted = []
    with zipfile.ZipFile(BytesIO(body)) as zf:
        for name in zf.namelist():
            if name.endswith(".json") and name.split("/")[-1].startswith("gl-"):
                target = dest / Path(name).name
                target.write_bytes(zf.read(name))
                extracted.append(target)
    return extracted


def run_ciguard_on_artifacts(artifact_paths: list[Path]) -> None:
    """Use the gitlab_native scanner directly so we get structured results."""
    from ciguard.scanners.gitlab_native import GitLabNativeScanner
    scanner = GitLabNativeScanner()
    print("\n=== ciguard scan of GitLab native security artifacts ===")
    total_findings = 0
    for art in artifact_paths:
        findings = scanner.scan(art)
        print(f"\n  → {art.name}  ({len(findings)} findings)")
        for f in findings[:5]:
            print(f"      [{f.severity.value:8s}] {f.name}")
            if f.evidence:
                ev = f.evidence if len(f.evidence) <= 100 else f.evidence[:97] + "..."
                print(f"          evidence: {ev}")
        if len(findings) > 5:
            print(f"      ... and {len(findings) - 5} more")
        total_findings += len(findings)
    print(f"\nTotal findings across {len(artifact_paths)} artifact files: {total_findings}")


def main() -> int:
    if not DEMO_FILE.exists():
        sys.exit(f"ERROR: demo file not found at {DEMO_FILE}")
    token, project = load_env()
    print(f"Project: {project}")
    pid = project_id(token, project)
    print(f"Project id: {pid}")

    bundle = {".gitlab-ci.yml": DEMO_FILE.read_text(), **_DEMO_BUNDLE}
    print(f"Pushing {len(bundle)} files: {list(bundle.keys())}")
    sha = commit_files(token, pid, "main", bundle,
                       "ciguard E2E: deliberately-bad pipeline + scannable source")
    print(f"Commit: {sha[:12]}")

    print("Waiting for pipeline…")
    pipeline = get_pipeline_for_sha(token, pid, sha)
    pipeline_id = pipeline["id"]
    print(f"Pipeline {pipeline_id}: {pipeline['web_url']}")

    final = wait_for_pipeline(token, pid, pipeline_id)
    print(f"\nFinal pipeline status: {final['status']}")

    jobs = list_jobs(token, pid, pipeline_id)
    print(f"Jobs ({len(jobs)}):")
    for j in jobs:
        print(f"  - {j['name']:50s} status={j['status']:10s} id={j['id']}")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    for f in ARTIFACT_DIR.glob("gl-*.json"):
        f.unlink()  # clean stale artifacts

    artifact_paths: list[Path] = []
    for j in jobs:
        if j["name"] in SECURITY_JOB_NAMES or j["name"].startswith(("sast", "secret_detection", "gemnasium")):
            print(f"\nDownloading artifacts from {j['name']} (id={j['id']}, status={j['status']})…")
            extracted = download_artifacts(token, pid, j["id"], ARTIFACT_DIR)
            for e in extracted:
                print(f"  ✓ {e.name} ({e.stat().st_size} bytes)")
            artifact_paths.extend(extracted)

    if not artifact_paths:
        print("\nWARN: no gl-*-report.json artifacts found. Likely causes:")
        print("  - free-tier shared runners not enabled on this project")
        print("  - security jobs failed before producing artifacts (check pipeline web_url)")
        print("  - GitLab security templates required additional config")
        return 2

    run_ciguard_on_artifacts(artifact_paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
