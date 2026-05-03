"""SCA-PIN-003 — Cross-pipeline image drift (Slice 14c follow-up).

Detects when two or more pipeline files in the same repository reference
the same image NAME with different tag / digest combinations. Auditor
signal: "this repo runs multiple flavours of python across its pipelines —
pick one." Drift is not a security gate; it's a posture-consistency
finding that surfaces in the audit deliverable.

Lives outside `sca_rules.py` because it requires aggregation across
multiple pipeline files in one scan, not a per-file rule. Called from
`repo_scan.scan_repo()` after the per-file scan loop completes.

Severity: Medium. The hosting pipeline's per-file scoring is unaffected;
the finding lands on a new top-level `cross_pipeline_findings` field of
the repo-scan result so it can drive the audit dashboard's drift panel
without distorting individual pipeline grades.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .image_extractor import ImageReference

DRIFT_RULE_ID = "SCA-PIN-003"
DRIFT_RULE_NAME = "Cross-pipeline image drift"
DRIFT_SEVERITY = "Medium"
DRIFT_CATEGORY = "Supply Chain"


@dataclass
class CrossPipelineDrift:
    """A single drift finding — one image name with N variants across M files."""
    rule_id: str
    name: str
    severity: str
    category: str
    image_name: str
    variants: List[Dict[str, object]]   # [{raw, tag, digest, files: [...]}]
    files_affected: List[str]
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "category": self.category,
            "image_name": self.image_name,
            "variants": self.variants,
            "files_affected": self.files_affected,
            "message": self.message,
            "remediation": self.remediation,
        }


def _variant_key(ref: ImageReference) -> Tuple[str, str]:
    """Two image references are the SAME variant iff their effective
    target bytes match. We treat `python:3.11.4` and `python:3.11.4@sha256:abc`
    as the SAME variant — the digest is additional pinning of the same
    underlying tag, not a different version. Drift only fires when the
    tag itself differs across files."""
    return (ref.tag or "", ref.digest or "")


def _human_variant(ref: ImageReference) -> str:
    """Render a single ImageReference for the variants table."""
    bits = []
    if ref.registry:
        bits.append(ref.registry + "/")
    bits.append(ref.name)
    if ref.tag:
        bits.append(":" + ref.tag)
    if ref.digest:
        bits.append("@sha256:" + ref.digest[:12] + "…")
    return "".join(bits)


def detect_drift(
    file_image_pairs: Sequence[Tuple[str, ImageReference]],
) -> List[CrossPipelineDrift]:
    """Group image references by canonical name across files; emit one
    drift finding per name that has >1 distinct variant across >1 file.

    `file_image_pairs` is `[(rel_path, ImageReference), ...]` — the same
    image referenced from two different files counts twice."""
    # name → variant_key → list[(file, ref)]
    by_name: Dict[str, Dict[Tuple[str, str], List[Tuple[str, ImageReference]]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for path, ref in file_image_pairs:
        by_name[ref.name][_variant_key(ref)].append((path, ref))

    drifts: List[CrossPipelineDrift] = []
    for name, variants in by_name.items():
        if len(variants) < 2:
            continue
        # Drift only counts if the variants are spread across >1 distinct
        # file. Two `python:3.9` and one `python:3.10` in the SAME file is
        # noise inside a single pipeline — drift is the cross-file shape.
        files_per_variant = {
            vkey: {p for p, _ in entries}
            for vkey, entries in variants.items()
        }
        all_files = set().union(*files_per_variant.values())
        if len(all_files) < 2:
            continue

        variant_dicts: List[Dict[str, object]] = []
        for vkey, entries in sorted(variants.items()):
            sample_ref = entries[0][1]
            variant_dicts.append({
                "label": _human_variant(sample_ref),
                "tag": sample_ref.tag,
                "digest": sample_ref.digest,
                "files": sorted({p for p, _ in entries}),
                "occurrences": len(entries),
            })

        files_affected = sorted(all_files)
        n_variants = len(variants)
        n_files = len(files_affected)
        message = (
            f"Image '{name}' is referenced with {n_variants} different "
            f"variants across {n_files} pipeline files. Inconsistent "
            "versions across pipelines mean different runners boot "
            "different runtimes; CVEs patched in one variant may still "
            "be live in another."
        )
        remediation = (
            f"Pick one variant of '{name}' as the canonical version for "
            "this repo and align every pipeline file. If different "
            "pipelines genuinely need different runtimes (e.g. matrix "
            "Python testing), document the rationale in the pipeline "
            "files so the divergence is intentional rather than drift."
        )
        drifts.append(CrossPipelineDrift(
            rule_id=DRIFT_RULE_ID,
            name=DRIFT_RULE_NAME,
            severity=DRIFT_SEVERITY,
            category=DRIFT_CATEGORY,
            image_name=name,
            variants=variant_dicts,
            files_affected=files_affected,
            message=message,
            remediation=remediation,
        ))

    drifts.sort(key=lambda d: (-len(d.files_affected), d.image_name))
    return drifts
