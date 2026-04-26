"""
Cross-platform image extraction.

SCA rules need to know "what container images does this pipeline reference?"
The answer lives in three different model shapes (Pipeline / Workflow /
Jenkinsfile), each with its own conventions for where images appear. This
module flattens them all into a single `ImageReference` list.

We also parse the `name:tag` string into structured fields a downstream
EOL/CVE check can use:
  - `name` — the image name minus registry + tag (e.g. `python` from
    `docker.io/library/python:3.9-slim`).
  - `tag` — the raw tag (e.g. `3.9-slim`).
  - `cycle_id` — the version-like prefix of the tag (e.g. `3.9` from
    `3.9-slim`, `12` from `12.0.4-jdk-21-slim`).
  - `digest` — the `@sha256:...` portion if present.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Union

from ...models.jenkinsfile import Jenkinsfile
from ...models.pipeline import Pipeline
from ...models.workflow import Workflow


# Regex for splitting an image reference into (registry?, name, tag?, digest?).
# Examples it must handle:
#   alpine
#   alpine:3.18
#   python:3.9-slim
#   ghcr.io/jo-jo98/ciguard:0.5.0
#   docker.io/library/maven:3.9.4-eclipse-temurin-21
#   alpine@sha256:abc123...
#   alpine:3.18@sha256:abc123...
_IMAGE_REF_RE = re.compile(
    r"""
    ^
    (?:(?P<registry>[a-zA-Z0-9.\-]+(?::\d+)?)/)?     # optional registry/host:port
    (?P<path>[a-zA-Z0-9._\-/]+?)                     # image path (may contain /)
    (?::(?P<tag>[a-zA-Z0-9._\-]+))?                  # optional :tag
    (?:@(?P<digest>sha256:[a-f0-9]{64}))?            # optional @sha256:digest
    $
    """,
    re.VERBOSE,
)

# Looser tag → cycle extraction. Strips suffixes like `-slim`, `-alpine`,
# `-bullseye`, `-jdk-21`. Result is the leading version-like prefix.
_TAG_VERSION_RE = re.compile(r"^(\d+(?:\.\d+){0,3})")


@dataclass
class ImageReference:
    """A single container image reference found in a pipeline."""
    raw: str                        # original string as written in the pipeline
    location: str                   # where it was found (job/stage path)
    name: str                       # bare image name, lowercase (e.g. "python")
    tag: Optional[str] = None       # raw tag (e.g. "3.9-slim", "latest")
    cycle_id: Optional[str] = None  # version-like prefix of tag (e.g. "3.9")
    digest: Optional[str] = None    # sha256 digest if pinned
    registry: Optional[str] = None  # explicit registry if given (e.g. "ghcr.io")

    @property
    def is_digest_pinned(self) -> bool:
        return self.digest is not None

    @property
    def has_tag(self) -> bool:
        return self.tag is not None and self.tag != ""


def parse_image_reference(raw: str, location: str) -> Optional[ImageReference]:
    """Parse `image:tag@digest` into structured fields. Returns None if
    the string doesn't look like an image reference at all."""
    if not raw or not isinstance(raw, str):
        return None
    m = _IMAGE_REF_RE.match(raw.strip())
    if not m:
        return None
    path = m.group("path") or ""
    if not path:
        return None
    # The bare image name is the last path component, lowercased.
    name = path.split("/")[-1].lower()
    tag = m.group("tag")
    digest = m.group("digest")
    registry = m.group("registry")
    cycle_id = None
    if tag:
        v = _TAG_VERSION_RE.match(tag)
        if v:
            cycle_id = v.group(1)
    return ImageReference(
        raw=raw,
        location=location,
        name=name,
        tag=tag,
        cycle_id=cycle_id,
        digest=digest,
        registry=registry,
    )


def extract_images(target: Union[Pipeline, Workflow, Jenkinsfile]) -> List[ImageReference]:
    """Walk a parsed pipeline / workflow / Jenkinsfile and return every
    image reference encountered, structured for SCA lookups."""
    if isinstance(target, Pipeline):
        return _extract_from_pipeline(target)
    if isinstance(target, Workflow):
        return _extract_from_workflow(target)
    if isinstance(target, Jenkinsfile):
        return _extract_from_jenkinsfile(target)
    return []


def _extract_from_pipeline(p: Pipeline) -> List[ImageReference]:
    """GitLab CI: every Job has an optional `image` field."""
    out: List[ImageReference] = []
    for job in p.jobs:
        img = getattr(job, "image", None)
        if img:
            ref = parse_image_reference(img, f"job[{job.name}].image")
            if ref:
                out.append(ref)
    # Some pipelines set a default `image` at the top — model-dependent.
    default_img = getattr(p, "default_image", None)
    if default_img:
        ref = parse_image_reference(default_img, "default.image")
        if ref:
            out.append(ref)
    return out


def _extract_from_workflow(wf: Workflow) -> List[ImageReference]:
    """GitHub Actions: container references appear as:
      - `jobs.<id>.container.image` (full container spec)
      - `jobs.<id>.container` as bare string (shorthand)
      - `jobs.<id>.services.<name>.image` (service containers)
    """
    out: List[ImageReference] = []
    for job in wf.jobs:
        container = getattr(job, "container", None)
        if container:
            # container can be a dict-like with `image`, or a string
            container_image = container if isinstance(container, str) else getattr(container, "image", None) or (container.get("image") if isinstance(container, dict) else None)
            if container_image:
                ref = parse_image_reference(container_image, f"job[{job.id or job.name}].container")
                if ref:
                    out.append(ref)
        services = getattr(job, "services", None) or {}
        if isinstance(services, dict):
            for sname, svc in services.items():
                svc_image = svc if isinstance(svc, str) else (svc.get("image") if isinstance(svc, dict) else getattr(svc, "image", None))
                if svc_image:
                    ref = parse_image_reference(svc_image, f"job[{job.id or job.name}].services.{sname}")
                    if ref:
                        out.append(ref)
    return out


def _extract_from_jenkinsfile(jf: Jenkinsfile) -> List[ImageReference]:
    """Jenkins: docker agents at the top level or per-stage carry an image."""
    out: List[ImageReference] = []
    if jf.agent and jf.agent.image:
        ref = parse_image_reference(jf.agent.image, "pipeline.agent")
        if ref:
            out.append(ref)
    for stage in jf.stages:
        if stage.agent and stage.agent.image:
            ref = parse_image_reference(stage.agent.image, f"stage[{stage.name}].agent")
            if ref:
                out.append(ref)
        for sub in stage.parallel_stages:
            if sub.agent and sub.agent.image:
                ref = parse_image_reference(
                    sub.agent.image,
                    f"stage[{stage.name}].parallel[{sub.name}].agent",
                )
                if ref:
                    out.append(ref)
    return out
