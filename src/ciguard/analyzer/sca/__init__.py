"""SCA (Software Composition Analysis) enrichment for ciguard pipelines (v0.6.0).

Adds CVE / EOL awareness to existing pipeline findings without becoming a full
SCA tool. We scan what is *referenced inside the pipeline* (container images,
language runtime tags) — we do NOT scan the user's runtime application
dependencies (`requirements.txt`, `package.json`, etc.). That's a different
product space owned by Snyk / Dependabot / Nexus IQ; we complement, we don't
compete.

The headline use-case is end-of-life detection: pipelines accumulate
`python:3.9-slim`, `node:16-alpine`, `debian:11-slim` references that quietly
go EOL and stay in production for years afterwards. ciguard now flags these.
"""
