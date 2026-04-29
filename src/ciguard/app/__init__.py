"""ciguard GitHub App — v0.10.0 (in development).

Receives GitHub webhooks, exchanges JWTs for installation-scoped tokens, runs
ciguard scans on PR head SHAs, and posts results back as Check Runs + PR
comments. See `Project ciguard/THREAT_MODEL.md` Surface 9 for the threat
model that informs every design decision in this package.
"""
