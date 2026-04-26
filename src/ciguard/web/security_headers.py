"""HTTP security headers middleware (added v0.8.2).

Sets the standard set of defence-in-depth headers per the OWASP Secure
Headers Project. Per-path CSP carve-out for `/api/docs` because FastAPI's
auto-generated Swagger UI loads scripts/styles from the jsdelivr CDN.

The Web UI is intended for local-only deployment, but adding these
headers does no harm in that context and provides correct posture if a
user ever fronts ciguard with nginx + LetsEncrypt for a tiny private
team. Future PRD Slice 9 (GitHub App) and Slice 12+ (hosted dashboard)
will carry the same middleware forward.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "interest-cohort=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # COEP intentionally NOT set to require-corp: Swagger UI's
        # cross-origin assets would break, and we have no SharedArrayBuffer
        # use that would benefit from it.

        # Per-path CSP. The Swagger UI at /api/docs needs jsdelivr.
        if request.url.path.startswith("/api/docs") or request.url.path.startswith("/api/redoc"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "font-src 'self' data:; "
                "connect-src 'self'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self' data:; "
                "connect-src 'self'"
            )
        return response


__all__ = ["SecurityHeadersMiddleware"]
