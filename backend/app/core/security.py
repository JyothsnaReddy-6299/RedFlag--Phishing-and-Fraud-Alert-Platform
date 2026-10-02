"""Security basics (contract section 19, P0 row "Security basics").

  * In-memory sliding-window rate limiting per client IP per endpoint group.
  * Request body size ceiling.
  * Safe error handler: never leak stack traces or internal paths.
  * Standard hardening response headers.

Deliberately dependency-free so the demo cannot fail on a missing Redis.
For multi-worker production, swap `_HITS` for a shared store.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger("redflag.security")

MAX_BODY_BYTES = int(os.getenv("REDFLAG_MAX_BODY_BYTES", str(10 * 1024 * 1024)))

# (requests, window_seconds) per bucket
LIMITS: Dict[str, Tuple[int, int]] = {
    "analyze": (int(os.getenv("REDFLAG_RATE_ANALYZE", "30")), 60),
    "report": (int(os.getenv("REDFLAG_RATE_REPORT", "10")), 60),
    "read": (int(os.getenv("REDFLAG_RATE_READ", "240")), 60),
}

_HITS: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)


def _bucket(path: str, method: str) -> str:
    if "/analyze" in path or "/scan" in path:
        return "analyze"
    if "/reports" in path and method == "POST":
        return "report"
    return "read"


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("x-correlation-id") or uuid.uuid4().hex[:16]

        # --- body size ceiling
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return JSONResponse(status_code=413, content={
                "detail": f"Request too large. Limit is {MAX_BODY_BYTES // (1024*1024)} MB.",
                "correlation_id": correlation_id})

        # --- rate limiting (skip docs/static)
        path = request.url.path
        if path.startswith(("/api", "/health")):
            bucket = _bucket(path, request.method)
            limit, window = LIMITS[bucket]
            key = (_client_ip(request), bucket)
            now = time.time()
            hits = _HITS[key]
            while hits and now - hits[0] > window:
                hits.popleft()
            if len(hits) >= limit:
                retry = int(window - (now - hits[0])) + 1
                return JSONResponse(status_code=429, headers={"Retry-After": str(retry)},
                                    content={
                                        "detail": (f"Rate limit reached for {bucket} requests "
                                                   f"({limit} per {window}s). Try again in "
                                                   f"{retry}s."),
                                        "correlation_id": correlation_id})
            hits.append(now)

        try:
            response = await call_next(request)
        except Exception:
            # Safe error: log internally with the correlation id, return nothing sensitive.
            log.exception("Unhandled error [%s] %s %s", correlation_id,
                          request.method, path)
            return JSONResponse(status_code=500, content={
                "detail": "An internal error occurred. Nothing was saved.",
                "correlation_id": correlation_id})

        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
        return response
