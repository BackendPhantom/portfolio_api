"""
Custom middleware for the portfolio API.
"""

import logging
import time

from django.middleware.csrf import CsrfViewMiddleware

logger = logging.getLogger("api.requests")


# =========================================================================
# CSRF exemption for API routes
# =========================================================================
class CSRFExemptAPIMiddleware(CsrfViewMiddleware):
    """
    Skip CSRF checks for ``/api/`` routes.

    API endpoints use header-based auth (``Authorization: Bearer …`` or
    ``X-API-Key: …``) which is not vulnerable to CSRF.  Server-rendered
    pages (admin, frontend templates) still receive full CSRF protection.
    """

    def process_view(self, request, callback, callback_args, callback_kwargs):
        if request.path.startswith("/api/"):
            return None
        return super().process_view(request, callback, callback_args, callback_kwargs)


# =========================================================================
# Request / response logging
# =========================================================================
class RequestLoggingMiddleware:
    """
    Logs every request's method, path, status code, and duration.

    Slow requests (>1 s) are logged at WARNING level.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.monotonic()

        response = self.get_response(request)

        duration = time.monotonic() - start
        logger.info(
            "%s %s %s %.3fs",
            request.method,
            request.get_full_path(),
            response.status_code,
            duration,
        )

        if duration > 1.0:
            logger.warning(
                "SLOW REQUEST: %s %s took %.3fs",
                request.method,
                request.get_full_path(),
                duration,
            )

        return response
