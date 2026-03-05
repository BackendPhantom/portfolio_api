# ---------------------------------------------------------------------------
# Backward-compatibility shim.
# All throttle classes now live in commons.throttles — import from there.
# ---------------------------------------------------------------------------
from commons.throttles import ContactRateThrottle  # noqa: F401
