"""
Custom DRF exception handler that normalises every error response
into a consistent envelope:

    {
        "success": false,
        "status_code": 400,
        "message": "Validation failed.",
        "errors": { ... }          # optional, for field-level errors
    }
"""

from rest_framework.views import exception_handler as drf_exception_handler


def custom_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)

    if response is None:
        return None

    normalised = {
        "success": False,
        "status_code": response.status_code,
    }

    if isinstance(response.data, dict):
        if "detail" in response.data:
            normalised["message"] = str(response.data["detail"])
        elif "error" in response.data:
            # Our own views sometimes use {"error": "..."}
            normalised["message"] = str(response.data["error"])
        else:
            # Field-level validation errors
            normalised["message"] = "Validation failed."
            normalised["errors"] = response.data
    elif isinstance(response.data, list):
        normalised["message"] = (
            str(response.data[0]) if response.data else "An error occurred."
        )
        normalised["errors"] = response.data
    else:
        normalised["message"] = str(response.data)

    response.data = normalised
    return response
