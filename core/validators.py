"""
Reusable field validators for file uploads.
"""

from django.core.exceptions import ValidationError


def validate_file_size(value, max_mb=5):
    """Reject files larger than *max_mb* megabytes."""
    max_bytes = max_mb * 1024 * 1024
    if value.size > max_bytes:
        raise ValidationError(
            f"File size must not exceed {max_mb} MB. "
            f"Current size: {value.size / (1024 * 1024):.1f} MB."
        )


def validate_image_file_type(value):
    """
    Reject files that are not JPEG, PNG, WebP, or GIF.

    Uses the file's magic bytes rather than the extension so
    a renamed ``.exe`` won't slip through.
    """
    allowed_types = {
        b"\xff\xd8\xff": "image/jpeg",
        b"\x89PNG": "image/png",
        b"RIFF": "image/webp",  # WebP starts with RIFF
        b"GIF8": "image/gif",
    }

    header = value.read(12)
    value.seek(0)

    for magic, mime in allowed_types.items():
        if header.startswith(magic):
            return

    # Special check for WebP (RIFF....WEBP)
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return

    raise ValidationError("Unsupported file type. Allowed: JPEG, PNG, WebP, GIF.")
