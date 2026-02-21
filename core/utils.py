"""
Shared utilities used across multiple apps.
"""

import sys
from io import BytesIO

from django.contrib.contenttypes.models import ContentType
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.utils.text import slugify


# =========================================================================
# Unique slug generation
# =========================================================================
def generate_unique_slug(model_class, value, instance=None):
    """
    Generate a slug unique within *model_class*.

    If ``base_slug`` already exists, appends ``-1``, ``-2``, etc.
    When editing an existing instance, excludes its own PK from the check.
    """
    base_slug = slugify(value)
    if not base_slug:
        base_slug = "item"
    slug = base_slug
    counter = 1

    qs = model_class.objects.all()
    if instance and instance.pk:
        qs = qs.exclude(pk=instance.pk)

    while qs.filter(slug=slug).exists():
        slug = f"{base_slug}-{counter}"
        counter += 1

    return slug


# =========================================================================
# Activity logging
# =========================================================================
def log_activity(user, action, instance):
    """
    Create an ``ActivityLog`` entry.

    ``action`` should be one of ``ActivityLog.Action`` values:
    ``"created"``, ``"updated"``, ``"deleted"``.
    """
    from core.models import ActivityLog

    ActivityLog.objects.create(
        user=user,
        action=action,
        content_type=ContentType.objects.get_for_model(instance),
        object_id=str(instance.pk),
        object_repr=str(instance)[:200],
    )


# =========================================================================
# Image optimisation
# =========================================================================
def optimize_image(image_field, max_width=1200, max_height=1200, quality=85):
    """
    Resize and compress an uploaded image to JPEG.

    Returns a new ``InMemoryUploadedFile`` ready to be assigned to a
    model field, or ``None`` if the input is falsy.
    """
    if not image_field:
        return image_field

    try:
        from PIL import Image
    except ImportError:
        # Pillow not installed — return as-is
        return image_field

    img = Image.open(image_field)

    # Convert RGBA/P → RGB for JPEG output
    if img.mode in ("RGBA", "P"):
        img = img.convert("RGB")

    img.thumbnail((max_width, max_height), Image.LANCZOS)

    output = BytesIO()
    img.save(output, format="JPEG", quality=quality, optimize=True)
    output.seek(0)

    name = getattr(image_field, "name", "image.jpg")
    name = f"{name.rsplit('.', 1)[0]}.jpg" if "." in name else f"{name}.jpg"

    return InMemoryUploadedFile(
        output,
        "ImageField",
        name,
        "image/jpeg",
        sys.getsizeof(output),
        None,
    )
