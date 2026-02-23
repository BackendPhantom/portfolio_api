import hashlib
import hmac
import secrets
import uuid
from datetime import timedelta

from django.conf import settings as django_settings
from django.contrib.auth.models import AbstractUser
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField


class User(AbstractUser):
    """
    Custom User model for Developer Portfolio.
    Uses email as the primary identifier and UUID as primary key.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    token_version = models.PositiveIntegerField(default=0)
    refresh_jti = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="SHA-256 hash of the currently valid refresh token's JTI. "
        "Only one refresh token is valid at a time.",
    )

    # -------------------------------------------------------------------------
    # Profile Information
    # -------------------------------------------------------------------------
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    avatar = models.URLField(
        blank=True, help_text="URL to profile picture (can be from social provider)"
    )
    title = models.CharField(
        max_length=100,
        blank=True,
        help_text="Professional title, e.g., 'Full Stack Developer'",
        db_index=True,
    )
    bio = models.TextField(blank=True, help_text="Short biography or about section")
    location = models.CharField(
        max_length=100, blank=True, help_text="City, Country or Remote"
    )
    date_of_birth = models.DateField(null=True, blank=True)
    phone_number = PhoneNumberField(blank=True, help_text="Contact phone number with country code") 
    website = models.URLField(blank=True, help_text="Personal website or portfolio URL")

    # -------------------------------------------------------------------------
    # Social Links
    # -------------------------------------------------------------------------
    github_url = models.URLField(blank=True)
    linkedin_url = models.URLField(blank=True)
    twitter_url = models.URLField(blank=True)

    # -------------------------------------------------------------------------
    # Professional Details
    # -------------------------------------------------------------------------
    years_of_experience = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text="Years of professional experience"
    )
    is_available_for_hire = models.BooleanField(
        default=False, help_text="Open to job opportunities", db_index=True
    )
    is_open_to_freelance = models.BooleanField(
        default=False, help_text="Available for freelance work", db_index=True
    )

    # -------------------------------------------------------------------------
    # Email Verification & Settings
    # -------------------------------------------------------------------------
    email_verified = models.BooleanField(
        default=False, help_text="Whether email has been verified"
    )
    is_profile_public = models.BooleanField(
        default=True, help_text="Whether profile is visible to public", db_index=True
    )

    # -------------------------------------------------------------------------
    # Timestamps
    # -------------------------------------------------------------------------
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["title", "is_available_for_hire"]),
            models.Index(fields=["title", "is_open_to_freelance"]),
            models.Index(fields=["title", "is_profile_public"]),
        ]

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        """Returns the user's full name or email if not set."""
        if self.first_name or self.last_name:
            return f"{self.first_name} {self.last_name}".strip()
        return self.email.split("@")[0]

    @property
    def has_complete_profile(self):
        """Check if user has filled out essential profile fields."""
        return all([self.first_name, self.last_name, self.title, self.bio])


class APIKey(models.Model):
    """
    Long-lived API key for frontend authentication.

    The raw key is shown only once on creation. We store a SHA-256 hash
    so that even a full DB leak does not expose usable credentials.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(
        max_length=100,
        default="default",
        help_text="A friendly label, e.g. 'Frontend App'",
    )
    prefix = models.CharField(
        max_length=8,
        db_index=True,
        help_text="First 8 chars of the key — used for identification in UI",
    )
    key_hash = models.CharField(
        max_length=64,
        unique=True,
        help_text="SHA-256 hex digest of the full API key",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Null means the key never expires",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"

    def __str__(self):
        return f"{self.name} ({self.prefix}…) — {self.user.email}"

    @property
    def is_valid(self):
        """Key is active and not expired."""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    MAX_KEYS_PER_USER = 10

    def record_usage(self):
        """Stamp last_used_at — only writes if >5 min since last stamp."""
        now = timezone.now()
        if self.last_used_at is None or (now - self.last_used_at) > timedelta(
            minutes=5
        ):
            APIKey.objects.filter(pk=self.pk).update(last_used_at=now)

    # ------------------------------------------------------------------
    # Key generation helpers
    # ------------------------------------------------------------------
    _KEY_PREFIX = "dvf"  # DevFolio

    @classmethod
    def hash_key(cls, raw_key: str) -> str:
        """HMAC-SHA256 keyed with Django's SECRET_KEY."""
        return hmac.new(
            key=django_settings.SECRET_KEY.encode(),
            msg=raw_key.encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()

    @classmethod
    def create_key(cls, user, name="default", expires_at=None):
        """
        Generate a new API key for *user*.

        Returns ``(api_key_instance, raw_key)``.
        The raw key is **never stored** — show it to the user once.

        If *expires_at* is not provided, defaults to 1 year from now.
        """
        if expires_at is None:
            expires_at = timezone.now() + timedelta(days=365)

        raw = f"{cls._KEY_PREFIX}_{secrets.token_urlsafe(48)}"
        instance = cls.objects.create(
            user=user,
            name=name,
            prefix=raw[:8],
            key_hash=cls.hash_key(raw),
            expires_at=expires_at,
        )
        return instance, raw

    @classmethod
    def get_or_create_key(cls, user, name="default"):
        """
        Return the user's current active, non-expired key (prefix only)
        or create a fresh one.  Uses ``select_for_update`` inside a
        transaction to avoid race conditions.

        Returns ``(api_key_instance, raw_key_or_none)``.
        ``raw_key`` is only set when a *new* key is created.
        """
        with transaction.atomic():
            existing = (
                cls.objects.select_for_update()
                .filter(user=user, name=name, is_active=True)
                .exclude(expires_at__lt=timezone.now())
                .order_by("-created_at")
                .first()
            )
            if existing:
                return existing, None  # raw key unknown — already issued
            try:
                return cls.create_key(user, name=name)
            except IntegrityError:
                # Lost the race — another request already created it
                return (
                    cls.objects.get(user=user, name=name, is_active=True),
                    None,
                )
