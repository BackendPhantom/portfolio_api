import logging

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,  # Retry after 60 seconds
)
def send_verification_email(self, user_email, verify_url):
    """
    Send email verification link asynchronously.

    Retries up to 3 times if sending fails.
    """
    try:
        send_mail(
            subject="Verify your email address",
            message=(
                f"Welcome to our platform!\n\n"
                f"Please click the following link to verify your email address:\n"
                f"{verify_url}\n\n"
                f"This link will expire in 24 hours.\n\n"
                f"If you didn't create this account, please ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            fail_silently=False,
        )
        logger.info(f"Verification email sent to {user_email}")
        return True
    except Exception as exc:
        logger.error(f"Failed to send verification email to {user_email}: {exc}")
        # Retry the task
        raise self.retry(exc=exc)


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def send_password_reset_email(self, user_email, reset_url):
    """
    Send password reset link asynchronously.
    """
    try:
        send_mail(
            subject="Password Reset Request",
            message=(
                f"Click the following link to reset your password:\n"
                f"{reset_url}\n\n"
                f"This link will expire in 24 hours.\n\n"
                f"If you didn't request this, please ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            fail_silently=False,
        )
        logger.info(f"Password reset email sent to {user_email}")
        return True
    except Exception as exc:
        logger.error(f"Failed to send password reset email to {user_email}: {exc}")
        raise self.retry(exc=exc)


@shared_task
def send_welcome_email(user_email, user_name):
    """
    Send welcome email after account verification.
    """
    send_mail(
        subject="Welcome to Portfolio API!",
        message=(
            f"Hi {user_name},\n\n"
            f"Your email has been verified. Welcome aboard!\n\n"
            f"Start building your portfolio by adding projects and skills."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=True,  # Non-critical, don't retry
    )
