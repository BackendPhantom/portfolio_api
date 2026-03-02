import logging

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.utils.html import escape

logger = logging.getLogger(__name__)


def _glassmorphism_email(title, body_html):
    """
    Wrap email content in a minimal glassmorphism-styled HTML template.
    """
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{escape(title)}</title>
</head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
             background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="min-height:100vh;">
    <tr>
      <td align="center" valign="middle" style="padding:40px 16px;">

        <!-- Glass card -->
        <table role="presentation" width="520" cellpadding="0" cellspacing="0"
               style="max-width:520px;width:100%;
                      background:rgba(255,255,255,0.08);
                      border:1px solid rgba(255,255,255,0.18);
                      border-radius:16px;
                      box-shadow:0 8px 32px rgba(0,0,0,0.37);
                      backdrop-filter:blur(12px);
                      -webkit-backdrop-filter:blur(12px);">
          <tr>
            <td style="padding:40px 36px;">

              <!-- Title -->
              <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;
                         color:#ffffff;letter-spacing:-0.3px;">
                {escape(title)}
              </h1>
              <hr style="border:none;height:1px;
                         background:linear-gradient(90deg,rgba(255,255,255,0.3),
                         rgba(255,255,255,0.05));margin:0 0 28px;" />

              <!-- Body -->
              {body_html}

            </td>
          </tr>
        </table>
        <!-- / Glass card -->

        <!-- Footer -->
        <p style="margin:24px 0 0;font-size:12px;color:rgba(255,255,255,0.35);
                  text-align:center;">
          &copy; Portfolio API &bull; This is an automated message
        </p>

      </td>
    </tr>
  </table>
</body>
</html>"""


def _button(url, label):
    """Render a glassmorphism-styled CTA button."""
    return (
        f'<a href="{escape(url)}" target="_blank" '
        f'style="display:inline-block;margin:28px 0 24px;padding:14px 32px;'
        f"font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;"
        f"border-radius:10px;letter-spacing:0.3px;"
        f"background:rgba(255,255,255,0.12);"
        f"border:1px solid rgba(255,255,255,0.25);"
        f'box-shadow:0 4px 16px rgba(0,0,0,0.25);">'
        f"{escape(label)}</a>"
    )


def _text(content):
    """Render a paragraph of body text."""
    return (
        f'<p style="margin:0 0 14px;font-size:15px;line-height:1.7;'
        f'color:rgba(255,255,255,0.75);">{content}</p>'
    )


def _muted(content):
    """Render muted / secondary text."""
    return (
        f'<p style="margin:0;font-size:13px;line-height:1.6;'
        f'color:rgba(255,255,255,0.4);">{content}</p>'
    )


# ──────────────────────────────────────────────
# Tasks
# ──────────────────────────────────────────────


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
    subject = "Verify your email address"
    plain = (
        f"Welcome to our platform!\n\n"
        f"Please click the following link to verify your email address:\n"
        f"{verify_url}\n\n"
        f"This link will expire in 24 hours.\n\n"
        f"If you didn't create this account, please ignore this email."
    )
    html = _glassmorphism_email(
        subject,
        _text(
            "Welcome to our platform! Please verify your email address "
            "to get started."
        )
        + _button(verify_url, "Verify Email Address")
        + _muted("This link will expire in 24 hours.")
        + _muted("If you didn't create this account, please ignore this email."),
    )
    try:
        send_mail(
            subject=subject,
            message=plain,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html,
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
    subject = "Password Reset Request"
    plain = (
        f"Click the following link to reset your password:\n"
        f"{reset_url}\n\n"
        f"This link will expire in 24 hours.\n\n"
        f"If you didn't request this, please ignore this email."
    )
    html = _glassmorphism_email(
        subject,
        _text(
            "We received a request to reset your password. "
            "Click the button below to choose a new one."
        )
        + _button(reset_url, "Reset Password")
        + _muted("This link will expire in 24 hours.")
        + _muted("If you didn't request this, please ignore this email."),
    )
    try:
        send_mail(
            subject=subject,
            message=plain,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            html_message=html,
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
    safe_name = escape(user_name)
    subject = "Welcome to Portfolio API!"
    plain = (
        f"Hi {user_name},\n\n"
        f"Your email has been verified. Welcome aboard!\n\n"
        f"Start building your portfolio by adding projects and skills."
    )
    html = _glassmorphism_email(
        subject,
        _text(f'Hi <strong style="color:#ffffff;">{safe_name}</strong>,')
        + _text("Your email has been verified — welcome aboard! 🎉")
        + _text("Start building your portfolio by adding projects and skills."),
    )
    send_mail(
        subject=subject,
        message=plain,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        html_message=html,
        fail_silently=True,  # Non-critical, don't retry
    )
