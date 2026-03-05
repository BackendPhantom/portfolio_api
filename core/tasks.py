"""
Centralised Celery email tasks for the entire project.
All apps import from here instead of defining their own task files.

Template design: minimal, monochrome (white / grey / black).
"""

import logging

from celery import shared_task
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, send_mail
from django.utils.html import escape

logger = logging.getLogger(__name__)


# =============================================================================
# Email template helpers
# =============================================================================


def _email(title: str, body_html: str) -> str:
    """
    Wrap body content in a clean, minimal HTML email shell.
    Palette: #111111 (text) · #666666 (muted) · #e5e5e5 (borders) · #f5f5f5 (bg)
    """
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{escape(title)}</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f5;
             font-family:'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif;">

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:48px 16px;">

        <!-- Card -->
        <table role="presentation" width="520" cellpadding="0" cellspacing="0"
               style="max-width:520px;width:100%;
                      background:#ffffff;
                      border:1px solid #e5e5e5;
                      border-radius:8px;">

          <!-- Top accent bar -->
          <tr>
            <td style="height:3px;background:#111111;
                       border-radius:8px 8px 0 0;font-size:0;line-height:0;">
              &nbsp;
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 32px;">
              <h1 style="margin:0 0 20px;font-size:18px;font-weight:600;
                         color:#111111;letter-spacing:-0.2px;line-height:1.3;">
                {escape(title)}
              </h1>
              <hr style="border:none;height:1px;background:#e5e5e5;margin:0 0 24px;" />
              {body_html}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:16px 40px;border-top:1px solid #e5e5e5;
                       background:#fafafa;border-radius:0 0 8px 8px;">
              <p style="margin:0;font-size:12px;color:#aaaaaa;">
                &copy; Portfolio API &bull; Automated message &mdash; do not reply
              </p>
            </td>
          </tr>

        </table>
        <!-- / Card -->

      </td>
    </tr>
  </table>

</body>
</html>"""


def _button(url: str, label: str) -> str:
    """Solid black CTA button."""
    return (
        f'<a href="{escape(url)}" target="_blank"'
        f' style="display:inline-block;margin:20px 0 24px;padding:12px 28px;'
        f"font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;"
        f'border-radius:6px;background:#111111;">'
        f"{escape(label)}</a>"
    )


def _text(content: str) -> str:
    """Standard body paragraph."""
    return (
        f'<p style="margin:0 0 14px;font-size:15px;'
        f'line-height:1.7;color:#333333;">{content}</p>'
    )


def _muted(content: str) -> str:
    """Small secondary/muted paragraph."""
    return (
        f'<p style="margin:0 0 8px;font-size:13px;'
        f'line-height:1.6;color:#888888;">{content}</p>'
    )


def _quote(content: str) -> str:
    """Indented quote block for message bodies."""
    return (
        '<div style="margin:20px 0;padding:16px 20px;'
        "background:#f5f5f5;border-left:3px solid #cccccc;"
        'border-radius:0 6px 6px 0;">'
        f'<p style="margin:0;font-size:14px;line-height:1.8;color:#333333;">'
        f"{content}</p>"
        "</div>"
    )


# =============================================================================
# Tasks
# =============================================================================


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_verification_email(self, user_email: str, verify_url: str) -> bool:
    """Send email-verification link. Retries up to 3 times on failure."""
    subject = "Verify your email address"
    plain = (
        "Welcome!\n\n"
        f"Verify your email address:\n{verify_url}\n\n"
        "This link expires in 24 hours.\n"
        "If you didn't create this account, ignore this email."
    )
    html = _email(
        subject,
        _text("Please verify your email address to activate your account.")
        + _button(verify_url, "Verify Email Address")
        + _muted("This link expires in 24 hours.")
        + _muted(
            "If you didn't create this account, you can safely ignore this email."
        ),
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
        logger.info("Verification email sent to %s", user_email)
        return True
    except Exception as exc:
        logger.error("Failed to send verification email to %s: %s", user_email, exc)
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_password_reset_email(self, user_email: str, reset_url: str) -> bool:
    """Send password-reset link. Retries up to 3 times on failure."""
    subject = "Reset your password"
    plain = (
        f"Click the link below to reset your password:\n{reset_url}\n\n"
        "This link expires in 24 hours.\n"
        "If you didn't request this, ignore this email."
    )
    html = _email(
        subject,
        _text("We received a request to reset your password.")
        + _button(reset_url, "Reset Password")
        + _muted("This link expires in 24 hours.")
        + _muted("If you didn't request this, you can safely ignore this email."),
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
        logger.info("Password reset email sent to %s", user_email)
        return True
    except Exception as exc:
        logger.error("Failed to send password reset email to %s: %s", user_email, exc)
        raise self.retry(exc=exc)


@shared_task
def send_welcome_email(user_email: str, user_name: str) -> None:
    """Send welcome email after account verification. Non-critical — no retry."""
    safe_name = escape(user_name)
    subject = "Welcome to the Portfolio"
    plain = (
        f"Hi {user_name},\n\n"
        "Your email has been verified — welcome aboard!\n\n"
        "Start building your portfolio by adding projects and skills."
    )
    html = _email(
        subject,
        _text(f"Hi <strong>{safe_name}</strong>,")
        + _text("Your email has been verified — welcome aboard.")
        + _text("Start building your portfolio by adding projects and skills."),
    )
    send_mail(
        subject=subject,
        message=plain,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        html_message=html,
        fail_silently=True,
    )


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_contact_email(self, name: str, email: str, message: str, sent_at: str) -> bool:
    """
    Deliver a contact-form submission to the site owner's inbox.
    Reply-to is set to the visitor's address for easy direct reply.
    """
    safe_name = escape(name)
    safe_email = escape(email)
    safe_message = escape(message).replace("\n", "<br>")

    subject = f"Portfolio contact from {name}"
    plain = (
        "New message via your portfolio contact form.\n\n"
        f"Name:     {name}\n"
        f"Email:    {email}\n"
        f"Sent at:  {sent_at}\n\n"
        f"Message:\n{message}"
    )
    html = _email(
        "New Portfolio Message",
        _text(f"<strong>From:</strong> {safe_name}")
        + _text(
            f"<strong>Email:</strong> "
            f'<a href="mailto:{safe_email}" style="color:#111111;">{safe_email}</a>'
        )
        + _text(f"<strong>Sent at:</strong> {escape(sent_at)}")
        + _quote(safe_message)
        + _muted(f"Hit reply to respond directly to {safe_email}."),
    )

    inbox = (
        getattr(settings, "CONTACT_INBOX_EMAIL", None) or settings.DEFAULT_FROM_EMAIL
    )

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=plain,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[inbox],
            reply_to=[f"{name} <{email}>"],
        )
        msg.attach_alternative(html, "text/html")
        msg.send(fail_silently=False)
        logger.info("Contact email delivered from %s", email)
        return True
    except Exception as exc:
        logger.error("Failed to deliver contact email from %s: %s", email, exc)
        raise self.retry(exc=exc)
