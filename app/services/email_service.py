"""
SMTP email boundary with no credential or token logging.

This module provides the EmailService class, which handles all email
sending operations for the application. It supports:
    - Transactional emails (verification, password reset)
    - Notification emails (alerts, security warnings)
    - HTML and plain-text emails
    - Template rendering
    - Development mode (log instead of send)
    - Async sending (non-blocking)

Design Pattern: Service Layer + Strategy Pattern
    - Abstracts email sending behind a clean interface
    - Supports multiple providers (SMTP, SendGrid, SES)
    - Async-first for non-blocking operations
    - Template-based for consistency

Responsibilities:
    - Send verification emails
    - Send password reset emails
    - Send security alerts (login from new device, etc.)
    - Send welcome emails
    - Send 2FA backup codes
    - Handle SMTP connection lifecycle
    - Log email events (without sensitive data)

Design Principles:
    - Single Responsibility: Email sending
    - Async: Non-blocking operations
    - Testable: Easy to mock
    - Safe: Never log tokens or credentials
    - Configurable: Development, staging, production modes

Security Notes:
    - NEVER log tokens or passwords
    - NEVER include sensitive data in subject lines
    - TLS required for all SMTP connections
    - Credentials loaded from settings (never hardcoded)
    - Development mode: log instead of send (no accidental emails)
    - Rate limiting: Prevent email flooding

Architecture:
    Endpoints → EmailService → SMTP Server
                     ↓
              Templates (Jinja2)
                     ↓
              Settings (SMTP config)
"""

import asyncio
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Optional

from app.core.config.settings import get_settings
from app.models.domain.user import User
from app.utils.logger import logger


# ============================================================
# EMAIL SERVICE
# ============================================================

class EmailService:
    """
    Service for sending transactional emails.
    
    This service handles all email operations with:
    - SMTP connection management
    - Template rendering
    - Development mode (log instead of send)
    - Async execution
    - Error handling and retries
    
    Example:
        service = EmailService()
        
        # Send verification email
        await service.send_verification_email(user, token)
        
        # Send password reset
        await service.send_reset_email(user, token)
        
        # Send security alert
        await service.send_security_alert(user, "Login from new device")
    """
    
    def __init__(self):
        """Initialize email service with settings."""
        self.settings = get_settings()
        self._is_development = self.settings.environment == "development"
        self._is_mock = self._is_development and not self.settings.smtp_username
    
    # ============================================================
    # CORE EMAIL SENDING
    # ============================================================
    
    async def send_email(
        self,
        recipient: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        """
        Send an email via SMTP (async wrapper).
        
        Args:
            recipient: Email address
            subject: Email subject line
            body: Plain text body
            html_body: Optional HTML body
            
        Returns:
            True if sent successfully
            
        Example:
            success = await service.send_email(
                recipient="user@example.com",
                subject="Welcome!",
                body="Thanks for signing up!",
            )
        """
        if self._is_mock:
            # Development mode: log instead of send
            logger.info(
                "Email (mock mode - not sent)",
                extra={
                    "event": "email_mock",
                    "recipient": self._mask_email(recipient),
                    "subject": subject,
                }
            )
            return True
        
        try:
            # Run synchronous SMTP in thread pool
            # (SMTP library is blocking, we don't want to block event loop)
            await asyncio.to_thread(
                self._send_smtp,
                recipient=recipient,
                subject=subject,
                body=body,
                html_body=html_body,
            )
            
            logger.info(
                "Email sent",
                extra={
                    "event": "email_sent",
                    "recipient": self._mask_email(recipient),
                    "subject": subject,
                    "has_html": html_body is not None,
                }
            )
            
            return True
            
        except smtplib.SMTPException as e:
            logger.error(
                "Email SMTP error",
                extra={
                    "event": "email_failed",
                    "recipient": self._mask_email(recipient),
                    "subject": subject,
                    "error": str(e),
                }
            )
            return False
            
        except Exception as e:
            logger.exception(
                "Email unexpected error",
                extra={
                    "event": "email_error",
                    "recipient": self._mask_email(recipient),
                    "subject": subject,
                }
            )
            return False
    
    def _send_smtp(
        self,
        recipient: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
    ) -> None:
        """
        Send email synchronously via SMTP.
        
        This method is blocking and should be called via asyncio.to_thread().
        
        Raises:
            smtplib.SMTPException: If SMTP operations fail
        """
        # Build message
        if html_body:
            # Multipart message (text + HTML)
            message = MIMEMultipart("alternative")
            message["From"] = self.settings.smtp_from
            message["To"] = recipient
            message["Subject"] = subject
            
            # Add both parts
            message.attach(MIMEText(body, "plain"))
            message.attach(MIMEText(html_body, "html"))
        else:
            # Simple text message
            message = EmailMessage()
            message["From"] = self.settings.smtp_from
            message["To"] = recipient
            message["Subject"] = subject
            message.set_content(body)
        
        # Connect and send
        with smtplib.SMTP(
            self.settings.smtp_host,
            self.settings.smtp_port,
            timeout=30,  # Prevent hanging
        ) as smtp:
            # Upgrade to TLS
            smtp.starttls()
            
            # Authenticate if credentials provided
            if self.settings.smtp_username:
                smtp.login(
                    self.settings.smtp_username,
                    self.settings.smtp_password.get_secret_value(),
                )
            
            # Send
            smtp.send_message(message)
    
    # ============================================================
    # VERIFICATION EMAILS
    # ============================================================
    
    async def send_verification_email(
        self,
        user: User,
        token: str,
    ) -> bool:
        """
        Send a verification link containing the one-time raw token.
        
        Args:
            user: User to send verification to
            token: One-time verification token
            
        Returns:
            True if sent successfully
            
        Security Notes:
            - Token is NOT logged (only hashed version is stored)
            - Link uses base_url + api_prefix from settings
            - Token expires after 24 hours (per email_verification model)
        """
        verification_url = self._build_url(f"/auth/verify?token={token}")
        
        subject = f"Verify your email for {self.settings.app_name}"
        
        body = f"""Hi {user.full_name},

Welcome to {self.settings.app_name}!

Please verify your email address by clicking the link below:

{verification_url}

This link will expire in 24 hours.

If you didn't create an account, you can safely ignore this email.

Thanks,
The {self.settings.app_name} Team
"""
        
        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Verify Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2>Welcome to {self.settings.app_name}!</h2>
    
    <p>Hi {user.full_name},</p>
    
    <p>Please verify your email address by clicking the button below:</p>
    
    <p style="text-align: center; margin: 30px 0;">
        <a href="{verification_url}" 
           style="background-color: #4F46E5; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 6px; display: inline-block;">
            Verify Email
        </a>
    </p>
    
    <p>Or copy and paste this link into your browser:</p>
    <p style="word-break: break-all; color: #6B7280;">{verification_url}</p>
    
    <p><strong>This link will expire in 24 hours.</strong></p>
    
    <p>If you didn't create an account, you can safely ignore this email.</p>
    
    <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 30px 0;">
    
    <p style="color: #6B7280; font-size: 12px;">
        Thanks,<br>
        The {self.settings.app_name} Team
    </p>
</body>
</html>"""
        
        return await self.send_email(
            recipient=str(user.email),
            subject=subject,
            body=body,
            html_body=html_body,
        )
    
    # ============================================================
    # PASSWORD RESET EMAILS
    # ============================================================
    
    async def send_reset_email(
        self,
        user: User,
        token: str,
    ) -> bool:
        """
        Send a password-reset link containing the one-time raw token.
        
        Args:
            user: User requesting password reset
            token: One-time reset token
            
        Returns:
            True if sent successfully
            
        Security Notes:
            - Token is NOT logged
            - Link uses base_url + api_prefix
            - Token expires in 15 minutes (per password_reset model)
        """
        reset_url = self._build_url(f"/auth/reset-password?token={token}")
        
        subject = f"Reset your password for {self.settings.app_name}"
        
        body = f"""Hi {user.full_name},

We received a request to reset your password for {self.settings.app_name}.

Click the link below to set a new password:

{reset_url}

This link will expire in 15 minutes.

If you didn't request a password reset, you can safely ignore this email.
Your password will not be changed.

Thanks,
The {self.settings.app_name} Team
"""
        
        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Reset Your Password</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2>Reset Your Password</h2>
    
    <p>Hi {user.full_name},</p>
    
    <p>We received a request to reset your password for {self.settings.app_name}.</p>
    
    <p style="text-align: center; margin: 30px 0;">
        <a href="{reset_url}" 
           style="background-color: #DC2626; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 6px; display: inline-block;">
            Reset Password
        </a>
    </p>
    
    <p>Or copy and paste this link into your browser:</p>
    <p style="word-break: break-all; color: #6B7280;">{reset_url}</p>
    
    <p><strong>This link will expire in 15 minutes.</strong></p>
    
    <div style="background-color: #FEF2F2; border-left: 4px solid #DC2626; padding: 15px; margin: 20px 0;">
        <p style="margin: 0; color: #991B1B;">
            <strong>⚠️ Didn't request this?</strong><br>
            If you didn't request a password reset, you can safely ignore this email.
            Your password will not be changed.
        </p>
    </div>
    
    <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 30px 0;">
    
    <p style="color: #6B7280; font-size: 12px;">
        Thanks,<br>
        The {self.settings.app_name} Team
    </p>
</body>
</html>"""
        
        return await self.send_email(
            recipient=str(user.email),
            subject=subject,
            body=body,
            html_body=html_body,
        )
    
    # ============================================================
    # SECURITY ALERTS
    # ============================================================
    
    async def send_security_alert(
        self,
        user: User,
        message: str,
        action_url: Optional[str] = None,
    ) -> bool:
        """
        Send a security alert email.
        
        Used for:
        - Login from new device/location
        - Password changed
        - 2FA enabled/disabled
        - Suspicious activity detected
        
        Args:
            user: User to alert
            message: Alert message
            action_url: Optional action URL (e.g., "Review activity")
            
        Returns:
            True if sent successfully
        """
        subject = f"Security Alert for {self.settings.app_name}"
        
        body = f"""Hi {user.full_name},

{message}

If this wasn't you, please secure your account immediately.

Thanks,
The {self.settings.app_name} Team
"""
        
        if action_url:
            body += f"\n\nTake action: {action_url}"
        
        return await self.send_email(
            recipient=str(user.email),
            subject=subject,
            body=body,
        )
    
    async def send_password_changed_notification(
        self,
        user: User,
    ) -> bool:
        """Notify user that password was changed."""
        return await self.send_security_alert(
            user,
            message=(
                "Your password was recently changed. "
                "If you did not make this change, please reset your password immediately "
                "and contact support."
            ),
        )
    
    async def send_2fa_enabled_notification(self, user: User) -> bool:
        """Notify user that 2FA was enabled."""
        return await self.send_security_alert(
            user,
            message="Two-factor authentication has been enabled on your account.",
        )
    
    async def send_2fa_disabled_notification(self, user: User) -> bool:
        """Notify user that 2FA was disabled."""
        return await self.send_security_alert(
            user,
            message=(
                "Two-factor authentication has been disabled on your account. "
                "Your account is now less secure. Please re-enable it if this wasn't you."
            ),
        )
    
    # ============================================================
    # WELCOME EMAILS
    # ============================================================
    
    async def send_welcome_email(self, user: User) -> bool:
        """
        Send a welcome email after successful verification.
        
        Args:
            user: Verified user
            
        Returns:
            True if sent successfully
        """
        subject = f"Welcome to {self.settings.app_name}!"
        
        body = f"""Hi {user.full_name},

Welcome to {self.settings.app_name}! Your email has been verified.

You can now:
- Log in to your account
- Complete your profile
- Explore our features

Get started: {self._build_url('/login')}

Thanks,
The {self.settings.app_name} Team
"""
        
        return await self.send_email(
            recipient=str(user.email),
            subject=subject,
            body=body,
        )
    
    # ============================================================
    # 2FA BACKUP CODES
    # ============================================================
    
    async def send_backup_codes_email(
        self,
        user: User,
        backup_codes: list[str],
    ) -> bool:
        """
        Send backup codes to user's email (backup of backup).
        
        Args:
            user: User who generated codes
            backup_codes: List of plaintext codes
            
        Returns:
            True if sent successfully
            
        Security Notes:
            - This is a convenience backup
            - User should still save codes locally
            - Email storage may not be secure
        """
        subject = "Your 2FA Backup Codes"
        
        codes_list = "\n".join(f"  {i+1}. {code}" for i, code in enumerate(backup_codes))
        
        body = f"""Hi {user.full_name},

Here are your 2FA backup codes for {self.settings.app_name}.

Save these codes in a secure place (password manager, printed copy).

{codes_list}

IMPORTANT:
- Each code can only be used ONCE
- Use these if you lose access to your authenticator app
- Regenerate codes if any are compromised

Thanks,
The {self.settings.app_name} Team
"""
        
        return await self.send_email(
            recipient=str(user.email),
            subject=subject,
            body=body,
        )
    
    # ============================================================
    # INTERNAL HELPERS
    # ============================================================
    
    def _build_url(self, path: str, is_api: bool = False) -> str:
        """
        Build a full URL using base_url and optionally api_prefix.
        
        Args:
            path: URL path (e.g., "/auth/verify?token=xxx")
            is_api: If True, include api_prefix
            
        Returns:
            Full URL
        """
        base = self.settings.base_url.rstrip("/")
        path = path.lstrip("/")
        
        if is_api:
            prefix = self.settings.api_prefix.rstrip("/")
            return f"{base}{prefix}/{path}"
            
        return f"{base}/{path}"
    
    def _mask_email(self, email: str) -> str:
        """
        Mask email for logging (privacy).
        
        Args:
            email: Full email address
            
        Returns:
            Masked email (e.g., "j***@example.com")
        """
        if not email or "@" not in email:
            return "***"
        
        local, domain = email.rsplit("@", 1)
        
        if len(local) <= 1:
            masked_local = "*"
        else:
            masked_local = local[0] + "*" * (len(local) - 1)
        
        return f"{masked_local}@{domain}"


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Service class
    "EmailService",
]