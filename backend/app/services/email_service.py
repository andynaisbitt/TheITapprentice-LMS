# Backend\app\services\email_service.py
"""
Email Service for sending verification emails, notifications, etc.
Uses SMTP for production, logs to console for development
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Email sending service"""

    def __init__(self):
        self.smtp_host = settings.SMTP_HOST if hasattr(settings, 'SMTP_HOST') else None
        self.smtp_port = settings.SMTP_PORT if hasattr(settings, 'SMTP_PORT') else 587
        self.smtp_user = settings.SMTP_USER if hasattr(settings, 'SMTP_USER') else None
        self.smtp_password = settings.SMTP_PASSWORD if hasattr(settings, 'SMTP_PASSWORD') else None
        self.from_email = settings.FROM_EMAIL if hasattr(settings, 'FROM_EMAIL') else "noreply@theitapprentice.com"
        self.from_name = settings.FROM_NAME if hasattr(settings, 'FROM_NAME') else "The IT Apprentice"

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None
    ) -> bool:
        """
        Send an email

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body (optional, falls back to stripped HTML)

        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to_email

            # Add plain text version (fallback)
            if text_body:
                part1 = MIMEText(text_body, 'plain')
                msg.attach(part1)

            # Add HTML version
            part2 = MIMEText(html_body, 'html')
            msg.attach(part2)

            # Send email (production) or log (development)
            if self.smtp_host and self.smtp_user and self.smtp_password:
                # Production: Send via SMTP
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)
                logger.info(f"✅ Email sent to {to_email}: {subject}")
            else:
                # Development: Log to console
                logger.warning("📧 SMTP not configured - Email would be sent to: %s", to_email)
                logger.info("=" * 80)
                logger.info("Subject: %s", subject)
                logger.info("To: %s", to_email)
                logger.info("From: %s <%s>", self.from_name, self.from_email)
                logger.info("-" * 80)
                logger.info("HTML Body:")
                logger.info(html_body)
                logger.info("=" * 80)

            return True

        except Exception as e:
            logger.error(f"❌ Failed to send email to {to_email}: {e}")
            return False

    def send_verification_email(
        self,
        to_email: str,
        first_name: str,
        short_code: str,
        long_token: str,
        base_url: str = "http://localhost:5173"
    ) -> bool:
        """
        Send email verification email

        Args:
            to_email: User email address
            first_name: User first name
            short_code: 6-digit verification code
            long_token: Long URL token
            base_url: Frontend base URL

        Returns:
            bool: True if sent successfully
        """
        verification_url = f"{base_url}/verify-email?token={long_token}"

        subject = "Verify your email - The IT Apprentice"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f4f4f4;
                }}
                .container {{
                    background-color: #ffffff;
                    border-radius: 10px;
                    padding: 40px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    color: #2563eb;
                    margin: 0;
                    font-size: 28px;
                }}
                .code-box {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    text-align: center;
                    margin: 30px 0;
                }}
                .code {{
                    font-size: 36px;
                    font-weight: bold;
                    letter-spacing: 8px;
                    font-family: 'Courier New', monospace;
                }}
                .code-label {{
                    font-size: 14px;
                    opacity: 0.9;
                    margin-top: 10px;
                }}
                .button {{
                    display: inline-block;
                    padding: 15px 40px;
                    background-color: #2563eb;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .button:hover {{
                    background-color: #1d4ed8;
                }}
                .divider {{
                    text-align: center;
                    margin: 30px 0;
                    color: #666;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    color: #666;
                    font-size: 14px;
                }}
                .warning {{
                    background-color: #fef3c7;
                    border-left: 4px solid #f59e0b;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎓 The IT Apprentice</h1>
                    <p style="color: #666; margin-top: 10px;">Verify Your Email Address</p>
                </div>

                <p>Hi <strong>{first_name}</strong>,</p>

                <p>Welcome to The IT Apprentice! We're excited to have you join our community of learners and developers.</p>

                <p>To complete your registration and access all features, please verify your email address using one of the methods below:</p>

                <div class="code-box">
                    <div class="code">{short_code}</div>
                    <div class="code-label">Enter this code on the verification page</div>
                </div>

                <div class="divider">
                    <strong>OR</strong>
                </div>

                <div style="text-align: center;">
                    <a href="{verification_url}" class="button">Verify Email Instantly</a>
                </div>

                <div class="warning">
                    <strong>⏰ Important:</strong> This verification code expires in <strong>24 hours</strong>. The 6-digit code is valid for <strong>15 minutes</strong>.
                </div>

                <p style="color: #666; font-size: 14px;">If you didn't create an account with The IT Apprentice, you can safely ignore this email.</p>

                <div class="footer">
                    <p><strong>Need Help?</strong></p>
                    <p>If you're having trouble verifying your email, please contact us at support@theitapprentice.com</p>
                    <p style="margin-top: 20px;">© 2026 The IT Apprentice. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
Hi {first_name},

Welcome to The IT Apprentice! Please verify your email address to complete your registration.

Your verification code is: {short_code}

Or click this link to verify instantly:
{verification_url}

⏰ This code expires in 24 hours.

If you didn't create this account, please ignore this email.

Thanks,
The IT Apprentice Team
        """

        return self.send_email(to_email, subject, html_body, text_body)

    def send_password_reset_email(
        self,
        to_email: str,
        first_name: str,
        reset_token: str,
        base_url: str = "http://localhost:5173"
    ) -> bool:
        """Send password reset email (for future implementation)"""
        reset_url = f"{base_url}/reset-password?token={reset_token}"

        subject = "Reset your password - The IT Apprentice"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Password Reset Request</h2>
            <p>Hi {first_name},</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}" style="background: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
            </p>
            <p style="color: #666; font-size: 14px;">This link expires in 1 hour.</p>
            <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """

        return self.send_email(to_email, subject, html_body)


# Singleton instance
email_service = EmailService()
