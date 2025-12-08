# Backend/app/api/v1/services/newsletter/email_service.py
"""SMTP Email service for newsletter"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """SMTP Email service"""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        smtp_from_email: str,
        smtp_from_name: str,
        smtp_use_tls: bool = True
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.smtp_from_email = smtp_from_email
        self.smtp_from_name = smtp_from_name
        self.smtp_use_tls = smtp_use_tls

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None
    ) -> bool:
        """Send an email via SMTP"""
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.smtp_from_name} <{self.smtp_from_email}>"
            message["To"] = to_email

            # Add text and HTML parts
            if text_body:
                part1 = MIMEText(text_body, "plain")
                message.attach(part1)

            part2 = MIMEText(html_body, "html")
            message.attach(part2)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.smtp_from_email, to_email, message.as_string())

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

    def send_welcome_email(self, to_email: str, site_title: str, site_url: str) -> bool:
        """Send welcome email to new subscriber"""
        subject = f"Welcome to {site_title} Newsletter!"

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #2563eb;">Thank you for subscribing!</h1>
                    <p>You've successfully subscribed to the {site_title} newsletter.</p>
                    <p>You'll receive updates about new posts and content directly in your inbox.</p>
                    <p style="margin-top: 30px;">
                        <a href="{site_url}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                            Visit {site_title}
                        </a>
                    </p>
                    <p style="color: #666; font-size: 12px; margin-top: 40px;">
                        You're receiving this email because you subscribed to our newsletter.
                        If you didn't subscribe, you can safely ignore this email.
                    </p>
                </div>
            </body>
        </html>
        """

        text_body = f"""
        Thank you for subscribing!

        You've successfully subscribed to the {site_title} newsletter.
        You'll receive updates about new posts and content directly in your inbox.

        Visit us at: {site_url}

        You're receiving this email because you subscribed to our newsletter.
        If you didn't subscribe, you can safely ignore this email.
        """

        return self.send_email(to_email, subject, html_body, text_body)

    def send_new_post_notification(
        self,
        to_email: str,
        post_title: str,
        post_excerpt: str,
        post_url: str,
        site_title: str
    ) -> bool:
        """Send notification about new blog post"""
        subject = f"New Post: {post_title}"

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2563eb;">{post_title}</h2>
                    <p>{post_excerpt}</p>
                    <p style="margin-top: 30px;">
                        <a href="{post_url}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                            Read Full Post
                        </a>
                    </p>
                    <p style="color: #666; font-size: 12px; margin-top: 40px;">
                        You're receiving this email because you're subscribed to {site_title} newsletter.
                    </p>
                </div>
            </body>
        </html>
        """

        text_body = f"""
        New Post: {post_title}

        {post_excerpt}

        Read full post at: {post_url}

        You're receiving this email because you're subscribed to {site_title} newsletter.
        """

        return self.send_email(to_email, subject, html_body, text_body)


def get_email_service_from_settings(settings) -> Optional[EmailService]:
    """Create EmailService instance from site settings"""
    if not all([
        settings.smtp_host,
        settings.smtp_username,
        settings.smtp_password,
        settings.smtp_from_email
    ]):
        logger.warning("SMTP settings incomplete, email service not available")
        return None

    return EmailService(
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port or 587,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        smtp_from_email=settings.smtp_from_email,
        smtp_from_name=settings.smtp_from_name or settings.site_title,
        smtp_use_tls=settings.smtp_use_tls if hasattr(settings, 'smtp_use_tls') else True
    )
