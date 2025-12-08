# Newsletter System Implementation Plan

## Overview
Complete newsletter subscription system with SMTP email configuration and enable/disable toggle.

## Database Schema

### newsletter_subscribers table
```sql
- id (PK)
- email (unique, indexed)
- is_active (boolean, indexed)
- confirmed (boolean)
- confirmation_token (string, nullable)
- subscribed_at (timestamp)
- unsubscribed_at (timestamp, nullable)
```

### site_settings additions
```sql
- newsletter_enabled (boolean, default: true)
- smtp_host (string)
- smtp_port (integer, default: 587)
- smtp_username (string)
- smtp_password (string)
- smtp_use_tls (boolean, default: true)
- smtp_from_email (string)
- smtp_from_name (string)
```

## Backend Components

### Models
- [x] NewsletterSubscriber model
- [ ] Update SiteSettings model with email/newsletter fields

### Services
- [x] EmailService class with SMTP functionality
  - send_email()
  - send_welcome_email()
  - send_new_post_notification()

### API Endpoints

#### Public Endpoints
- POST /api/v1/newsletter/subscribe - Subscribe to newsletter
- GET /api/v1/newsletter/unsubscribe/{token} - Unsubscribe via email link

#### Admin Endpoints
- GET /api/v1/admin/newsletter/subscribers - List all subscribers
- DELETE /api/v1/admin/newsletter/subscribers/{id} - Remove subscriber
- POST /api/v1/admin/newsletter/test-email - Send test email
- POST /api/v1/admin/newsletter/send-to-all - Send email to all subscribers

## Frontend Components

### Admin Panel
- Email Settings page (SMTP configuration)
- Newsletter Subscribers list
- Test Email button
- Send to All button
- Newsletter enable/disable toggle

### Public
- Update Footer newsletter form to POST to API
- Show success/error messages
- Handle newsletter disabled state (hide form)

## Implementation Steps

### Phase 1: Database & Models ✓
- [x] Create newsletter_subscribers migration
- [x] Create email settings migration
- [x] Create NewsletterSubscriber model
- [x] Create email service

### Phase 2: Backend API (Next)
- [ ] Create public subscription endpoint
- [ ] Create admin endpoints
- [ ] Update SiteSettings model/schema
- [ ] Register routes in main.py

### Phase 3: Frontend Admin
- [ ] Add email settings fields to SiteSettings interface
- [ ] Create Email Settings tab in admin
- [ ] Create Newsletter Subscribers admin page
- [ ] Add newsletter_enabled toggle

### Phase 4: Frontend Public
- [ ] Update Footer newsletter form
- [ ] Handle API responses
- [ ] Hide newsletter when disabled

### Phase 5: Testing & Deployment
- [ ] Test SMTP connection
- [ ] Test subscription flow
- [ ] Test email sending
- [ ] Deploy to production

## Configuration Example

```python
# SMTP Settings (Gmail example)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your-email@gmail.com"
SMTP_PASSWORD = "app-specific-password"
SMTP_USE_TLS = True
SMTP_FROM_EMAIL = "noreply@yourdomain.com"
SMTP_FROM_NAME = "Your Site Name"
```

## Security Notes
- SMTP password stored encrypted in database (consider using environment variables)
- Email validation on frontend and backend
- Rate limiting on subscription endpoint
- Confirmation tokens for double opt-in (future enhancement)
- Unsubscribe tokens to prevent unauthorized unsubscribes

## Future Enhancements
- Double opt-in with confirmation email
- Email templates management
- Scheduled newsletter campaigns
- Analytics (open rates, click rates)
- Subscriber segmentation
- GDPR compliance features
