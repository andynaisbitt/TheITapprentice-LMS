# Security Architecture - BlogCMS v1.7

**Document Version:** 1.0
**Last Updated:** 2026-01-10
**Status:** Design Phase

---

## 🎯 Security Goals

1. **Prevent unauthorized access** to user accounts and admin panel
2. **Verify user identity** through email verification
3. **Add second factor** authentication for high-value accounts
4. **Allow admin control** over security policies
5. **Comply with security best practices** (OWASP, NIST)

---

## 🔐 Authentication Strategy

### Current State
- ✅ Email/password authentication (JWT tokens, HTTP-only cookies)
- ✅ Password hashing (bcrypt)
- ✅ Google OAuth (automatic email verification)
- ✅ Role-based access control (7 roles)
- ⚠️ **Missing:** Email verification for non-Google signups
- ⚠️ **Missing:** Multi-Factor Authentication (MFA/2FA)

---

## 📧 Email Verification System

### Decision: TWO-TIER VERIFICATION

**Google OAuth Users:**
- ✅ **NO email verification required**
- ✅ Automatically marked as `is_verified = True`
- **Rationale:** Google has already verified the email address
- **Benefit:** Frictionless signup experience for trusted providers

**Email/Password Users:**
- ❌ **MUST verify email before full access**
- ❌ Account created but `is_verified = False`
- ❌ Limited access until verified (can login but restricted)
- **Rationale:** Prevent fake accounts, spam, abuse
- **Benefit:** Ensures real email addresses, reduces bot signups

### Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│ USER SIGNS UP WITH EMAIL/PASSWORD                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Create user account (is_verified = False)               │
│ 2. Generate verification token (6-digit code + UUID token) │
│ 3. Send verification email                                  │
│ 4. Redirect to login with message                          │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ USER LOGS IN                                                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
                   is_verified?
                    /        \
                  NO          YES
                  /             \
                 ▼               ▼
    ┌─────────────────────┐   ┌────────────────┐
    │ Show verification   │   │ Full access to │
    │ prompt/banner       │   │ admin panel    │
    │ "Please verify      │   └────────────────┘
    │  your email"        │
    │                     │
    │ Allow access to:    │
    │ - View own profile  │
    │ - Resend email      │
    │ - Logout            │
    │                     │
    │ Restrict access to: │
    │ - Blog creation     │
    │ - Content editing   │
    │ - Admin features    │
    └─────────────────────┘
```

### Verification Token Design

**Two-part system for security + UX:**

1. **Short Code (6 digits):** For manual entry
   - Example: `847293`
   - Easy to type
   - Valid for 15 minutes
   - Case-insensitive

2. **Long Token (UUID):** For click-through links
   - Example: `a3f8b21c-4d5e-6f7g-8h9i-0j1k2l3m4n5o`
   - One-click verification
   - Valid for 24 hours
   - URL: `/verify-email?token=xxx`

**Database Schema:**
```python
class EmailVerification(Base):
    id: int
    user_id: int  # Foreign key to User
    short_code: str  # 6-digit code
    long_token: str  # UUID token
    created_at: datetime
    expires_at: datetime  # 24 hours from created_at
    verified_at: datetime | None  # NULL until verified
    is_used: bool  # Prevent reuse
```

### Email Template

**Subject:** Verify your email - The IT Apprentice

**Body:**
```html
Hi {first_name},

Welcome to The IT Apprentice! Please verify your email address to complete your registration.

Your verification code is:

┌─────────────┐
│   847293    │  (Valid for 15 minutes)
└─────────────┘

Or click this link to verify instantly:
https://theitapprentice.com/verify-email?token=a3f8b21c...

If you didn't create this account, please ignore this email.

Thanks,
The IT Apprentice Team
```

---

## 🔐 Multi-Factor Authentication (MFA/2FA)

### Decision: TOTP-Based MFA (Google Authenticator Style)

**Why TOTP?**
- ✅ Industry standard (NIST approved)
- ✅ Works offline (no SMS costs)
- ✅ Compatible with Google Authenticator, Authy, 1Password
- ✅ More secure than SMS (no SIM swap attacks)
- ✅ No third-party dependencies

**Implementation:** `pyotp` (Python) + `otpauth://` QR codes

### MFA Flow

```
┌─────────────────────────────────────────────────────────────┐
│ USER ENABLES MFA IN SETTINGS                                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Generate TOTP secret (32-char base32)                    │
│ 2. Show QR code + manual entry key                          │
│ 3. User scans with authenticator app                        │
│ 4. User enters 6-digit code to confirm setup                │
│ 5. Generate 10 backup codes (8-char alphanumeric)           │
│ 6. Mark user.mfa_enabled = True                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ FUTURE LOGINS                                                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. User enters email/password OR clicks Google              │
│ 2. Credentials verified ✓                                   │
│ 3. Check: Is MFA enabled?                                   │
│    YES → Show MFA verification page                         │
│    NO  → Grant full access                                  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ MFA VERIFICATION PAGE                                        │
│                                                              │
│ Enter 6-digit code from your authenticator app:             │
│                                                              │
│ ┌──┬──┬──┬──┬──┬──┐                                         │
│ │8 │4 │7 │2 │9 │3 │  [Verify]                              │
│ └──┴──┴──┴──┴──┴──┘                                         │
│                                                              │
│ Lost your device? [Use backup code]                         │
│ Trouble? [Disable MFA] (requires email confirmation)        │
└─────────────────────────────────────────────────────────────┘
```

### Backup Codes

**Purpose:** Emergency access if authenticator app is lost

**Format:** 10 codes, 8 characters each
```
XKCD-1234
PASS-5678
WORD-9012
EPIC-3456
HERO-7890
CODE-2345
SAFE-6789
LOCK-0123
KEYS-4567
SEAL-8901
```

**Usage:**
- Each code can only be used once
- Marked as `used: true` after use
- Displayed only once at MFA setup (download or print)
- Can regenerate codes (invalidates old ones)

### MFA Database Schema

```python
class UserMFA(Base):
    id: int
    user_id: int  # Foreign key to User
    totp_secret: str  # Base32 encoded secret (encrypted at rest)
    is_enabled: bool  # MFA active/inactive
    created_at: datetime
    last_used_at: datetime | None
    backup_codes: str  # JSON array of {code: str, used: bool}
```

### MFA Policy (Admin Configurable)

**Security Settings in Admin Panel:**

1. **Require MFA for Admins**
   - Toggle: ON/OFF
   - When ON: All users with `is_admin = True` MUST enable MFA
   - Grace period: 7 days to enable (then account locked)

2. **Require MFA for Authors**
   - Toggle: ON/OFF
   - When ON: All users with `can_write_blog = True` MUST enable MFA

3. **Allow MFA for All Users**
   - Toggle: ON/OFF (default ON)
   - When OFF: Only admins can enable MFA

---

## 🛡️ Security Settings (Admin Panel)

### New Admin Panel Section: "Security Settings"

**Location:** `/admin/security`

**Settings:**

### 1. Email Verification

```
┌─────────────────────────────────────────────────────────┐
│ ☑ Require email verification for new signups           │
│                                                         │
│ When enabled, users must verify their email before     │
│ accessing admin features. Google OAuth users are       │
│ automatically verified.                                │
│                                                         │
│ Verification expiry: [24 hours ▼]                      │
│                                                         │
│ Resend limit: [3 emails per 24 hours]                  │
└─────────────────────────────────────────────────────────┘
```

### 2. Multi-Factor Authentication

```
┌─────────────────────────────────────────────────────────┐
│ ☑ Allow MFA for all users                              │
│                                                         │
│ ☑ Require MFA for admins                               │
│   Grace period: [7 days ▼]                             │
│                                                         │
│ ☑ Require MFA for blog authors                         │
│   Grace period: [14 days ▼]                            │
│                                                         │
│ Backup codes per user: [10 ▼]                          │
└─────────────────────────────────────────────────────────┘
```

### 3. Password Policy

```
┌─────────────────────────────────────────────────────────┐
│ Minimum password length: [8 characters]                │
│                                                         │
│ Required character types:                              │
│ ☑ At least one uppercase letter                        │
│ ☑ At least one lowercase letter                        │
│ ☑ At least one number                                  │
│ ☐ At least one special character                       │
│                                                         │
│ Password expiry: [Never ▼]                             │
│   Options: Never, 30 days, 60 days, 90 days           │
│                                                         │
│ ☑ Prevent password reuse (last 3 passwords)            │
└─────────────────────────────────────────────────────────┘
```

### 4. Session Security

```
┌─────────────────────────────────────────────────────────┐
│ Session timeout (inactivity): [30 minutes ▼]           │
│   Options: 15m, 30m, 1h, 2h, 4h, 8h, Never            │
│                                                         │
│ Absolute session timeout: [7 days ▼]                   │
│   Options: 1d, 3d, 7d, 14d, 30d, Never                │
│                                                         │
│ ☑ Require re-authentication for sensitive actions      │
│   (account deletion, security changes, etc.)           │
│                                                         │
│ ☐ Log out all devices on password change               │
└─────────────────────────────────────────────────────────┘
```

### 5. Login Security

```
┌─────────────────────────────────────────────────────────┐
│ Max login attempts: [5 attempts]                        │
│ Lockout duration: [15 minutes ▼]                        │
│   Options: 5m, 15m, 30m, 1h, 24h                       │
│                                                         │
│ ☑ Send email on failed login attempts                  │
│   Threshold: [3 failed attempts]                       │
│                                                         │
│ ☑ Send email on new device login                       │
│                                                         │
│ ☑ Require CAPTCHA after failed attempts                │
│   Threshold: [3 failed attempts]                       │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Database Schema Changes

### New Tables Required

**1. email_verifications**
```sql
CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    short_code VARCHAR(6) NOT NULL,
    long_token VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_user_id (user_id),
    INDEX idx_long_token (long_token),
    INDEX idx_short_code (short_code)
);
```

**2. user_mfa**
```sql
CREATE TABLE user_mfa (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    totp_secret VARCHAR(32) NOT NULL,  -- Encrypted at rest
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    backup_codes JSON NOT NULL,  -- Array of {code, used}
    INDEX idx_user_id (user_id)
);
```

**3. security_settings**
```sql
CREATE TABLE security_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(64) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_by INTEGER REFERENCES users(id)
);
```

### Users Table Additions

```sql
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_required_by TIMESTAMP;  -- Deadline to enable MFA
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP;  -- Track when verified
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMP;  -- Account lockout
```

---

## 🔒 Security Considerations

### Email Verification

**Threats Mitigated:**
- ✅ Fake account creation
- ✅ Email enumeration attacks (rate limit verification requests)
- ✅ Spam/bot signups

**Implementation Notes:**
- Tokens stored hashed in database (bcrypt)
- Rate limit: 3 verification emails per 24 hours per user
- Expired tokens cleaned up daily (cron job)

### MFA/2FA

**Threats Mitigated:**
- ✅ Password theft/phishing
- ✅ Credential stuffing attacks
- ✅ Brute force attacks

**Implementation Notes:**
- TOTP secrets encrypted at rest (Fernet encryption)
- Backup codes hashed in database (bcrypt)
- Rate limit: 5 MFA attempts per 5 minutes (then lockout)
- No SMS-based 2FA (vulnerable to SIM swaps)

### Session Security

**Threats Mitigated:**
- ✅ Session hijacking
- ✅ Session fixation
- ✅ Idle session takeover

**Implementation Notes:**
- HTTP-only cookies (prevents XSS)
- Secure flag in production (HTTPS only)
- SameSite=Lax (CSRF protection)
- Regenerate session ID on login

### Brute Force Protection

**Threats Mitigated:**
- ✅ Password guessing
- ✅ Credential stuffing
- ✅ Automated attacks

**Implementation Notes:**
- Rate limiting (5 attempts per minute per IP)
- Account lockout (15 minutes after 5 failed attempts)
- CAPTCHA after 3 failed attempts
- Log all failed attempts

---

## 📝 Implementation Checklist

### Phase 1: Email Verification (HIGH PRIORITY)
- [ ] Create `email_verifications` table
- [ ] Add `email_verified_at` to users table
- [ ] Create verification token generator
- [ ] Create email sender service
- [ ] Create verification endpoints (send, verify, resend)
- [ ] Update registration flow
- [ ] Create verification UI page
- [ ] Create verification email template
- [ ] Add "Resend Email" button
- [ ] Test verification flow end-to-end

### Phase 2: MFA Foundation (HIGH PRIORITY)
- [ ] Install `pyotp` package
- [ ] Create `user_mfa` table
- [ ] Add `mfa_enabled` to users table
- [ ] Create MFA setup endpoint (generate secret, QR code)
- [ ] Create MFA verify endpoint (check TOTP code)
- [ ] Create backup codes generator
- [ ] Create MFA disable endpoint
- [ ] Create MFA verification UI page
- [ ] Create MFA settings UI page
- [ ] Test MFA flow with Google Authenticator

### Phase 3: Security Settings Panel (MEDIUM PRIORITY)
- [ ] Create `security_settings` table
- [ ] Create security settings API endpoints
- [ ] Create admin security settings UI
- [ ] Implement email verification toggle
- [ ] Implement MFA policy toggles
- [ ] Implement password policy settings
- [ ] Implement session timeout settings
- [ ] Implement login security settings
- [ ] Test all security settings

### Phase 4: Enhanced Login Security (MEDIUM PRIORITY)
- [ ] Add `failed_login_attempts` to users table
- [ ] Add `locked_until` to users table
- [ ] Implement login attempt tracking
- [ ] Implement account lockout logic
- [ ] Add CAPTCHA integration (hCaptcha or reCAPTCHA)
- [ ] Create "account locked" UI page
- [ ] Send email on suspicious login
- [ ] Send email on new device login

### Phase 5: Password Management (LOW PRIORITY)
- [ ] Implement password expiry
- [ ] Implement password history (prevent reuse)
- [ ] Create "change password" flow
- [ ] Create "forgot password" flow
- [ ] Create password reset email template
- [ ] Implement "log out all devices" on password change

---

## 🎯 Recommended Security Defaults

**For Production:**

| Setting | Recommended Value | Rationale |
|---------|------------------|-----------|
| Require email verification | ✅ ON | Prevent fake accounts |
| Allow MFA for all users | ✅ ON | User choice for extra security |
| Require MFA for admins | ✅ ON | Protect privileged accounts |
| Require MFA for authors | ☐ OFF | Optional (low risk) |
| Password min length | 8 chars | Balance security & UX |
| Password requires uppercase | ✅ ON | Increase entropy |
| Password requires number | ✅ ON | Increase entropy |
| Session timeout | 30 minutes | Balance security & UX |
| Max login attempts | 5 attempts | Prevent brute force |
| Lockout duration | 15 minutes | Annoying but not catastrophic |
| Email on failed logins | ✅ ON | User awareness |
| Email on new device | ✅ ON | Detect unauthorized access |

---

**Status:** Ready for implementation in v1.7 🚀

