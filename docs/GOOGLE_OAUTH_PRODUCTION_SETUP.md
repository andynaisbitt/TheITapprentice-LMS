# Google OAuth Setup - Production Guide

**For v1.7 Deployment**
**Estimated Time:** 15 minutes

---

## 📋 Prerequisites

- Google Cloud Console account
- Production domain (e.g., theitapprentice.com)
- SSH access to production VM
- Frontend and backend deployed

---

## Step 1: Google Cloud Console Setup (10 minutes)

### 1.1 Create or Select Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click project dropdown (top left)
3. Click **"New Project"**
   - **Project name:** `BlogCMS` or `The IT Apprentice`
   - Click **"Create"**
4. Wait for project creation (30 seconds)
5. Select the new project from dropdown

### 1.2 Enable Required APIs

1. Navigate to **APIs & Services** → **Library** (left sidebar)
2. Search for **"Google+ API"** or **"People API"**
3. Click on **"Google+ API"**
4. Click **"Enable"** button
5. Wait for API to enable (~10 seconds)

### 1.3 Configure OAuth Consent Screen

1. Navigate to **APIs & Services** → **OAuth consent screen**
2. **User Type:** Select **"External"** (for public access)
3. Click **"Create"**

**App Information:**
- **App name:** `The IT Apprentice` (or your blog name)
- **User support email:** Select your email from dropdown
- **App logo:** (optional) Upload 512x512 PNG logo

**App Domain:**
- **Application home page:** `https://theitapprentice.com`
- **Application privacy policy:** `https://theitapprentice.com/privacy`
- **Application terms of service:** `https://theitapprentice.com/terms`

**Authorized domains:**
- Click **"Add domain"**
- Enter: `theitapprentice.com` (your production domain)
- Click outside field to confirm

**Developer contact information:**
- **Email addresses:** Enter your email

4. Click **"Save and Continue"**

**Scopes (Step 2):**
- Click **"Add or Remove Scopes"**
- Select these scopes:
  - `.../auth/userinfo.email`
  - `.../auth/userinfo.profile`
  - `openid`
- Click **"Update"**
- Click **"Save and Continue"**

**Test users (Step 3):**
- **If app is in testing mode:** Add your email as test user
- Click **"Add Users"** → Enter email → Save
- Click **"Save and Continue"**

**Summary (Step 4):**
- Review all settings
- Click **"Back to Dashboard"**

### 1.4 Create OAuth 2.0 Client ID

1. Navigate to **APIs & Services** → **Credentials**
2. Click **"+ Create Credentials"** (top bar)
3. Select **"OAuth client ID"**

**Application type:**
- Select: **"Web application"**

**Name:**
- Enter: `BlogCMS Production Web Client`

**Authorized JavaScript origins:**
Click **"+ Add URI"** for each:
```
https://theitapprentice.com
https://www.theitapprentice.com
```

**Authorized redirect URIs:**
Click **"+ Add URI"** for each:
```
https://theitapprentice.com/login
https://www.theitapprentice.com/login
https://theitapprentice.com/register
https://www.theitapprentice.com/register
```

4. Click **"Create"**

**✅ OAuth client created!**

**CRITICAL - Save These Credentials:**
```
Client ID: 123456789-xxxxxxxxxxxxxxxxx.apps.googleusercontent.com
Client Secret: GOCSPX-xxxxxxxxxxxxxxxxxxxxx
```

⚠️ **Copy both values immediately!** You'll need them in next steps.

5. Click **"OK"** to close dialog
6. You can retrieve credentials anytime from the Credentials page

---

## Step 2: Production VM Configuration (5 minutes)

### 2.1 SSH into Production VM

```bash
ssh your-user@theitapprentice.com
# Or use your VPS provider's SSH method
```

### 2.2 Configure Backend Environment

```bash
# Navigate to backend directory
cd /var/www/fastreactcms/backend

# Edit .env file
sudo nano .env
```

**Add these lines to `.env`:**
```env
# ============================================================================
# GOOGLE OAUTH CONFIGURATION (v1.7)
# ============================================================================
GOOGLE_CLIENT_ID=123456789-xxxxxxxxxxxxxxxxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxxxxxxx

# OAuth redirect URIs (production)
GOOGLE_REDIRECT_URI=https://theitapprentice.com/login
```

**Save and exit:**
- Press `Ctrl+X`
- Press `Y` to confirm
- Press `Enter` to save

### 2.3 Configure Frontend Environment

```bash
# Navigate to frontend directory
cd /var/www/fastreactcms/frontend

# Edit .env file
sudo nano .env
```

**Add/update these lines in `.env`:**
```env
# ============================================================================
# GOOGLE OAUTH CONFIGURATION (v1.7)
# ============================================================================
VITE_GOOGLE_CLIENT_ID=123456789-xxxxxxxxxxxxxxxxx.apps.googleusercontent.com

# Backend API URL (production)
VITE_API_URL=https://theitapprentice.com
```

**Save and exit:**
- Press `Ctrl+X`
- Press `Y` to confirm
- Press `Enter` to save

### 2.4 Rebuild Frontend

```bash
# Still in /var/www/fastreactcms/frontend
npm run build
```

**Expected output:**
```
✓ built in 15s
dist/index.html                   0.XX kB
dist/assets/index-XXXXX.js      XXX.XX kB
```

### 2.5 Restart Services

```bash
# Restart backend (FastAPI)
sudo systemctl restart fastreactcms

# Restart frontend SSR (if using)
sudo systemctl restart fastreactcms-ssr

# Check status
sudo systemctl status fastreactcms
sudo systemctl status fastreactcms-ssr
```

**Expected output:**
```
● fastreactcms.service - BlogCMS Backend
     Active: active (running) since ...
```

---

## Step 3: Verify OAuth is Working

### 3.1 Test Frontend Button

1. Open browser (Incognito/Private mode recommended)
2. Navigate to: `https://theitapprentice.com/login`
3. **Look for:** "Sign in with Google" button (with Google logo)
4. **If you see:** Placeholder button → OAuth not configured correctly
5. **If you see:** Real Google button → Configuration successful! ✅

### 3.2 Test OAuth Flow (Full Test)

1. Click **"Sign in with Google"** button
2. **Google popup should appear** (if not, check popup blocker)
3. **Select your Google account**
4. **Grant permissions** (email, profile)
5. **Popup closes** → You're redirected to `/admin` dashboard
6. **Check:** Your name and avatar appear in header
7. **Verify:** User created in database with Google data

**If OAuth fails:**
- Check browser console (F12) for errors
- Check backend logs: `sudo journalctl -u fastreactcms -n 50`
- Verify Client ID matches in both `.env` files

### 3.3 Backend Logs Check

```bash
# Check backend logs for OAuth requests
sudo journalctl -u fastreactcms -n 100 --no-pager | grep -i "oauth\|google"
```

**Expected log entries:**
```
POST /api/v1/auth/oauth/google - 200 OK
🔗 Linking Google account to existing user: user@example.com
✅ User logged in via Google OAuth
```

---

## Step 4: Email Service Configuration (v1.7 Email Verification)

### 4.1 SendGrid Setup (Recommended)

**Option A: SendGrid (Easiest)**

1. Go to [SendGrid](https://sendgrid.com/)
2. Create free account (100 emails/day)
3. Navigate to **Settings** → **API Keys**
4. Click **"Create API Key"**
5. **Name:** `BlogCMS Production`
6. **Permissions:** `Full Access`
7. Click **"Create & View"**
8. **Copy API key:** `SG.xxxxxxxxxxxxxxxxxxxxxxx`

**Add to backend `.env`:**
```bash
cd /var/www/fastreactcms/backend
sudo nano .env
```

```env
# ============================================================================
# EMAIL SERVICE CONFIGURATION (v1.7)
# ============================================================================
# SendGrid API Key
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxx

# Email sender details
EMAIL_FROM=noreply@theitapprentice.com
EMAIL_FROM_NAME=The IT Apprentice

# Frontend URL (for verification links)
FRONTEND_URL=https://theitapprentice.com
```

**Option B: SMTP (Gmail, Outlook, etc.)**

**For Gmail:**
1. Enable 2FA on your Google account
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Copy 16-character password

**Add to backend `.env`:**
```env
# ============================================================================
# SMTP EMAIL CONFIGURATION (Alternative to SendGrid)
# ============================================================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
SMTP_USE_TLS=True

# Email sender details
EMAIL_FROM=your-email@gmail.com
EMAIL_FROM_NAME=The IT Apprentice

# Frontend URL (for verification links)
FRONTEND_URL=https://theitapprentice.com
```

### 4.2 Restart Backend

```bash
sudo systemctl restart fastreactcms
sudo systemctl status fastreactcms
```

### 4.3 Test Email Verification

1. Register new account: `https://theitapprentice.com/register`
2. Fill out form and submit
3. **Check:** Redirected to `/verify-email` page
4. **Check your email:** Verification email received
5. **Click link** in email OR **enter 6-digit code**
6. **Success:** Redirected to login page

**If emails not sending:**
```bash
# Check logs
sudo journalctl -u fastreactcms -n 50 | grep -i "email\|sendgrid\|smtp"
```

---

## Step 5: Production Checklist

### Security

- [ ] ✅ HTTPS enabled (Let's Encrypt SSL)
- [ ] ✅ OAuth credentials saved securely
- [ ] ✅ `.env` files NOT in git (check `.gitignore`)
- [ ] ✅ Firewall configured (ports 80, 443 only)
- [ ] ✅ Backend running on localhost (not public)
- [ ] ✅ CORS configured for production domain only

### OAuth Configuration

- [ ] ✅ Google Cloud project created
- [ ] ✅ OAuth consent screen configured
- [ ] ✅ OAuth client ID created
- [ ] ✅ Authorized domains added
- [ ] ✅ Redirect URIs configured (HTTPS!)
- [ ] ✅ Client ID in frontend `.env`
- [ ] ✅ Client ID + Secret in backend `.env`
- [ ] ✅ Frontend rebuilt with new `.env`
- [ ] ✅ Backend restarted
- [ ] ✅ Google button appears on login page
- [ ] ✅ OAuth flow works (tested)

### Email Verification

- [ ] ✅ SendGrid API key OR SMTP credentials added
- [ ] ✅ Email sender configured
- [ ] ✅ Frontend URL configured
- [ ] ✅ Test email sent successfully
- [ ] ✅ Verification links work

---

## Troubleshooting

### Google Button Not Appearing

**Check frontend `.env`:**
```bash
cd /var/www/fastreactcms/frontend
cat .env | grep GOOGLE_CLIENT_ID
```

**Should show:**
```
VITE_GOOGLE_CLIENT_ID=123456789-xxx.apps.googleusercontent.com
```

**If empty or wrong:**
1. Edit `.env` file
2. Add correct Client ID
3. Rebuild: `npm run build`
4. Restart SSR: `sudo systemctl restart fastreactcms-ssr`

### OAuth Popup Error: "redirect_uri_mismatch"

**Problem:** Redirect URI not authorized in Google Console

**Fix:**
1. Go to Google Cloud Console → Credentials
2. Click your OAuth client ID
3. Add missing redirect URI:
   - `https://theitapprentice.com/login`
   - `https://theitapprentice.com/register`
4. Click **"Save"**
5. Wait 5 minutes for Google to propagate changes
6. Try again

### Backend Error: "Invalid OAuth credentials"

**Check backend `.env`:**
```bash
cd /var/www/fastreactcms/backend
sudo cat .env | grep GOOGLE
```

**Verify:**
- Client ID matches Google Console
- Client Secret matches Google Console
- No extra spaces or quotes

**Fix and restart:**
```bash
sudo nano .env  # Fix credentials
sudo systemctl restart fastreactcms
```

### Emails Not Sending

**Check SendGrid/SMTP credentials:**
```bash
cd /var/www/fastreactcms/backend
sudo cat .env | grep -E "SENDGRID|SMTP|EMAIL"
```

**Test email service:**
```bash
# Check logs for email errors
sudo journalctl -u fastreactcms -n 100 | grep -i "email\|error"
```

**Common issues:**
- SendGrid API key expired/invalid
- Gmail App Password incorrect
- SMTP port blocked by firewall (587, 465)
- Email FROM address not verified in SendGrid

---

## Next Steps

After OAuth is working:

1. **Test all OAuth features:**
   - Login with Google
   - Register with Google
   - Link existing account
   - Avatar sync

2. **Monitor usage:**
   - Check Google Cloud Console → OAuth consent screen
   - View user statistics

3. **Optional: Publish OAuth App**
   - Go to OAuth consent screen
   - Click **"Publish App"**
   - Submit for verification (if >100 users expected)

4. **Configure rate limiting:**
   - Google OAuth has daily quotas
   - Monitor in Cloud Console

---

## Support

**Google OAuth Issues:**
- [Google OAuth Documentation](https://developers.google.com/identity/protocols/oauth2)
- [OAuth Playground](https://developers.google.com/oauthplayground/)

**BlogCMS Issues:**
- Check: `docs/V1.7_RELEASE_NOTES.md`
- Check: `backend/app/auth/oauth.py` (implementation)

---

**🎉 OAuth Setup Complete!**

Users can now sign in with Google on your production site.
