# v1.7 Production Deployment - Manual Commands

**Copy-paste these commands into your production VM SSH session**

---

## ⚡ Quick Deploy (Copy-Paste All)

```bash
# STEP 1: Backup
mkdir -p ~/backups/pre-v1.7-$(date +%Y%m%d)
sudo -u postgres pg_dump blogcms_db > ~/backups/pre-v1.7-$(date +%Y%m%d)/database_backup.sql
echo "✅ Backup complete"

# STEP 2: Pull code
cd /var/www/fastreactcms
git pull origin master
echo "✅ Code updated"

# STEP 3: Database migration
cd /var/www/fastreactcms/backend
alembic upgrade head
echo "✅ Database migrated"

# STEP 4: Configure backend .env
cd /var/www/fastreactcms/backend
sudo nano .env
```

**Add these lines to backend/.env:**
```env
# Google OAuth (v1.7)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/login

# Email Service (v1.7)
SENDGRID_API_KEY=
EMAIL_FROM=noreply@theitapprentice.com
EMAIL_FROM_NAME=The IT Apprentice
FRONTEND_URL=https://theitapprentice.com
```

**Save:** Ctrl+X, Y, Enter

```bash
# STEP 5: Configure frontend .env
cd /var/www/fastreactcms/frontend
sudo nano .env
```

**Add/update these lines in frontend/.env:**
```env
# Google OAuth (v1.7)
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# Backend API
VITE_API_URL=https://theitapprentice.com
```

**Save:** Ctrl+X, Y, Enter

```bash
# STEP 6: Install dependencies & build
cd /var/www/fastreactcms/frontend
npm install
npm run build
echo "✅ Frontend built"

# STEP 7: Restart services
sudo systemctl restart fastreactcms
sudo systemctl restart fastreactcms-ssr
sudo systemctl restart nginx
echo "✅ Services restarted"

# STEP 8: Verify
curl https://theitapprentice.com/api/v1/health
curl -I https://theitapprentice.com/register
echo "✅ Deployment complete!"
```

---

## 🔍 Detailed Steps (If You Prefer)

### 1. Backup Everything

```bash
# Create backup directory
mkdir -p ~/backups/pre-v1.7-$(date +%Y%m%d)
cd ~/backups/pre-v1.7-$(date +%Y%m%d)

# Backup database
sudo -u postgres pg_dump blogcms_db > database_backup.sql

# Backup code
cp -r /var/www/fastreactcms fastreactcms-backup

# Verify
ls -lh
```

**Expected output:** You should see `database_backup.sql` and `fastreactcms-backup/`

---

### 2. Pull v1.7 Code

```bash
# Navigate to app
cd /var/www/fastreactcms

# Pull latest
git fetch origin
git pull origin master

# Verify you got v1.7
git log -1 --oneline
```

**Expected output:** Should show commit starting with `74ad722` or `701791d`

---

### 3. Run Database Migration

```bash
cd /var/www/fastreactcms/backend

# Check current state
alembic current

# Run migration
alembic upgrade head

# Verify
alembic current
```

**Expected output:** `v1_7_oauth_email_verification (head)`

---

### 4. Configure Backend .env

```bash
cd /var/www/fastreactcms/backend
sudo nano .env
```

**Scroll to bottom and add:**

```env
# ============================================================================
# GOOGLE OAUTH CONFIGURATION (v1.7)
# ============================================================================
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://theitapprentice.com/login

# ============================================================================
# EMAIL SERVICE CONFIGURATION (v1.7)
# ============================================================================
# SendGrid API Key (leave empty for now, configure later)
SENDGRID_API_KEY=

# SMTP Alternative (if not using SendGrid)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASSWORD=
# SMTP_USE_TLS=True

# Email sender details
EMAIL_FROM=noreply@theitapprentice.com
EMAIL_FROM_NAME=The IT Apprentice

# Frontend URL (for email verification links)
FRONTEND_URL=https://theitapprentice.com
```

**Save:** Ctrl+X, then Y, then Enter

---

### 5. Configure Frontend .env

```bash
cd /var/www/fastreactcms/frontend
sudo nano .env
```

**If .env doesn't exist, create it with this content:**

```env
# ============================================================================
# BACKEND API CONFIGURATION
# ============================================================================
VITE_API_URL=https://theitapprentice.com

# ============================================================================
# GOOGLE OAUTH CONFIGURATION (v1.7)
# ============================================================================
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# ============================================================================
# APPLICATION CONFIGURATION
# ============================================================================
VITE_APP_NAME=The IT Apprentice
VITE_ENV=production
```

**If .env already exists, just add/update:**

```env
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

**Save:** Ctrl+X, then Y, then Enter

---

### 6. Install Frontend Dependencies

```bash
cd /var/www/fastreactcms/frontend
npm install
```

**Expected output:** Should see `added 2 packages` (OAuth dependencies)

---

### 7. Build Frontend

```bash
cd /var/www/fastreactcms/frontend

# Clean old build
rm -rf dist

# Build new
npm run build
```

**Expected output:**
```
✓ 1234 modules transformed.
dist/index.html                  4.12 kB
dist/assets/index-xxxxx.js     834.23 kB
```

**Verify:**
```bash
ls -lh dist/
```

---

### 8. Restart All Services

```bash
# Restart backend (FastAPI)
sudo systemctl restart fastreactcms

# Restart frontend (SSR)
sudo systemctl restart fastreactcms-ssr

# Restart Nginx
sudo systemctl restart nginx

# Check status
sudo systemctl status fastreactcms --no-pager | head -5
sudo systemctl status fastreactcms-ssr --no-pager | head -5
```

**Expected:** Both services should show `active (running)`

---

### 9. Verify Deployment

```bash
# Test backend health
curl https://theitapprentice.com/api/v1/health

# Test homepage
curl https://theitapprentice.com | grep -o "<title>.*</title>"

# Test new pages
curl -I https://theitapprentice.com/register
curl -I https://theitapprentice.com/verify-email
curl -I https://theitapprentice.com/login

# Check for errors
sudo journalctl -u fastreactcms -n 50 | grep -i "error\|exception"
```

**Expected:**
- Health endpoint returns: `{"status":"healthy"...}`
- All pages return: `HTTP/2 200`
- No critical errors in logs

---

## 🧪 Browser Testing

1. **Open:** https://theitapprentice.com/login
2. **Look for:** "Sign in with Google" button (with Google logo, not placeholder)
3. **Test:** Click the Google button
4. **Expected:** Google OAuth popup appears
5. **Sign in:** Select Google account
6. **Result:** Redirected to /admin dashboard

---

## 🔧 Troubleshooting

### Google Button Not Appearing

**Check frontend .env:**
```bash
cd /var/www/fastreactcms/frontend
cat .env | grep GOOGLE
```

**Should show:**
```
VITE_GOOGLE_CLIENT_ID=117069294573-...
```

**If missing or wrong:**
```bash
sudo nano .env
# Add the correct Client ID
# Save, then rebuild:
npm run build
sudo systemctl restart fastreactcms-ssr nginx
```

---

### OAuth Error: "redirect_uri_mismatch"

**Check your Google Console settings:**
- Authorized JavaScript origins: `https://theitapprentice.com`
- Authorized redirect URIs: `https://theitapprentice.com/login`

**Update if needed, then wait 5 minutes for Google to propagate.**

---

### Backend Won't Start

```bash
# Check logs
sudo journalctl -u fastreactcms -n 100 --no-pager

# Common fix: reinstall dependencies
cd /var/www/fastreactcms/backend
pip install -r requirements.txt
sudo systemctl restart fastreactcms
```

---

### Frontend 404 Errors

```bash
# Rebuild
cd /var/www/fastreactcms/frontend
npm run build

# Restart
sudo systemctl restart fastreactcms-ssr nginx
```

---

## ✅ Deployment Complete Checklist

- [ ] Backup created successfully
- [ ] Code pulled (commit 74ad722 or 701791d)
- [ ] Database migration ran (v1_7_oauth_email_verification)
- [ ] Backend .env configured with OAuth credentials
- [ ] Frontend .env configured with Client ID
- [ ] Frontend dependencies installed
- [ ] Frontend built successfully
- [ ] All services restarted
- [ ] Health check returns 200
- [ ] Homepage loads
- [ ] /register page loads (200)
- [ ] /verify-email page loads (200)
- [ ] /login shows Google button
- [ ] No errors in logs
- [ ] Google OAuth works (button clicks, popup appears)

---

## 🎉 Success!

Your production site now has v1.7 with:
- ✅ Blog category filtering fix
- ✅ Mobile carousel optimization
- ✅ User registration system
- ✅ Email verification system
- ✅ Google OAuth login
- ✅ Admin user management

**Next steps:**
1. Test Google OAuth login
2. Create test account
3. Test email verification (when you add SendGrid key)
4. Access admin user management

**Documentation:**
- Full deployment guide: `docs/V1.7_PRODUCTION_DEPLOYMENT.md`
- OAuth setup: `docs/GOOGLE_OAUTH_PRODUCTION_SETUP.md`
- Quick reference: `docs/V1.7_DEPLOYMENT_QUICK_REFERENCE.md`
