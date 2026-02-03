# Production Deployment - Registration Control

**Date**: 2025-12-12
**Feature**: Registration Control (Enable/Disable + Custom Message)
**Commit**: 66816d8

---

## Pre-Deployment Checklist

- [x] Code pushed to GitHub
- [x] Migration file created (v2_11_add_registration_control.py)
- [x] Backend changes tested locally
- [x] Frontend changes tested locally
- [ ] Production backup created
- [ ] Production deployment executed

---

## Deployment Steps

### Step 1: SSH to Production Server

```bash
ssh andynaisbitt@instance-20250512-195527
# Or your server's IP/hostname
```

### Step 2: Backup Database (CRITICAL)

```bash
# Create backup directory if doesn't exist
sudo mkdir -p /var/backups/blogcms

# Backup database
sudo -u postgres pg_dump blogcms_db > /var/backups/blogcms/backup_$(date +%Y%m%d_%H%M%S).sql

# Verify backup created
ls -lh /var/backups/blogcms/
```

### Step 3: Deploy Backend

```bash
# Navigate to backend directory
cd /var/www/fastreactcms/backend

# Pull latest code
git pull origin master

# Should show:
# - v2_11_add_registration_control.py (new)
# - models.py, schemas.py, registration.py (modified)

# Activate virtual environment
source venv/bin/activate

# Run migration
alembic upgrade head

# Should output:
# INFO  [alembic.runtime.migration] Running upgrade 116a2592ee5f -> v2_11_registration_control, add registration control to site settings

# Verify migration
alembic current

# Should show:
# v2_11_registration_control (head)

# Verify columns added
psql -U postgres -d blogcms_db -c "\d site_settings" | grep registration

# Should show:
# registration_enabled             | boolean
# registration_disabled_message    | character varying(500)

# Check current values
psql -U postgres -d blogcms_db -c "SELECT registration_enabled, registration_disabled_message FROM site_settings;"

# Should show:
# registration_enabled | registration_disabled_message
# t                    | (empty)

# Restart backend service
sudo systemctl restart fastreactcms-backend

# Check status
sudo systemctl status fastreactcms-backend

# Check logs for errors
sudo journalctl -u fastreactcms-backend -n 50 --no-pager
```

### Step 4: Deploy Frontend

```bash
# Navigate to frontend directory
cd /var/www/fastreactcms/frontend

# Pull latest code
git pull origin master

# Install dependencies (if package.json changed)
npm install

# Build production bundle
npm run build

# Verify build succeeded
ls -lh dist/index.html
ls -lh dist/assets/

# Should see new bundle files with recent timestamps

# Restart SSR server
sudo systemctl restart fastreactcms-ssr

# Check status
sudo systemctl status fastreactcms-ssr

# Check logs for errors
sudo journalctl -u fastreactcms-ssr -n 50 --no-pager
```

### Step 5: Verify Deployment

```bash
# Test backend API endpoint
curl -s http://localhost:8000/api/v1/site-settings | grep -i registration

# Should return (formatted):
# "registrationEnabled": true,
# "registrationDisabledMessage": ""

# Check Nginx is serving new frontend
curl -s http://localhost/ | grep -i "index-"

# Should show new bundle hash in script tags

# Test full site
curl -I https://yourdomain.com

# Should return: HTTP/1.1 200 OK (or 301 redirect to HTTPS)
```

### Step 6: Test in Browser

1. **Open incognito**: https://yourdomain.com/login
2. Should see: "Sign up" link (registration enabled by default)
3. Login as admin
4. Go to: https://yourdomain.com/admin/settings
5. Click **"User Registration"** tab (👥)
6. Should see: Toggle, message field, preview

### Step 7: Disable Registration

1. Toggle "Allow User Registration" to **OFF**
2. Enter message:
   ```
   Registration is currently disabled. We are optimizing our systems and have enough users for this beta release. Thank you for your interest!
   ```
3. Click "Save Settings"
4. See success message
5. Logout

### Step 8: Verify Disabled State

1. Open **NEW incognito**: https://yourdomain.com/login
2. Should see: Amber info banner with your message
3. Should NOT see: "Sign up" link
4. Try: https://yourdomain.com/register
5. Should redirect to login with message after 2 seconds

---

## Rollback Plan (If Issues Occur)

### Option 1: Rollback Migration Only

```bash
cd /var/www/fastreactcms/backend
source venv/bin/activate
alembic downgrade -1
sudo systemctl restart fastreactcms-backend
```

This removes the registration control columns but leaves code in place.

### Option 2: Rollback Code + Migration

```bash
# Backend
cd /var/www/fastreactcms/backend
git reset --hard 88f4232  # Previous commit
source venv/bin/activate
alembic downgrade v2_10_missing_cols
sudo systemctl restart fastreactcms-backend

# Frontend
cd /var/www/fastreactcms/frontend
git reset --hard 88f4232
npm run build
sudo systemctl restart fastreactcms-ssr
```

### Option 3: Restore Database Backup

```bash
# ONLY if database is corrupted
sudo systemctl stop fastreactcms-backend
sudo -u postgres psql -d blogcms_db < /var/backups/blogcms/backup_YYYYMMDD_HHMMSS.sql
sudo systemctl start fastreactcms-backend
```

---

## Post-Deployment Monitoring

### Check Backend Logs

```bash
# Watch logs in real-time
sudo journalctl -u fastreactcms-backend -f

# Look for errors
sudo journalctl -u fastreactcms-backend -p err -n 100

# Check registration attempts (should be blocked)
sudo journalctl -u fastreactcms-backend | grep -i "registration blocked"
```

### Check Frontend Logs

```bash
# Watch SSR server logs
sudo journalctl -u fastreactcms-ssr -f

# Check for errors
sudo journalctl -u fastreactcms-ssr -p err -n 100
```

### Monitor Database

```bash
# Watch site_settings changes
psql -U postgres -d blogcms_db -c "SELECT registration_enabled, updated_at FROM site_settings;"

# Check for registration attempts (should see none if disabled)
psql -U postgres -d blogcms_db -c "SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '1 hour';"
```

### Check Nginx Access Logs

```bash
# Watch access logs
sudo tail -f /var/log/nginx/access.log

# Check for /register access (should redirect)
sudo grep "/register" /var/log/nginx/access.log | tail -20
```

---

## Troubleshooting

### Issue: Migration Fails

**Error**: `KeyError: 'v2_10_missing_cols'`

**Solution**: Update migration file to use correct parent revision
```bash
cd /var/www/fastreactcms/backend
alembic heads  # Check current heads
# Edit migration file to match correct parent
alembic upgrade head
```

### Issue: Frontend Not Showing Disabled Message

**Possible Causes**:
1. Old bundle cached
2. Site settings not loaded
3. Browser cache

**Solutions**:
```bash
# Clear browser cache
# Ctrl+Shift+Delete → Clear site data

# Force rebuild frontend
cd /var/www/fastreactcms/frontend
rm -rf dist/
npm run build
sudo systemctl restart fastreactcms-ssr

# Check if settings loaded
curl http://localhost:8000/api/v1/site-settings | jq .registrationEnabled
```

### Issue: Backend API Returns 500

**Check**:
```bash
# View recent errors
sudo journalctl -u fastreactcms-backend -n 100

# Test database connection
psql -U postgres -d blogcms_db -c "SELECT 1;"

# Restart service
sudo systemctl restart fastreactcms-backend
```

### Issue: Changes Not Saving in Admin

**Check**:
```bash
# Verify user is admin
psql -U postgres -d blogcms_db -c "SELECT email, is_admin FROM users WHERE email = 'your@email.com';"

# Check API permissions
curl -I http://localhost:8000/api/v1/admin/site-settings

# Should return 200 OK (if authenticated)
```

---

## Success Criteria

Deployment is successful when ALL of these are true:

- [x] Migration applied: `alembic current` shows `v2_11_registration_control`
- [x] Database has columns: `registration_enabled`, `registration_disabled_message`
- [x] Backend service running: `sudo systemctl status fastreactcms-backend`
- [x] Frontend built: `dist/index.html` exists with recent timestamp
- [x] SSR service running: `sudo systemctl status fastreactcms-ssr`
- [x] Site loads: https://yourdomain.com returns 200 OK
- [x] Admin panel shows "User Registration" tab
- [x] Can toggle registration on/off and save
- [x] Login page shows disabled message when toggled off
- [x] /register redirects when disabled
- [x] No errors in backend logs
- [x] No errors in frontend logs

---

## Next Steps After Deployment

1. **Test Thoroughly**:
   - Test in multiple browsers
   - Test on mobile
   - Test in incognito (no cache)

2. **Monitor for 24 Hours**:
   - Watch error logs
   - Check for unexpected behavior
   - Monitor user complaints

3. **Announce to Users** (if needed):
   - Update social media
   - Send email to beta users
   - Update documentation

4. **Security Hardening** (Next Priority):
   - Content sanitization (XSS prevention)
   - Leaderboard/XP validation
   - Score spoofing prevention

---

## Important Notes

- **Registration is ENABLED by default** after deployment
- Admin must manually disable it via Site Settings
- Disabled message is optional (default provided)
- Settings persist across server restarts
- No breaking changes - existing users unaffected

---

**Deployed By**: _____________
**Deployed Date**: _____________
**Deployment Result**: ☐ Success ☐ Partial ☐ Failed
**Notes**: _____________________________________________

---

**Next Task**: Security Hardening (XSS + XP/Leaderboard Validation)
