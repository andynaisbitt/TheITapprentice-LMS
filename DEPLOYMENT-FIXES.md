# BlogCMS V1.1 - Deployment Instructions

**Date**: 2025-12-05
**Status**: Ready for deployment to production

---

## 🚀 FIXED ISSUES

### ✅ #1: Mobile Hamburger Menu Crash (CRITICAL)
**Status**: FIXED
**Files Changed**: `Frontend/src/components/layout/Header.tsx`

**Problem**: React hook (`useState`) being called inside render function causing React #310 error

**Fix Applied**:
- Converted `renderMobileNavItem` function to proper React component `MobileNavItem`
- Moved `useState` hook to component level (legal placement)
- Updated mobile menu to use `<MobileNavItem />` component

**Action Required**: Rebuild frontend and deploy

---

### ✅ #3 & #4: RSS Feed & Sitemap Broken (HIGH PRIORITY)
**Status**: FIXED
**Files Changed**:
- `nginx-config.conf`
- `Frontend/src/components/layout/Footer.tsx`

**Problem**:
- Footer linked to `/rss` and `/sitemap` but backend serves `/rss.xml` and `/sitemap.xml`
- React Router was catching requests first, causing redirects to homepage
- nginx wasn't proxying XML routes to backend

**Fix Applied**:
1. Added nginx location blocks for `/rss.xml` and `/sitemap.xml` (BEFORE React fallback)
2. Changed footer links from `<Link>` to `<a href>` tags pointing to correct URLs
3. Added `target="_blank"` to open in new tab (standard for feeds)

**Action Required**:
1. Update nginx config on server
2. Test nginx config: `sudo nginx -t`
3. Reload nginx: `sudo systemctl reload nginx`
4. Rebuild and deploy frontend

---

### ⚠️ #2: Image Uploads Not Displaying (CRITICAL)
**Status**: NEEDS SERVER-SIDE FIX
**Files Changed**: None (backend code is correct)

**Problem**: Images upload successfully but return 404 when accessed

**Root Cause**:
- Backend saves to `Backend/static/blog/uploads/2025/12/[hash].png`
- nginx serves from `/var/www/fastreactcms/Backend/static/`
- Directory may not exist OR file permissions are incorrect

**Diagnosis Steps** (run on server):
```bash
# 1. Check if static directory exists
ls -la /var/www/fastreactcms/Backend/static/

# 2. Check if uploads directory exists
ls -la /var/www/fastreactcms/Backend/static/blog/uploads/

# 3. Check directory permissions
ls -ld /var/www/fastreactcms/Backend/static/

# 4. Check uploaded files (if any exist)
find /var/www/fastreactcms/Backend/static/ -type f -name "*.png" -o -name "*.jpg"
```

**Fix Required on Server**:
```bash
# Navigate to backend directory
cd /var/www/fastreactcms/Backend

# Create static directory structure if missing
mkdir -p static/blog/uploads

# Set correct ownership (replace 'www-data' with your nginx user if different)
sudo chown -R www-data:www-data static/

# Set correct permissions
sudo chmod -R 755 static/
sudo chmod -R 775 static/blog/uploads/  # Write permissions for uploads

# Verify
ls -la static/
```

**Test After Fix**:
1. Upload a test image in admin panel
2. Check if file exists: `ls -la static/blog/uploads/2025/12/`
3. Try accessing image URL directly in browser
4. Check nginx error logs if still failing: `sudo tail -f /var/log/nginx/theitapprentice.error.log`

---

## 📦 DEPLOYMENT CHECKLIST

### Step 1: Local Build
```bash
# Navigate to project root
cd "C:\Gitlab Projects\BlogCMS"

# Frontend build
cd Frontend
npm install  # If dependencies changed
npm run build

# Backend (no changes needed for this deployment)
# cd Backend
# source venv/bin/activate  # or venv\Scripts\activate on Windows
# pip install -r requirements.txt
```

### Step 2: Upload Files to Server
```bash
# From local machine (PowerShell or Git Bash)
# Replace with your actual server details

# Upload frontend build
scp -r Frontend/dist/* user@35.230.128.169:/var/www/fastreactcms/Frontend/dist/

# Upload updated nginx config
scp nginx-config.conf user@35.230.128.169:/tmp/nginx-config.conf

# Note: Backend code unchanged, no upload needed
```

### Step 3: Server-Side Deployment
```bash
# SSH into server
ssh user@35.230.128.169

# 1. Fix image upload directory
cd /var/www/fastreactcms/Backend
sudo mkdir -p static/blog/uploads
sudo chown -R www-data:www-data static/
sudo chmod -R 755 static/
sudo chmod -R 775 static/blog/uploads/

# 2. Update nginx config
sudo cp /tmp/nginx-config.conf /etc/nginx/sites-available/theitapprentice.com
sudo nginx -t  # Test config
sudo systemctl reload nginx  # Apply changes

# 3. Restart backend (if needed)
# sudo systemctl restart fastreactcms-backend

# 4. Verify frontend files deployed
ls -la /var/www/fastreactcms/Frontend/dist/

# 5. Clear browser cache or hard refresh (Ctrl+Shift+R)
```

### Step 4: Verification
```bash
# Test on server
curl -I https://theitapprentice.com/rss.xml  # Should return 200 OK
curl -I https://theitapprentice.com/sitemap.xml  # Should return 200 OK

# Test in browser
1. Visit https://theitapprentice.com on mobile - test hamburger menu
2. Click RSS Feed link in footer - should open XML feed
3. Click Sitemap link in footer - should open XML sitemap
4. Upload test image in admin panel
5. Verify image displays in post preview
```

---

## 🐛 REMAINING ISSUES (Not Fixed Yet)

### Not Addressed in This Deployment:
- **#5**: URL slug system (pages get `/pages/` prefix) - requires backend + DB migration
- **#6**: "View Post" button after saving - requires frontend work
- **#7**: Light mode checkbox visibility - requires CSS fix
- **#8**: Seed data for fresh installs - requires SQL script

These will be addressed in V1.2.

---

## 🔄 ROLLBACK PROCEDURE (If Something Breaks)

### Rollback nginx:
```bash
# If you have a backup
sudo cp /etc/nginx/sites-available/theitapprentice.com.backup /etc/nginx/sites-available/theitapprentice.com
sudo nginx -t
sudo systemctl reload nginx
```

### Rollback Frontend:
```bash
# Re-upload previous dist/ folder from backup
scp -r Frontend-backup/dist/* user@server:/var/www/fastreactcms/Frontend/dist/
```

---

## 📝 NOTES

### Changes Summary:
- **Frontend**: 2 files changed (Header.tsx, Footer.tsx)
- **nginx**: 1 file changed (added RSS/sitemap routes)
- **Backend**: No code changes (directory permissions only)

### Testing Priority:
1. **Critical**: Mobile menu (was completely broken)
2. **High**: Image uploads (can't add content without this)
3. **Medium**: RSS/Sitemap (SEO impact but not blocking)

### Browser Cache:
After deployment, users may need to hard refresh (Ctrl+Shift+R) to see the hamburger menu fix due to aggressive caching on static assets.

---

**Ready to deploy!** 🚀

Questions? Issues? Check:
- nginx error log: `/var/log/nginx/theitapprentice.error.log`
- Backend logs: `journalctl -u fastreactcms-backend -f`
- Browser console (F12) for frontend errors
