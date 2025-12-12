# 🚀 Production Deployment Guide

## ✅ Pre-Deployment Checklist

**What We're Deploying:**
- ✅ Phase 1: Carousel crossfade & performance improvements
- ✅ Phase 2: Full admin control backend (database migration)
- ✅ Phase 3: Mobile optimization (touch-friendly UI)
- ✅ Phase 4: Security improvements (CSP-compliant Analytics)

**Commits Pushed:**
```
115a38e feat(security): Phase 4 - CSP-compliant Analytics & AdSense
d530ac7 feat(homepage): Phase 2 Frontend + Phase 3 Mobile
a63c2f6 feat(homepage): Phase 2 - full admin control backend
0ad841d feat(homepage): Phase 1 - carousel crossfade & performance
```

---

## 🔧 Production Deployment Steps

### Step 1: SSH into Production Server
```bash
ssh your-server
```

### Step 2: Navigate to Project Directory
```bash
cd /var/www/fastreactcms
```

### Step 3: Pull Latest Code
```bash
git pull origin master
```

**Expected Output:**
```
Updating 66f325b..115a38e
Fast-forward
 ANALYTICS_SETUP.md                                 | 263 +++++++++++++++++
 Frontend/src/App.tsx                               |  47 +--
 Frontend/src/components/analytics/AdSenseAd.tsx    | 183 +++++++++++
 Frontend/src/components/analytics/GoogleAnalytics.tsx | 231 +++++++-------
 Frontend/src/components/home/CategoryShowcase.tsx  |  30 +-
 Frontend/src/components/home/FeaturedCarousel.tsx  |  45 +--
 Frontend/src/components/home/RecentPostsGrid.tsx   |  38 +--
 Frontend/src/hooks/useSiteSettings.ts              |  24 ++
 Frontend/src/pages/BlogHome.tsx                    |  44 +--
 Frontend/src/pages/admin/SiteSettings.tsx          | 333 ++++++++++++++++++++-
 Frontend/src/utils/analytics.ts                    |  58 ++++
 Frontend/vite.config.ts                            |   7 +
 12 files changed, 1165 insertions(+), 138 deletions(-)
```

### Step 4: Install Frontend Dependencies (if package.json changed)
```bash
cd Frontend
npm install
```

### Step 5: Build Frontend
```bash
npm run build
```

**Expected Output:**
```
vite v5.x.x building for production...
✓ 1234 modules transformed.
dist/index.html                   1.23 kB
dist/assets/index-abc123.js     234.56 kB │ gzip: 78.90 kB
✓ built in 12.34s
```

**Verify Build:**
```bash
ls -lh dist/
# Should show: index.html, assets/, etc.
```

### Step 6: Run Database Migration (IMPORTANT!)
```bash
cd /var/www/fastreactcms/Backend

# Activate virtual environment
source venv/bin/activate

# Run migration
alembic upgrade head
```

**Expected Output:**
```
INFO  [alembic.runtime.migration] Running upgrade xxx -> yyy, add homepage layout settings
```

**If you get "No such revision":**
```bash
# Create the migration
alembic revision --autogenerate -m "add homepage layout settings"

# Then run upgrade
alembic upgrade head
```

### Step 7: Restart Backend Service
```bash
sudo systemctl restart fastreactcms-backend
```

**Verify Backend is Running:**
```bash
sudo systemctl status fastreactcms-backend
```

**Expected Output:**
```
● fastreactcms-backend.service - FastReactCMS Backend
   Active: active (running) since ...
```

### Step 8: Verify Nginx is Serving Frontend
```bash
# Nginx should already be configured to serve from Frontend/dist
# Just verify the config points to the right location
cat /etc/nginx/sites-available/fastreactcms | grep -A 5 "location /"
```

**Should see:**
```nginx
location / {
    root /var/www/fastreactcms/Frontend/dist;
    try_files $uri $uri/ /index.html;
}
```

**No need to restart nginx** - it serves static files, just refreshing browser is enough!

---

## 🧪 Post-Deployment Testing

### 1. Test Homepage Loading
```bash
curl -I https://yourdomain.com
```
**Expected:** `HTTP/1.1 200 OK`

### 2. Test Backend API
```bash
curl https://yourdomain.com/api/v1/admin/site-settings
```
**Expected:** `{"detail":"Could not validate credentials"}` (normal - you're not authenticated)

### 3. Test in Browser

**Open:** `https://yourdomain.com`

**Check Console (F12):**
```
[GA] Initializing Google Analytics: G-TMWQPFXFJJ
[GA] Loaded successfully
[GA] Page view: /
```

**Test Admin Panel:**
1. Navigate to: `https://yourdomain.com/admin/site-settings`
2. Login with admin credentials
3. Click "Homepage Layout" tab
4. Should see toggle switches for sections ✅
5. Toggle "Show Carousel" OFF → Go to homepage → Carousel disappears ✅
6. Save settings → Should see green success message ✅

**Test Mobile:**
1. Open DevTools (F12) → Toggle device toolbar (Ctrl+Shift+M)
2. Select iPhone SE (375px)
3. Carousel arrows should be touch-friendly ✅
4. Categories should fit in 2 columns ✅
5. All touch targets should be large (44x44px minimum) ✅

---

## 🔧 Troubleshooting

### Backend Won't Start
```bash
# Check logs
sudo journalctl -u fastreactcms-backend -n 50 --no-pager

# Common issues:
# - Database connection error → Check DATABASE_URL in .env
# - Port already in use → Check if old process is running
# - Permission errors → Check file ownership
```

### Frontend Not Updating
```bash
# Hard refresh in browser: Ctrl+Shift+R
# Or clear browser cache

# Verify build succeeded
ls -lh /var/www/fastreactcms/Frontend/dist/

# Check nginx is serving from correct location
sudo nginx -t
```

### Database Migration Fails
```bash
# Check current migration status
cd /var/www/fastreactcms/Backend
source venv/bin/activate
alembic current

# If stuck, check migration history
alembic history

# Manual SQL (last resort):
psql -U your_db_user -d your_db_name
# Then manually add columns from the migration file
```

### Analytics Not Loading
```bash
# 1. Check admin panel has Analytics ID: G-TMWQPFXFJJ
# 2. Check browser console for errors
# 3. Verify CSP headers aren't blocking scripts
curl -I https://yourdomain.com | grep -i "content-security"
```

---

## 📊 Expected Database Changes

The migration adds these columns to `site_settings` table:
```sql
ALTER TABLE site_settings ADD COLUMN show_carousel BOOLEAN DEFAULT TRUE;
ALTER TABLE site_settings ADD COLUMN carousel_title VARCHAR(100);
ALTER TABLE site_settings ADD COLUMN carousel_subtitle VARCHAR(200);
ALTER TABLE site_settings ADD COLUMN carousel_limit INTEGER DEFAULT 5;
ALTER TABLE site_settings ADD COLUMN carousel_autoplay BOOLEAN DEFAULT TRUE;
ALTER TABLE site_settings ADD COLUMN carousel_interval INTEGER DEFAULT 7000;

ALTER TABLE site_settings ADD COLUMN show_categories BOOLEAN DEFAULT TRUE;
ALTER TABLE site_settings ADD COLUMN categories_title VARCHAR(100);
ALTER TABLE site_settings ADD COLUMN categories_subtitle VARCHAR(200);
ALTER TABLE site_settings ADD COLUMN categories_limit INTEGER DEFAULT 6;

ALTER TABLE site_settings ADD COLUMN show_recent_posts BOOLEAN DEFAULT TRUE;
ALTER TABLE site_settings ADD COLUMN recent_posts_title VARCHAR(100);
ALTER TABLE site_settings ADD COLUMN recent_posts_subtitle VARCHAR(200);
ALTER TABLE site_settings ADD COLUMN recent_posts_limit INTEGER DEFAULT 6;
```

---

## ✅ Deployment Complete Checklist

- [ ] Code pulled from GitHub successfully
- [ ] Frontend build completed with no errors
- [ ] Database migration ran successfully
- [ ] Backend service restarted and running
- [ ] Homepage loads without errors
- [ ] Console shows Analytics loading
- [ ] Admin panel "Homepage Layout" tab visible
- [ ] Settings save successfully
- [ ] Toggle switches work (sections show/hide)
- [ ] Mobile view looks good (touch-friendly)
- [ ] No console errors or warnings

---

## 🎉 Success!

Your production deployment is complete! All 4 phases are now live:

1. ✅ **Carousel Improvements** - Smooth crossfade animations
2. ✅ **Admin Controls** - Full homepage customization
3. ✅ **Mobile Optimization** - Touch-friendly UI
4. ✅ **Security** - CSP-compliant Analytics

**Configure Analytics:**
1. Go to: `https://yourdomain.com/admin/site-settings`
2. Click "Analytics & Ads" tab
3. Enter: `G-TMWQPFXFJJ`
4. Save!

**Next Steps:**
- Monitor server logs for any errors
- Test all features in production
- Configure homepage layout via admin panel
- Enjoy your improved CMS! 🚀
