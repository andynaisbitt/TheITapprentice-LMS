# RSS/Sitemap Fix Deployment Steps

## Problem
- RSS feed and sitemap were showing hardcoded `https://yourdomain.com` URLs
- nginx was not correctly proxying `/rss.xml` and `/sitemap.xml` to backend API

## Solution
1. Added `site_url` and `site_description` fields to `theme_settings` table
2. Updated RSS and sitemap generators to read from database
3. Fixed nginx configuration to proxy to correct API endpoints

## Deployment Steps (Production Server)

### 1. Pull Latest Code
```bash
cd /var/www/fastreactcms
git pull origin master
```

### 2. Run Database Migration
```bash
cd Backend
source venv/bin/activate  # or your virtualenv activation
alembic upgrade head
```

### 3. Update Site Settings in Database
```bash
# Connect to PostgreSQL
psql -U blogcms_user -d blogcms_db

# Update theme_settings with your actual domain
UPDATE theme_settings
SET site_url = 'https://theitapprentice.com',
    site_name = 'The IT Apprentice',
    site_description = 'A Blog about Software Development and Cloud Computing'
WHERE id = 1;

# Verify
SELECT site_name, site_url, site_description FROM theme_settings;

# Exit
\q
```

### 4. Update nginx Configuration
```bash
# Backup current config
sudo cp /etc/nginx/sites-available/fastreactcms /etc/nginx/sites-available/fastreactcms.backup

# Copy new config
sudo cp /var/www/fastreactcms/nginx-fastreactcms-FINAL.conf /etc/nginx/sites-available/fastreactcms

# Test nginx config
sudo nginx -t

# If test passes, reload nginx
sudo systemctl reload nginx
```

### 5. Restart Backend Service
```bash
sudo systemctl restart fastreactcms-backend
# or
sudo systemctl restart uvicorn
```

### 6. Test the Fixes
```bash
# Test RSS feed
curl https://theitapprentice.com/rss.xml | head -20

# Test sitemap
curl https://theitapprentice.com/sitemap.xml | head -20
```

Expected output should show:
- `<link>https://theitapprentice.com</link>` (NOT yourdomain.com)
- `<title>The IT Apprentice</title>` (your actual site name)

## Files Changed
- `Backend/app/api/v1/services/theme/models.py` - Added fields
- `Backend/app/api/v1/services/theme/schemas.py` - Added fields
- `Backend/app/api/v1/endpoints/blog/rss.py` - Dynamic URLs
- `Backend/app/api/v1/endpoints/blog/sitemap.py` - Dynamic URLs
- `Backend/alembic/versions/5176ac1d7056_*.py` - Migration
- `nginx-fastreactcms-FINAL.conf` - Fixed proxy paths

## Rollback (if needed)
```bash
# Restore nginx config
sudo cp /etc/nginx/sites-available/fastreactcms.backup /etc/nginx/sites-available/fastreactcms
sudo systemctl reload nginx

# Rollback database
cd /var/www/fastreactcms/Backend
alembic downgrade -1

# Restart service
sudo systemctl restart fastreactcms-backend
```

## Notes
- The RSS/sitemap will now always use values from `theme_settings` table
- Update site settings via admin panel or directly in database
- nginx config change is critical - old config proxied to wrong endpoint
