#!/bin/bash
# ============================================================================
# v1.7 Production Deployment Script for theitapprentice.com
# ============================================================================
# Run these commands on your production VM via SSH
# Estimated time: 10-15 minutes
# ============================================================================

echo "=========================================="
echo "v1.7 Production Deployment Starting..."
echo "=========================================="
echo ""

# ============================================================================
# STEP 1: BACKUP EVERYTHING (2 minutes)
# ============================================================================
echo "STEP 1: Creating backups..."
mkdir -p ~/backups/pre-v1.7-$(date +%Y%m%d-%H%M%S)
cd ~/backups/pre-v1.7-$(date +%Y%m%d-%H%M%S)

echo "  - Backing up database..."
sudo -u postgres pg_dump blogcms_db > database_backup.sql

echo "  - Backing up code..."
cp -r /var/www/fastreactcms fastreactcms-backup

echo "  - Verifying backup..."
ls -lh

echo "✅ Backup complete!"
echo ""

# ============================================================================
# STEP 2: PULL v1.7 CODE (1 minute)
# ============================================================================
echo "STEP 2: Pulling v1.7 code from GitHub..."
cd /var/www/fastreactcms

echo "  - Fetching latest..."
git fetch origin

echo "  - Pulling master..."
git pull origin master

echo "  - Verifying commit..."
git log -1 --oneline

echo "✅ Code updated!"
echo ""

# ============================================================================
# STEP 3: RUN DATABASE MIGRATION (2 minutes)
# ============================================================================
echo "STEP 3: Running database migration..."
cd /var/www/fastreactcms/backend

echo "  - Current migration state:"
alembic current

echo "  - Running upgrade..."
alembic upgrade head

echo "  - Verifying migration:"
alembic current

echo "✅ Database migrated!"
echo ""

# ============================================================================
# STEP 4: CONFIGURE BACKEND ENVIRONMENT (1 minute)
# ============================================================================
echo "STEP 4: Configuring backend environment..."
cd /var/www/fastreactcms/backend

echo "  - Opening .env file (add OAuth credentials)..."
echo ""
echo "=========================================="
echo "IMPORTANT: Add these lines to backend/.env"
echo "=========================================="
cat << 'EOF'

# ============================================================================
# GOOGLE OAUTH CONFIGURATION (v1.7)
# ============================================================================
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://theitapprentice.com/login

# ============================================================================
# EMAIL SERVICE CONFIGURATION (v1.7)
# ============================================================================
# SendGrid (add API key when ready)
SENDGRID_API_KEY=

# Email settings
EMAIL_FROM=noreply@theitapprentice.com
EMAIL_FROM_NAME=The IT Apprentice

# Frontend URL (for verification links)
FRONTEND_URL=https://theitapprentice.com
EOF
echo "=========================================="
echo ""

echo "Opening editor..."
sudo nano .env

# Wait for user to finish editing
echo "✅ Backend .env configured!"
echo ""

# ============================================================================
# STEP 5: CONFIGURE FRONTEND ENVIRONMENT (1 minute)
# ============================================================================
echo "STEP 5: Configuring frontend environment..."
cd /var/www/fastreactcms/frontend

echo "  - Opening .env file (add OAuth client ID)..."
echo ""
echo "=========================================="
echo "IMPORTANT: Add/update in frontend/.env"
echo "=========================================="
cat << 'EOF'

# ============================================================================
# GOOGLE OAUTH CONFIGURATION (v1.7)
# ============================================================================
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# ============================================================================
# BACKEND API CONFIGURATION
# ============================================================================
VITE_API_URL=https://theitapprentice.com
EOF
echo "=========================================="
echo ""

echo "Opening editor..."
sudo nano .env

# Wait for user to finish editing
echo "✅ Frontend .env configured!"
echo ""

# ============================================================================
# STEP 6: INSTALL FRONTEND DEPENDENCIES (2 minutes)
# ============================================================================
echo "STEP 6: Installing frontend dependencies..."
cd /var/www/fastreactcms/frontend

echo "  - Running npm install..."
npm install

echo "✅ Dependencies installed!"
echo ""

# ============================================================================
# STEP 7: BUILD FRONTEND (2 minutes)
# ============================================================================
echo "STEP 7: Building frontend for production..."
cd /var/www/fastreactcms/frontend

echo "  - Cleaning old build..."
rm -rf dist

echo "  - Building..."
npm run build

echo "  - Verifying build..."
ls -lh dist/

echo "✅ Frontend built!"
echo ""

# ============================================================================
# STEP 8: RESTART SERVICES (1 minute)
# ============================================================================
echo "STEP 8: Restarting services..."

echo "  - Restarting backend (FastAPI)..."
sudo systemctl restart fastreactcms

echo "  - Restarting frontend (SSR)..."
sudo systemctl restart fastreactcms-ssr

echo "  - Restarting Nginx..."
sudo systemctl restart nginx

echo "  - Checking service status..."
sudo systemctl status fastreactcms --no-pager | head -3
sudo systemctl status fastreactcms-ssr --no-pager | head -3

echo "✅ Services restarted!"
echo ""

# ============================================================================
# STEP 9: VERIFY DEPLOYMENT (1 minute)
# ============================================================================
echo "STEP 9: Verifying deployment..."

echo "  - Testing backend health..."
curl -s https://theitapprentice.com/api/v1/health

echo ""
echo "  - Testing homepage..."
curl -s https://theitapprentice.com | grep -o "<title>.*</title>"

echo ""
echo "  - Testing new pages..."
curl -I https://theitapprentice.com/register 2>&1 | grep "HTTP"
curl -I https://theitapprentice.com/verify-email 2>&1 | grep "HTTP"
curl -I https://theitapprentice.com/login 2>&1 | grep "HTTP"

echo ""
echo "  - Checking backend logs for errors..."
sudo journalctl -u fastreactcms -n 20 --no-pager | grep -i "error\|exception\|fail" || echo "No errors found!"

echo "✅ Verification complete!"
echo ""

# ============================================================================
# DEPLOYMENT COMPLETE!
# ============================================================================
echo "=========================================="
echo "🎉 v1.7 DEPLOYMENT COMPLETE! 🎉"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Open browser: https://theitapprentice.com"
echo "2. Test login page - Google button should be visible"
echo "3. Test register page - form should work"
echo "4. Test OAuth login (if configured)"
echo ""
echo "Optional (configure later):"
echo "- Add SendGrid API key for email verification"
echo "- Test full registration + email verification flow"
echo ""
echo "Documentation:"
echo "- Full guide: docs/V1.7_PRODUCTION_DEPLOYMENT.md"
echo "- Quick ref: docs/V1.7_DEPLOYMENT_QUICK_REFERENCE.md"
echo "- OAuth setup: docs/GOOGLE_OAUTH_PRODUCTION_SETUP.md"
echo ""
echo "=========================================="
