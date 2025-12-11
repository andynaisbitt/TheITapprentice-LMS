# FastReactCMS Quick Reference Guide

Quick commands for managing your production server.

---

## 🚀 Deployment Workflow

### 1. Pull Latest Code
```bash
cd /var/www/fastreactcms
git pull origin master
```

### 2. Update Backend
```bash
cd /var/www/fastreactcms/Backend
source venv/bin/activate
alembic upgrade head
sudo systemctl restart fastreactcms-backend
```

### 3. Update Frontend
```bash
cd /var/www/fastreactcms/Frontend
npm install  # if package.json changed
npm run build
sudo systemctl reload nginx
```

### 4. Update SSR Server (if server.js changed)
```bash
cd /var/www/fastreactcms/ssr
sudo cp /var/www/fastreactcms/Frontend/server.js .
sudo systemctl restart fastreactcms-ssr
```

---

## 🔧 Service Management

### Check All Services
```bash
bash check-services.sh
```

### Individual Service Commands

**Backend API:**
```bash
sudo systemctl status fastreactcms-backend    # Check status
sudo systemctl start fastreactcms-backend     # Start
sudo systemctl stop fastreactcms-backend      # Stop
sudo systemctl restart fastreactcms-backend   # Restart
sudo journalctl -u fastreactcms-backend -f    # View logs
```

**SSR Server:**
```bash
sudo systemctl status fastreactcms-ssr    # Check status
sudo systemctl start fastreactcms-ssr     # Start
sudo systemctl stop fastreactcms-ssr      # Stop
sudo systemctl restart fastreactcms-ssr   # Restart
sudo journalctl -u fastreactcms-ssr -f    # View logs
```

**NGINX:**
```bash
sudo systemctl status nginx       # Check status
sudo nginx -t                     # Test configuration
sudo systemctl reload nginx       # Reload config
sudo systemctl restart nginx      # Restart
```

---

## 📋 Health Checks

### Quick Health Check
```bash
# Backend API
curl http://localhost:8100/health

# SSR Server
curl http://localhost:3001/health

# Public site
curl https://theitapprentice.com
```

### Detailed Health Check
```bash
# Check all services
bash check-services.sh

# Or manually:
sudo systemctl status fastreactcms-backend
sudo systemctl status fastreactcms-ssr
sudo systemctl status nginx
sudo systemctl status postgresql
```

---

## 🐛 Troubleshooting

### Service Won't Start

**1. Check logs:**
```bash
# Backend
sudo journalctl -u fastreactcms-backend -n 100 --no-pager

# SSR
sudo journalctl -u fastreactcms-ssr -n 100 --no-pager
sudo cat /var/log/fastreactcms-ssr-error.log
```

**2. Check configuration:**
```bash
# Backend: check .env file
cat /var/www/fastreactcms/Backend/.env

# NGINX: test config
sudo nginx -t
```

**3. Check file permissions:**
```bash
ls -la /var/www/fastreactcms/
ls -la /var/www/fastreactcms/ssr/
```

### Port Already in Use

**Find process using port:**
```bash
sudo lsof -i :8100  # Backend
sudo lsof -i :3001  # SSR
```

**Kill process:**
```bash
sudo kill <PID>
```

### Database Issues

**Check PostgreSQL:**
```bash
sudo systemctl status postgresql
sudo -u postgres psql -l
```

**Connect to database:**
```bash
sudo -u postgres psql fastreactcms
```

**Check migrations:**
```bash
cd /var/www/fastreactcms/Backend
source venv/bin/activate
alembic current
alembic history
```

---

## 📊 Logs

### View Live Logs
```bash
# Backend API
sudo journalctl -u fastreactcms-backend -f

# SSR Server
sudo journalctl -u fastreactcms-ssr -f

# NGINX Access
sudo tail -f /var/log/nginx/theitapprentice.access.log

# NGINX Errors
sudo tail -f /var/log/nginx/theitapprentice.error.log
```

### View Recent Logs
```bash
# Backend (last 50 lines)
sudo journalctl -u fastreactcms-backend -n 50 --no-pager

# SSR (last 50 lines)
sudo journalctl -u fastreactcms-ssr -n 50 --no-pager

# NGINX (last 50 lines)
sudo tail -n 50 /var/log/nginx/theitapprentice.error.log
```

### Search Logs
```bash
# Search for errors in backend
sudo journalctl -u fastreactcms-backend | grep -i error

# Search for specific term
sudo journalctl -u fastreactcms-backend | grep "canonical"

# Search by time
sudo journalctl -u fastreactcms-backend --since "1 hour ago"
```

---

## 🔍 SEO & Canonical URLs

### Test Canonical URL
```bash
# Test API endpoint
curl "http://localhost:8100/api/v1/content/by-canonical?url=https://theitapprentice.com/RAM-Price-Spikes"

# Test as crawler
curl -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
  "https://theitapprentice.com/RAM-Price-Spikes"
```

### Check Database for Canonical URLs
```bash
sudo -u postgres psql fastreactcms -c \
  "SELECT id, title, canonical_url FROM blog_posts WHERE canonical_url IS NOT NULL;"
```

### Test SSR Meta Tags
```bash
# Run diagnostic script
cd /var/www/fastreactcms
node test-seo.js

# Manual test as crawler
curl -H "User-Agent: Googlebot" \
  "https://theitapprentice.com/blog/your-post-slug" | grep "<title>"
```

---

## 📁 Important Paths

```
/var/www/fastreactcms/                    # Project root
  ├── Backend/                            # Backend API
  │   ├── .env                           # Environment variables
  │   ├── venv/                          # Python virtual environment
  │   └── alembic/                       # Database migrations
  ├── Frontend/                          # Frontend React app
  │   ├── dist/                          # Built files (served by NGINX)
  │   └── server.js                      # SSR server source
  └── ssr/                               # SSR server runtime
      ├── server.js                      # Copied from Frontend/
      ├── package.json                   # Node dependencies
      └── node_modules/                  # Installed packages

/etc/systemd/system/
  ├── fastreactcms-backend.service      # Backend systemd unit
  └── fastreactcms-ssr.service          # SSR systemd unit

/etc/nginx/
  ├── nginx.conf                        # Main NGINX config
  └── sites-available/
      └── theitapprentice.com           # Site config

/var/log/
  ├── fastreactcms-ssr.log             # SSR stdout logs
  ├── fastreactcms-ssr-error.log       # SSR stderr logs
  └── nginx/
      ├── theitapprentice.access.log   # NGINX access logs
      └── theitapprentice.error.log    # NGINX error logs
```

---

## 🔐 Database Commands

### Backup Database
```bash
sudo -u postgres pg_dump fastreactcms > backup_$(date +%Y%m%d).sql
```

### Restore Database
```bash
sudo -u postgres psql fastreactcms < backup_20250101.sql
```

### Check Database Size
```bash
sudo -u postgres psql -c "\l+" fastreactcms
```

### Useful Queries
```bash
# Count posts
sudo -u postgres psql fastreactcms -c \
  "SELECT COUNT(*) FROM blog_posts;"

# Recent posts
sudo -u postgres psql fastreactcms -c \
  "SELECT id, title, published, created_at FROM blog_posts ORDER BY created_at DESC LIMIT 10;"

# Posts with canonical URLs
sudo -u postgres psql fastreactcms -c \
  "SELECT id, title, canonical_url FROM blog_posts WHERE canonical_url IS NOT NULL;"
```

---

## 🎯 Common Tasks

### Clear SSR Cache
```bash
sudo systemctl restart fastreactcms-ssr
```

### Force NGINX Reload
```bash
sudo systemctl reload nginx
# Or if that doesn't work:
sudo systemctl restart nginx
```

### Update SSL Certificate
```bash
sudo certbot renew
sudo systemctl reload nginx
```

### View Active Connections
```bash
# NGINX connections
sudo netstat -an | grep :443 | grep ESTABLISHED | wc -l

# Backend connections
sudo netstat -an | grep :8100 | grep ESTABLISHED | wc -l

# SSR connections
sudo netstat -an | grep :3001 | grep ESTABLISHED | wc -l
```

### Check Disk Space
```bash
df -h
du -sh /var/www/fastreactcms/*
```

---

## 🆘 Emergency Commands

### Restart Everything
```bash
sudo systemctl restart fastreactcms-backend
sudo systemctl restart fastreactcms-ssr
sudo systemctl restart nginx
```

### Stop Everything
```bash
sudo systemctl stop fastreactcms-backend
sudo systemctl stop fastreactcms-ssr
sudo systemctl stop nginx
```

### Check System Resources
```bash
top           # CPU/Memory usage
htop          # Better interface (if installed)
free -h       # Memory usage
df -h         # Disk usage
```

### View System Logs
```bash
sudo journalctl -xe                    # Recent system logs
sudo journalctl -p err -xe             # Only errors
sudo dmesg | tail                      # Kernel messages
```

---

## 📞 Support

**Documentation:**
- Full SEO Troubleshooting: `docs/TROUBLESHOOTING_SEO.md`
- Deployment Guide: `docs/DEPLOYMENT_GUIDE_SSR.md`
- Deployment Complete: `docs/DEPLOYMENT_COMPLETE.md`

**Diagnostic Scripts:**
- Service Check: `bash check-services.sh`
- SEO Test: `node test-seo.js`

**Quick Checks:**
```bash
# Are all services running?
bash check-services.sh

# Are there any errors?
sudo journalctl -p err --since "1 hour ago"

# Is the site accessible?
curl -I https://theitapprentice.com
```
