#!/bin/bash

# FastReactCMS - NGINX Setup Script
# Domain: theitapprentice.com
# Static IP: 35.230.128.169

set -e

echo "🔧 FastReactCMS - NGINX Configuration Setup"
echo "=========================================="
echo "Domain: theitapprentice.com"
echo "IP: 35.230.128.169"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (use sudo)"
  exit 1
fi

# 1. Stop NGINX if running
echo "📋 Step 1: Stopping NGINX..."
systemctl stop nginx || true
echo "✅ NGINX stopped"
echo ""

# 2. Create certbot webroot directory
echo "📋 Step 2: Creating Certbot webroot..."
mkdir -p /var/www/certbot
chown -R www-data:www-data /var/www/certbot
echo "✅ Certbot webroot created"
echo ""

# 3. Backup existing NGINX config
echo "📋 Step 3: Backing up existing NGINX configs..."
if [ -f /etc/nginx/sites-available/fastreactcms ]; then
    cp /etc/nginx/sites-available/fastreactcms /etc/nginx/sites-available/fastreactcms.backup.$(date +%Y%m%d_%H%M%S)
    echo "✅ Backup created"
else
    echo "ℹ️  No existing config to backup"
fi
echo ""

# 4. Remove old symlink if exists
echo "📋 Step 4: Removing old symlinks..."
rm -f /etc/nginx/sites-enabled/fastreactcms
rm -f /etc/nginx/sites-enabled/default
echo "✅ Old symlinks removed"
echo ""

# 5. Copy new config
echo "📋 Step 5: Installing new NGINX config..."
cat > /etc/nginx/sites-available/fastreactcms << 'NGINX_CONFIG'
# FastReactCMS NGINX Configuration
# Domain: theitapprentice.com
# Static IP: 35.230.128.169

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

# Upstream backend
upstream fastapi_backend {
    server 127.0.0.1:8100;
    keepalive 32;
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name theitapprentice.com www.theitapprentice.com;

    # Certbot ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }

    # Redirect all other HTTP traffic to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server - www redirect to non-www
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.theitapprentice.com;

    # SSL certificates (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/theitapprentice.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/theitapprentice.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Redirect www to non-www
    return 301 https://theitapprentice.com$request_uri;
}

# HTTPS server - Main
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name theitapprentice.com;

    # SSL certificates (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/theitapprentice.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/theitapprentice.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Logging
    access_log /var/log/nginx/theitapprentice.access.log;
    error_log /var/log/nginx/theitapprentice.error.log;

    # Client body size (for image uploads)
    client_max_body_size 10M;

    # Frontend (React SPA)
    root /var/www/fastreactcms/Frontend/dist;
    index index.html;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/rss+xml
        application/atom+xml
        image/svg+xml;

    # Static files with aggressive caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|webp)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
        try_files $uri =404;
    }

    # API endpoints with rate limiting
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;

        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;

        # WebSocket support (if needed)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Auth endpoints with stricter rate limiting
    location /auth/login {
        limit_req zone=login_limit burst=3 nodelay;
        limit_req_status 429;

        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Other auth endpoints
    location /auth/ {
        limit_req zone=api_limit burst=10 nodelay;

        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Backend docs
    location ~ ^/(docs|redoc|openapi.json) {
        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend static files (uploads, blog images, etc.)
    location /static/ {
        alias /var/www/fastreactcms/Backend/static/;
        expires 30d;
        add_header Cache-Control "public";
        access_log off;

        # Security: prevent execution of scripts
        location ~ \.(php|py|pl|sh)$ {
            deny all;
        }
    }

    # Health check endpoint (optional)
    location /health {
        proxy_pass http://fastapi_backend;
        access_log off;
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # React Router fallback (SPA)
    # This MUST be last
    location / {
        try_files $uri $uri/ /index.html;
    }
}
NGINX_CONFIG

echo "✅ NGINX config installed"
echo ""

# 6. Create symlink
echo "📋 Step 6: Creating symlink..."
ln -s /etc/nginx/sites-available/fastreactcms /etc/nginx/sites-enabled/fastreactcms
echo "✅ Symlink created"
echo ""

# 7. Test NGINX configuration
echo "📋 Step 7: Testing NGINX configuration..."
nginx -t
if [ $? -ne 0 ]; then
    echo "❌ NGINX configuration test failed!"
    echo "Please check the error messages above"
    exit 1
fi
echo "✅ NGINX configuration valid"
echo ""

# 8. Check if SSL certificates exist
echo "📋 Step 8: Checking SSL certificates..."
if [ ! -f /etc/letsencrypt/live/theitapprentice.com/fullchain.pem ]; then
    echo "⚠️  SSL certificates not found!"
    echo ""
    echo "Run Certbot to obtain certificates:"
    echo "sudo certbot certonly --webroot -w /var/www/certbot -d theitapprentice.com -d www.theitapprentice.com"
    echo ""
    echo "After obtaining certificates, restart NGINX:"
    echo "sudo systemctl restart nginx"
    exit 0
fi
echo "✅ SSL certificates found"
echo ""

# 9. Start NGINX
echo "📋 Step 9: Starting NGINX..."
systemctl start nginx
systemctl enable nginx
echo "✅ NGINX started and enabled"
echo ""

# 10. Check status
echo "📋 Step 10: Checking NGINX status..."
systemctl status nginx --no-pager
echo ""

echo "=========================================="
echo "✅ NGINX Setup Complete!"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Verify backend is running:"
echo "   curl http://localhost:8100/health"
echo ""
echo "2. Verify NGINX is serving frontend:"
echo "   curl -I https://theitapprentice.com"
echo ""
echo "3. Test in browser:"
echo "   https://theitapprentice.com"
echo ""
echo "4. Check NGINX logs if issues:"
echo "   sudo tail -f /var/log/nginx/theitapprentice.error.log"
echo "=========================================="
