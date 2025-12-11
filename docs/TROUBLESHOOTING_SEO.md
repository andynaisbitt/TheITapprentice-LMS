# SEO & Canonical URL Troubleshooting Guide

## Overview

This guide helps you diagnose and fix issues with:
1. **SEO Meta Tags** - Not showing in search engines/social media
2. **Canonical URLs** - Getting 404 when accessing short URLs
3. **SSR Server** - Server-side rendering for crawlers

---

## How The System Works

### For Regular Users (Browsers)
```
User visits → NGINX serves SPA → React loads → Helmet updates meta tags
```
- **Initial HTML**: Default meta tags (this is normal!)
- **After React loads**: Correct meta tags via React Helmet
- **View Source**: Shows default tags (expected)

### For Crawlers (SEO/Social Bots)
```
Crawler visits → NGINX detects bot → Routes to SSR server → Injects meta tags → Returns HTML
```
- **Initial HTML**: Correct meta tags (injected by SSR)
- **No React**: Crawlers get pre-rendered HTML
- **View Source**: Shows correct tags (critical for SEO)

---

## Quick Diagnostic

### Run the Test Script

**On your local machine:**
```bash
cd C:\Gitlab Projects\BlogCMS
node test-seo.js
```

**On the production server:**
```bash
cd /var/www/fastreactcms/Frontend
node test-seo.js
```

This script checks:
- ✅ SSR server health
- ✅ Canonical URL API
- ✅ Meta tags for crawlers
- ✅ Meta tags for users

---

## Common Issues & Fixes

### Issue 1: Canonical URL Returns 404

**Symptom:**
- Visiting `https://theitapprentice.com/RAM-Price-Spikes` returns 404
- You set the canonical URL in the admin panel

**Diagnosis:**
```bash
# On production server, check if canonical URL exists in database
curl "https://theitapprentice.com/api/v1/content/by-canonical?url=https://theitapprentice.com/RAM-Price-Spikes"
```

**Possible Causes:**

#### A) Canonical URL not saved in database
```bash
# Check the database
psql fastreactcms_db -c "SELECT id, title, canonical_url FROM blog_posts WHERE canonical_url LIKE '%RAM-Price-Spikes%';"
```

**Fix:** Go to Admin → Edit Post → Set canonical URL → Save

#### B) Wrong URL format
- ❌ Wrong: `RAM-Price-Spikes` (missing domain)
- ❌ Wrong: `http://theitapprentice.com/RAM-Price-Spikes` (http not https)
- ✅ Correct: `https://theitapprentice.com/RAM-Price-Spikes`

**Fix:** Edit post and use full HTTPS URL

#### C) Post not published
```bash
# Check if post is published
sudo -u postgres psql fastreactcms -c "SELECT id, title, published FROM blog_posts WHERE canonical_url LIKE '%RAM-Price-Spikes%';"
```

**Fix:** Publish the post in admin panel

---

### Issue 2: SSR Server Not Running

**Symptom:**
- Crawlers see default meta tags
- `curl localhost:3001/health` fails

**Check Status:**
```bash
# On production server
sudo systemctl status fastreactcms-ssr
```

**Fix:**
```bash
# Start the service
sudo systemctl start fastreactcms-ssr

# Enable auto-start on boot
sudo systemctl enable fastreactcms-ssr

# Check status again
sudo systemctl status fastreactcms-ssr
```

**Verify:**
```bash
# Check logs
sudo journalctl -u fastreactcms-ssr -n 50 --no-pager

# Test health endpoint
curl http://localhost:3001/health
```

Expected response:
```json
{
  "status": "ok",
  "cache_size": 5,
  "cache_max": 100,
  "uptime": 123.45
}
```

**If service fails to start:**
```bash
# Check error logs
sudo journalctl -u fastreactcms-ssr -n 100 --no-pager
sudo cat /var/log/fastreactcms-ssr-error.log

# Restart the service
sudo systemctl restart fastreactcms-ssr
```

---

### Issue 3: NGINX Not Routing to SSR

**Symptom:**
- SSR server is running
- But crawlers still see default tags

**Check NGINX Config:**
```bash
# On production server
sudo nginx -t
sudo cat /etc/nginx/nginx.conf | grep -A 20 "map \$http_user_agent"
```

**Expected Output:**
```nginx
map $http_user_agent $is_crawler {
    default 0;
    ~*googlebot 1;
    ~*facebookexternalhit 1;
    ...
}
```

**If missing:**
```bash
# Add content from nginx-http-block.conf to /etc/nginx/nginx.conf
sudo nano /etc/nginx/nginx.conf
# Add BEFORE: include /etc/nginx/sites-enabled/*;

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

---

### Issue 4: Regular Users See Default Meta Tags

**Symptom:**
- You visit blog post and see "FastReactCMS - Modern Blog Platform"
- "View Source" shows default title/description

**Diagnosis:**
This is **CORRECT behavior**! Here's why:

**For Regular Users:**
1. NGINX serves SPA with default meta tags (fast)
2. React loads in browser
3. `<Helmet>` updates meta tags dynamically
4. User sees correct title/description (check browser tab!)

**To verify it's working:**
1. Visit: `https://theitapprentice.com/blog/your-post-slug`
2. Look at **browser tab title** (should show post title)
3. Check with **Meta Tags Debugger** (simulates crawler):
   - Facebook: https://developers.facebook.com/tools/debug/
   - Twitter: https://cards-dev.twitter.com/validator
   - LinkedIn: https://www.linkedin.com/post-inspector/

**What matters for SEO:**
- ❌ Don't check: "View Source" as regular user
- ✅ Do check: Meta tag debuggers (these simulate crawlers)

---

## Testing Meta Tags Properly

### Test as Crawler (SEO)

**Method 1: cURL with Googlebot UA**
```bash
curl -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  "https://theitapprentice.com/blog/your-post-slug" | grep -i "<title>"
```

Expected: Shows post-specific title

**Method 2: Online Tools**
- Facebook Debugger: https://developers.facebook.com/tools/debug/
- Twitter Card Validator: https://cards-dev.twitter.com/validator
- LinkedIn Inspector: https://www.linkedin.com/post-inspector/

These tools behave like crawlers and show what SEO bots see.

### Test as Regular User

**Method 1: Browser Dev Tools**
```javascript
// Open browser console (F12)
document.title // Should show post title after React loads
document.querySelector('meta[property="og:title"]').content
```

**Method 2: React DevTools**
- Install React DevTools extension
- Check `<HelmetProvider>` component
- Verify meta tags are updating

---

## Canonical URL Best Practices

### Setting Canonical URLs

**In Admin Panel:**
1. Edit Post/Page
2. Scroll to "SEO Settings"
3. Enter "Canonical URL" (optional)
4. Format: `https://theitapprentice.com/Your-Short-Url`
5. Save

**When to use:**
- ✅ Short, memorable URLs (e.g., `/RAM-Price-Spikes`)
- ✅ Keyword-rich URLs (e.g., `/Python-Best-Practices`)
- ✅ Social media sharing (e.g., `/Newsletter-Subscribe`)

**When NOT to use:**
- ❌ Every post (only use for special URLs)
- ❌ Same as slug (e.g., if slug is `ram-price-spikes`, canonical URL is redundant)
- ❌ External domains (must match your domain)

### URL Format Rules

**Correct:**
```
https://theitapprentice.com/RAM-Price-Spikes
https://theitapprentice.com/Python-Tips
https://theitapprentice.com/Newsletter
```

**Incorrect:**
```
RAM-Price-Spikes                                    # Missing domain
http://theitapprentice.com/RAM-Price-Spikes        # HTTP not HTTPS
https://example.com/RAM-Price-Spikes               # Wrong domain
/RAM-Price-Spikes                                   # Missing domain
```

---

## Server Health Checks

### SSR Server
```bash
# Check if running
sudo systemctl status fastreactcms-ssr

# Check logs (live)
sudo journalctl -u fastreactcms-ssr -f

# Check recent logs
sudo journalctl -u fastreactcms-ssr -n 50 --no-pager
sudo cat /var/log/fastreactcms-ssr.log

# Restart if needed
sudo systemctl restart fastreactcms-ssr

# Check health endpoint
curl http://localhost:3001/health
```

### Backend API
```bash
# Check if running
sudo systemctl status fastreactcms-backend

# Check logs
sudo journalctl -u fastreactcms-backend -n 50 --no-pager

# Test canonical endpoint
curl "http://localhost:8100/api/v1/content/by-canonical?url=https://theitapprentice.com/RAM-Price-Spikes"
```

### NGINX
```bash
# Test config
sudo nginx -t

# Check logs
sudo tail -f /var/log/nginx/theitapprentice.error.log
sudo tail -f /var/log/nginx/theitapprentice.access.log | grep -i bot

# Reload if config changed
sudo systemctl reload nginx
```

---

## Debugging Checklist

### ✅ Canonical URLs

- [ ] Post is published
- [ ] Canonical URL is set in admin
- [ ] URL format is correct (https://)
- [ ] API endpoint returns 200: `/api/v1/content/by-canonical?url=...`
- [ ] Database has canonical_url populated
- [ ] CanonicalResolver is in `Frontend/src/routes/routes.tsx`
- [ ] Route is before 404 catch-all

### ✅ SEO Meta Tags (Crawlers)

- [ ] SSR server is running (`sudo systemctl status fastreactcms-ssr`)
- [ ] SSR health check works (`curl localhost:3001/health`)
- [ ] NGINX has crawler detection map (`$is_crawler`)
- [ ] NGINX routes crawlers to SSR (`@ssr` location)
- [ ] Test with crawler UA shows correct tags
- [ ] Facebook/Twitter debuggers show correct tags

### ✅ Meta Tags (Users)

- [ ] React Helmet is in `BlogPostView.tsx`
- [ ] Browser tab shows correct title
- [ ] Console shows no Helmet errors
- [ ] Meta tags update after page load

---

## Need More Help?

1. **Run diagnostic script:**
   ```bash
   node test-seo.js
   ```

2. **Check server logs:**
   ```bash
   pm2 logs ssr-server
   sudo journalctl -u fastreactcms -n 50
   ```

3. **Test specific URL:**
   ```bash
   curl -v "https://theitapprentice.com/RAM-Price-Spikes"
   ```

4. **Database query:**
   ```bash
   sudo -u postgres psql fastreactcms -c "SELECT id, title, slug, canonical_url, published FROM blog_posts ORDER BY created_at DESC LIMIT 10;"
   ```

---

## Summary

**What's Normal:**
- ✅ Regular users see default tags in "View Source"
- ✅ Meta tags update after React loads
- ✅ Browser tab shows correct title
- ✅ Crawlers see correct tags (test with debuggers)

**What's Broken:**
- ❌ Canonical URLs return 404
- ❌ SSR server not running
- ❌ Crawlers see default tags
- ❌ Meta tag debuggers show wrong info

**Quick Fix:**
```bash
# 1. Start SSR server
sudo systemctl start fastreactcms-ssr
sudo systemctl status fastreactcms-ssr

# 2. Verify canonical URLs in database
sudo -u postgres psql fastreactcms -c "SELECT canonical_url FROM blog_posts WHERE canonical_url IS NOT NULL;"

# 3. Test with crawler
curl -H "User-Agent: Googlebot" "https://theitapprentice.com/blog/your-post" | grep title
```
