# Analytics & AdSense Setup Guide

## 🔒 Security-First Implementation

Your BlogCMS now has **secure, CSP-compliant** Google Analytics and AdSense integration with:
- ✅ ID validation (prevents injection attacks)
- ✅ No `innerHTML` usage (CSP compliant)
- ✅ DNT (Do Not Track) respect
- ✅ GDPR-compliant settings
- ✅ Database-driven configuration (no `.env` needed!)

---

## 📊 Google Analytics Setup

### Step 1: Get Your Measurement ID
1. Go to [Google Analytics](https://analytics.google.com)
2. Create a property (if you haven't already)
3. Get your Measurement ID (format: `G-XXXXXXXXXX`)
   - Your ID: **G-TMWQPFXFJJ** ✅

### Step 2: Configure in Admin Panel
1. Start your backend: `cd Backend && uvicorn app.main:app --reload`
2. Start your frontend: `cd Frontend && npm run dev`
3. Navigate to: `http://localhost:5173/admin/site-settings`
4. Click the **"Analytics & Ads"** tab
5. Paste your Measurement ID: `G-TMWQPFXFJJ`
6. Click **"Save Settings"**

### Step 3: Test It Works
1. Open DevTools Console (F12)
2. Look for: `[GA] Initializing Google Analytics: G-TMWQPFXFJJ`
3. Navigate between pages - each page view should log
4. Check Real-Time reports in Google Analytics

---

## 💰 Google AdSense Setup

### Step 1: Get Your Client ID
1. Go to [Google AdSense](https://www.google.com/adsense)
2. Get your Publisher ID (format: `ca-pub-XXXXXXXXXXXXXXXX`)

### Step 2: Configure in Admin Panel
1. Navigate to: `/admin/site-settings` → "Analytics & Ads" tab
2. Paste your AdSense Client ID
3. Click **"Save Settings"**

### Step 3: Create Ad Units
1. In Google AdSense, create ad units and get slot IDs
2. Add ads to your blog posts (see below)

---

## 🎯 Using Ads in Blog Posts

### Option 1: Article Ad (In-Content)
```tsx
import { ArticleAd } from '../components/analytics/AdSenseAd';

<ArticleAd slot="1234567890" />
```

### Option 2: Sidebar Ad
```tsx
import { SidebarAd } from '../components/analytics/AdSenseAd';

<SidebarAd slot="1234567890" />
```

### Option 3: Banner Ad (Top/Bottom)
```tsx
import { BannerAd } from '../components/analytics/AdSenseAd';

<BannerAd slot="1234567890" />
```

### Option 4: Custom Ad
```tsx
import { AdSenseAd } from '../components/analytics/AdSenseAd';

<AdSenseAd
  slot="1234567890"
  format="auto"
  responsive={true}
/>
```

---

## 🔧 Environment Variables (Legacy - Not Recommended)

**Note**: The new implementation uses **database settings** instead of `.env` files. This is more secure and doesn't require rebuilding on changes.

If you need to use `.env` for local development testing:

```bash
# Frontend/.env
VITE_GA_MEASUREMENT_ID=G-TMWQPFXFJJ
VITE_ADSENSE_CLIENT_ID=ca-pub-XXXXXXXXXXXXXXXX
```

**But remember**: Database settings (via Admin Panel) take precedence!

---

## 🛡️ Security Features

### 1. ID Validation
```typescript
// Validates format before loading scripts
validateAnalyticsId('G-TMWQPFXFJJ') // ✅ Valid
validateAnalyticsId('INVALID') // ❌ Rejected
```

### 2. CSP Compliance
- No `innerHTML` or `eval()` usage
- Scripts loaded via `createElement()`
- All IDs sanitized before use

### 3. Privacy Features
- **DNT (Do Not Track)** respected
- **IP Anonymization** enabled
- **Secure cookies** (SameSite=None;Secure)
- Disabled in development by default

---

## 🧪 Testing

### Test Analytics
```bash
# 1. Start servers
cd Backend && uvicorn app.main:app --reload &
cd Frontend && npm run dev

# 2. Open browser to http://localhost:5173
# 3. Open DevTools Console (F12)
# 4. Look for:
[GA] Initializing Google Analytics: G-TMWQPFXFJJ
[GA] Loaded successfully
[GA] Page view: /

# 5. Navigate to /blog - should see:
[GA] Page view: /blog
```

### Test AdSense
```bash
# 1. Configure AdSense ID in admin panel
# 2. Add <ArticleAd slot="123" /> to a blog post
# 3. Check console for:
[AdSense] Loading script
[AdSense] Script loaded
[AdSense] Ad initialized: 123
```

---

## 📝 Migration from Old Implementation

If you were using the old `.env`-based approach:

**Before** (Insecure):
```tsx
// Used innerHTML (CSP violation)
script.innerHTML = `window.gtag('config', '${ID}')`;
```

**After** (Secure):
```tsx
// Uses createElement + database config
window.gtag = function(...args) { window.dataLayer.push(args); };
window.gtag('config', safeId);
```

**No code changes needed** - just configure via Admin Panel!

---

## ✅ Checklist

- [ ] Analytics ID configured in `/admin/site-settings`
- [ ] Console shows `[GA] Initializing Google Analytics`
- [ ] Page views tracked in Google Analytics Real-Time
- [ ] AdSense ID configured (optional)
- [ ] Ads displaying on blog posts (optional)
- [ ] No console errors related to CSP or script loading

---

## 🆘 Troubleshooting

### Analytics not loading?
1. Check console for `[GA]` logs
2. Verify ID format: `G-XXXXXXXXXX`
3. Check `/admin/site-settings` → Analytics & Ads tab
4. Ensure backend is running and saving settings

### Ads not showing?
1. Check console for `[AdSense]` logs
2. Verify client ID format: `ca-pub-XXXXXXXXXXXXXXXX`
3. Wait 10-20 minutes for Google to approve
4. Check ad slot IDs are correct

### CSP Errors?
- Our implementation is CSP-compliant!
- If you see CSP errors, check for old/legacy code
- All scripts loaded via `createElement()` - no `innerHTML`

---

**Questions?** Check the code comments in:
- `Frontend/src/components/analytics/GoogleAnalytics.tsx`
- `Frontend/src/components/analytics/AdSenseAd.tsx`
- `Frontend/src/utils/analytics.ts`
