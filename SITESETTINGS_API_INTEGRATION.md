# SiteSettings Frontend API Integration Guide

## Current State
- Frontend saves to `localStorage` only
- No backend communication
- Field names use camelCase

## What Needs to Change

### 1. Update defaultSettings object (line 52)
Replace all camelCase keys with snake_case to match API:

```typescript
const defaultSettings: SiteSettings = {
  google_analytics_id: '',
  google_adsense_client_id: '',
  site_title: 'FastReactCMS',
  site_tagline: 'A modern, SEO-optimized blog platform',
  meta_description: 'Share your knowledge...',
  meta_keywords: 'blog, cms, react...',
  hero_title: 'Share Your Story',
  hero_subtitle: 'A modern blogging platform...',
  hero_badge_text: 'Open Source',
  hero_cta_primary: 'Explore Articles',
  hero_cta_secondary: 'Learn More',
  stats_articles: '',
  stats_readers: '',
  stats_free: '100% Free',
  twitter_handle: '',
  facebook_url: '',
  linkedin_url: '',
  github_url: '',
  contact_email: '',
  support_email: '',
  site_url: 'https://yourdomain.com',
  logo_url: '',
  logo_dark_url: '',
};
```

### 2. Add loading and error states
```typescript
const [settings, setSettings] = useState<SiteSettings>(defaultSettings);
const [saved, setSaved] = useState(false);
const [loading, setLoading] = useState(true);
const [error, setError] = useState<string | null>(null);
```

### 3. Replace useEffect to fetch from API (line 88-93)
```typescript
useEffect(() => {
  fetchSettings();
}, []);

const fetchSettings = async () => {
  try {
    setLoading(true);
    const response = await fetch('/api/v1/admin/site-settings', {
      credentials: 'include' // Important for cookies
    });

    if (!response.ok) {
      if (response.status === 404) {
        // No settings yet, use defaults
        setSettings(defaultSettings);
      } else {
        throw new Error('Failed to fetch settings');
      }
    } else {
      const data = await response.json();
      setSettings(data);
    }
  } catch (err) {
    console.error('Error fetching settings:', err);
    setError('Failed to load settings');
    setSettings(defaultSettings);
  } finally {
    setLoading(false);
  }
};
```

### 4. Replace handleSave to POST to API (line 95-101)
```typescript
const handleSave = async () => {
  try {
    setLoading(true);
    setError(null);

    const response = await fetch('/api/v1/admin/site-settings', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify(settings)
    });

    if (!response.ok) {
      throw new Error('Failed to save settings');
    }

    const updatedSettings = await response.json();
    setSettings(updatedSettings);
    setSaved(true);

    console.log('✓ Settings saved successfully!');
    setTimeout(() => setSaved(false), 3000);
  } catch (err) {
    console.error('Error saving settings:', err);
    setError('Failed to save settings. Please try again.');
  } finally {
    setLoading(false);
  }
};
```

### 5. Update all field references from camelCase to snake_case

Throughout the component, replace:
- `settings.googleAnalyticsId` → `settings.google_analytics_id`
- `settings.googleAdsenseClientId` → `settings.google_adsense_client_id`
- `settings.siteTitle` → `settings.site_title`
- `settings.siteTagline` → `settings.site_tagline`
- `settings.metaDescription` → `settings.meta_description`
- `settings.metaKeywords` → `settings.meta_keywords`
- `settings.heroTitle` → `settings.hero_title`
- `settings.heroSubtitle` → `settings.hero_subtitle`
- `settings.heroBadgeText` → `settings.hero_badge_text`
- `settings.heroCTAPrimary` → `settings.hero_cta_primary`
- `settings.heroCTASecondary` → `settings.hero_cta_secondary`
- `settings.statsArticles` → `settings.stats_articles`
- `settings.statsReaders` → `settings.stats_readers`
- `settings.statsFree` → `settings.stats_free`
- `settings.twitterHandle` → `settings.twitter_handle`
- `settings.facebookUrl` → `settings.facebook_url`
- `settings.linkedinUrl` → `settings.linkedin_url`
- `settings.githubUrl` → `settings.github_url`
- `settings.contactEmail` → `settings.contact_email`
- `settings.supportEmail` → `settings.support_email`
- `settings.siteUrl` → `settings.site_url`

### 6. Add Logo fields to the UI

Add a new tab or section for logos:

```typescript
<div>
  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
    Logo URL (Light Mode)
  </label>
  <input
    type="url"
    value={settings.logo_url || ''}
    onChange={(e) => handleChange('logo_url', e.target.value)}
    placeholder="https://yourdomain.com/logo.png"
    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg..."
  />
  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
    Used in light mode
  </p>
</div>

<div>
  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
    Logo URL (Dark Mode)
  </label>
  <input
    type="url"
    value={settings.logo_dark_url || ''}
    onChange={(e) => handleChange('logo_dark_url', e.target.value)}
    placeholder="https://yourdomain.com/logo-dark.png"
    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg..."
  />
  <p className="mt-1 text-sm text-gray-400">
    Used in dark mode (optional - falls back to logo_url)
  </p>
</div>
```

### 7. Add loading spinner
```tsx
{loading && (
  <div className="flex justify-center items-center p-8">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
  </div>
)}
```

### 8. Add error display
```tsx
{error && (
  <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
    <p className="text-red-800 dark:text-red-300 font-medium">
      {error}
    </p>
  </div>
)}
```

## Testing
1. Load the page - should fetch settings from API
2. Change any field
3. Click Save - should POST to API
4. Refresh page - should load saved settings
5. Check RSS feed - should use new values
6. Check sitemap - should use new site_url

## API Endpoints
- `GET /api/v1/admin/site-settings` - Fetch settings
- `PUT /api/v1/admin/site-settings` - Update settings

Both require admin authentication (cookie-based).
