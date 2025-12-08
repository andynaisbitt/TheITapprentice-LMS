// src/hooks/useSiteSettings.ts
/**
 * Hook for accessing site-wide settings from the API
 * Settings can be configured in the admin panel at /admin/site-settings
 *
 * This hook fetches settings from the database and caches them in localStorage
 * for offline access and performance.
 */

import { useEffect, useState } from 'react';

export interface SiteSettings {
  // Analytics & Ads
  googleAnalyticsId: string;
  googleAdsenseClientId: string;

  // SEO Defaults
  siteTitle: string;
  siteTagline: string;
  metaDescription: string;
  metaKeywords: string;

  // Homepage Hero
  heroTitle: string;
  heroSubtitle: string;
  heroBadgeText: string;
  heroCTAPrimary: string;
  heroCTASecondary: string;

  // Homepage Stats (optional - empty string to hide)
  statsArticles: string;
  statsReaders: string;
  statsFree: string;

  // Social Media
  twitterHandle: string;
  facebookUrl: string;
  linkedinUrl: string;
  githubUrl: string;

  // Contact
  contactEmail: string;
  supportEmail: string;

  // Domain
  siteUrl: string;

  // Logo
  logoUrl: string;
  logoDarkUrl: string;

  // Branding
  showPoweredBy: boolean;
}

const defaultSettings: SiteSettings = {
  googleAnalyticsId: '',
  googleAdsenseClientId: '',
  siteTitle: 'FastReactCMS',
  siteTagline: 'A modern, SEO-optimized blog platform',
  metaDescription: 'Share your knowledge with the world using FastReactCMS - a modern blog platform built with React and FastAPI.',
  metaKeywords: 'blog, cms, react, fastapi, seo, content management',

  // Homepage defaults
  heroTitle: 'Share Your Story',
  heroSubtitle: 'A modern blogging platform built for creators, writers, and developers who want full control.',
  heroBadgeText: 'Open Source',
  heroCTAPrimary: 'Explore Articles',
  heroCTASecondary: 'Learn More',

  // Stats (empty to hide entire section)
  statsArticles: '',
  statsReaders: '',
  statsFree: '',

  twitterHandle: '',
  facebookUrl: '',
  linkedinUrl: '',
  githubUrl: '',
  contactEmail: '',
  supportEmail: '',
  siteUrl: 'https://yourdomain.com',
  logoUrl: '',
  logoDarkUrl: '',
  showPoweredBy: true,
};

/**
 * Convert snake_case field names from API to camelCase for frontend
 */
const convertToCamelCase = (apiSettings: any): SiteSettings => {
  return {
    googleAnalyticsId: apiSettings.google_analytics_id || '',
    googleAdsenseClientId: apiSettings.google_adsense_client_id || '',
    siteTitle: apiSettings.site_title || defaultSettings.siteTitle,
    siteTagline: apiSettings.site_tagline || '',
    metaDescription: apiSettings.meta_description || defaultSettings.metaDescription,
    metaKeywords: apiSettings.meta_keywords || '',
    heroTitle: apiSettings.hero_title || defaultSettings.heroTitle,
    heroSubtitle: apiSettings.hero_subtitle || defaultSettings.heroSubtitle,
    heroBadgeText: apiSettings.hero_badge_text || defaultSettings.heroBadgeText,
    heroCTAPrimary: apiSettings.hero_cta_primary || defaultSettings.heroCTAPrimary,
    heroCTASecondary: apiSettings.hero_cta_secondary || defaultSettings.heroCTASecondary,
    statsArticles: apiSettings.stats_articles || '',
    statsReaders: apiSettings.stats_readers || '',
    statsFree: apiSettings.stats_free || '',
    twitterHandle: apiSettings.twitter_handle || '',
    facebookUrl: apiSettings.facebook_url || '',
    linkedinUrl: apiSettings.linkedin_url || '',
    githubUrl: apiSettings.github_url || '',
    contactEmail: apiSettings.contact_email || '',
    supportEmail: apiSettings.support_email || '',
    siteUrl: apiSettings.site_url || defaultSettings.siteUrl,
    logoUrl: apiSettings.logo_url || '',
    logoDarkUrl: apiSettings.logo_dark_url || '',
    showPoweredBy: apiSettings.show_powered_by !== undefined ? apiSettings.show_powered_by : true,
  };
};

/**
 * Get initial settings from localStorage immediately (before API call)
 * This prevents flash of default content
 */
const getInitialSettings = (): SiteSettings => {
  try {
    const cached = localStorage.getItem('blogcms_settings');
    if (cached) {
      return { ...defaultSettings, ...JSON.parse(cached) };
    }
  } catch (error) {
    console.warn('Failed to load cached settings:', error);
  }
  return defaultSettings;
};

export const useSiteSettings = () => {
  const [settings, setSettings] = useState<SiteSettings>(getInitialSettings);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      // Try to fetch from API first
      const response = await fetch('/api/v1/site-settings');

      if (response.ok) {
        const apiSettings = await response.json();
        const camelCaseSettings = convertToCamelCase(apiSettings);

        // Update state
        setSettings(camelCaseSettings);

        // Cache in localStorage for offline access
        localStorage.setItem('blogcms_settings', JSON.stringify(camelCaseSettings));

        console.log('✓ Site settings loaded from API');
      } else {
        throw new Error('API fetch failed');
      }
    } catch (error) {
      console.warn('Failed to fetch site settings from API, using localStorage fallback:', error);

      // Fallback to localStorage if API fails
      try {
        const savedSettings = localStorage.getItem('blogcms_settings');
        if (savedSettings) {
          setSettings({ ...defaultSettings, ...JSON.parse(savedSettings) });
        }
      } catch (storageError) {
        console.error('Error loading from localStorage:', storageError);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const saveSettings = (newSettings: Partial<SiteSettings>) => {
    // Note: This function only updates localStorage cache
    // To persist to database, use the admin panel at /admin/site-settings
    const updated = { ...settings, ...newSettings };
    localStorage.setItem('blogcms_settings', JSON.stringify(updated));
    setSettings(updated);
  };

  const resetSettings = () => {
    // Clear cache and reload from API
    localStorage.removeItem('blogcms_settings');
    loadSettings();
  };

  return {
    settings,
    isLoading,
    saveSettings,
    resetSettings,
    reloadSettings: loadSettings,
  };
};
