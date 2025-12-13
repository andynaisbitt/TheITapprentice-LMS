// src/hooks/useSiteSettings.ts
/**
 * @deprecated This hook has been replaced by the Zustand store implementation.
 * Please import from '../store/useSiteSettingsStore' instead:
 *
 * import { useSiteSettings } from '../store/useSiteSettingsStore';
 *
 * Benefits of the new implementation:
 * - Single API call on app startup (vs. one call per component)
 * - Automatic state synchronization across all components
 * - Persistent caching with Zustand persist middleware
 * - DevTools support for debugging
 *
 * This file is kept for backward compatibility during migration but should not be used.
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
  ogImage: string;

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

  // Homepage Section Visibility
  showHero: boolean;
  showCarousel: boolean;
  showCategories: boolean;
  showRecentPosts: boolean;

  // Homepage Content Limits
  carouselLimit: number;
  categoriesLimit: number;
  recentPostsLimit: number;

  // CTA Button URLs
  ctaPrimaryUrl: string;
  ctaSecondaryUrl: string;

  // Carousel Settings
  carouselAutoplay: boolean;
  carouselInterval: number;
  carouselTransition: 'crossfade' | 'slide' | 'none';
  carouselTitle: string;
  carouselSubtitle: string;

  // Categories Settings
  categoriesTitle: string;
  categoriesSubtitle: string;

  // Recent Posts Settings
  recentPostsTitle: string;
  recentPostsSubtitle: string;

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

  // Newsletter & Email
  newsletterEnabled: boolean;
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  smtpPassword: string;
  smtpUseTls: boolean;
  smtpFromEmail: string;
  smtpFromName: string;
}

const defaultSettings: SiteSettings = {
  googleAnalyticsId: '',
  googleAdsenseClientId: '',
  siteTitle: 'FastReactCMS',
  siteTagline: 'A modern, SEO-optimized blog platform',
  metaDescription: 'Share your knowledge with the world using FastReactCMS - a modern blog platform built with React and FastAPI.',
  metaKeywords: 'blog, cms, react, fastapi, seo, content management',
  ogImage: '',

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

  // Section Visibility (all enabled by default)
  showHero: true,
  showCarousel: true,
  showCategories: true,
  showRecentPosts: true,

  // Content Limits
  carouselLimit: 5,
  categoriesLimit: 6,
  recentPostsLimit: 6,

  // CTA URLs
  ctaPrimaryUrl: '/blog',
  ctaSecondaryUrl: '/about',

  // Carousel Settings
  carouselAutoplay: true,
  carouselInterval: 7000,
  carouselTransition: 'crossfade',
  carouselTitle: 'Featured Articles',
  carouselSubtitle: 'Hand-picked posts showcasing our best content',

  // Categories Settings
  categoriesTitle: 'Explore by Category',
  categoriesSubtitle: 'Dive into topics that interest you',

  // Recent Posts Settings
  recentPostsTitle: 'Latest Posts',
  recentPostsSubtitle: 'Fresh content from our writers',

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
  newsletterEnabled: true,
  smtpHost: '',
  smtpPort: 587,
  smtpUsername: '',
  smtpPassword: '',
  smtpUseTls: true,
  smtpFromEmail: '',
  smtpFromName: '',
};

/**
 * Merge API response with defaults
 * Phase 2: API now returns camelCase directly (Pydantic alias_generator)
 */
const convertToCamelCase = (apiSettings: any): SiteSettings => {
  // API already returns camelCase, just merge with defaults
  return { ...defaultSettings, ...apiSettings };
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
