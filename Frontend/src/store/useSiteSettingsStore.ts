// src/store/useSiteSettingsStore.ts
/**
 * Zustand store for site-wide settings
 *
 * Replaces: hooks/useSiteSettings.ts
 *
 * Benefits:
 * - Centralized state (no prop drilling)
 * - No re-renders on unrelated state changes
 * - Persists to localStorage automatically
 * - Simpler API calls (no manual caching logic)
 */

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

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
 * Convert snake_case field names from API to camelCase for frontend
 * NOTE: This will be removed in Phase 2 when Pydantic aliases are configured
 */
const convertToCamelCase = (apiSettings: any): SiteSettings => {
  return {
    googleAnalyticsId: apiSettings.google_analytics_id || '',
    googleAdsenseClientId: apiSettings.google_adsense_client_id || '',
    siteTitle: apiSettings.site_title || defaultSettings.siteTitle,
    siteTagline: apiSettings.site_tagline || '',
    metaDescription: apiSettings.meta_description || defaultSettings.metaDescription,
    metaKeywords: apiSettings.meta_keywords || '',
    ogImage: apiSettings.og_image || '',
    heroTitle: apiSettings.hero_title || defaultSettings.heroTitle,
    heroSubtitle: apiSettings.hero_subtitle || defaultSettings.heroSubtitle,
    heroBadgeText: apiSettings.hero_badge_text || defaultSettings.heroBadgeText,
    heroCTAPrimary: apiSettings.hero_cta_primary || defaultSettings.heroCTAPrimary,
    heroCTASecondary: apiSettings.hero_cta_secondary || defaultSettings.heroCTASecondary,
    statsArticles: apiSettings.stats_articles || '',
    statsReaders: apiSettings.stats_readers || '',
    statsFree: apiSettings.stats_free || '',
    showHero: apiSettings.show_hero !== undefined ? apiSettings.show_hero : true,
    showCarousel: apiSettings.show_carousel !== undefined ? apiSettings.show_carousel : true,
    showCategories: apiSettings.show_categories !== undefined ? apiSettings.show_categories : true,
    showRecentPosts: apiSettings.show_recent_posts !== undefined ? apiSettings.show_recent_posts : true,
    carouselLimit: apiSettings.carousel_limit || 5,
    categoriesLimit: apiSettings.categories_limit || 6,
    recentPostsLimit: apiSettings.recent_posts_limit || 6,
    ctaPrimaryUrl: apiSettings.cta_primary_url || '/blog',
    ctaSecondaryUrl: apiSettings.cta_secondary_url || '/about',
    carouselAutoplay: apiSettings.carousel_autoplay !== undefined ? apiSettings.carousel_autoplay : true,
    carouselInterval: apiSettings.carousel_interval || 7000,
    carouselTransition: apiSettings.carousel_transition || 'crossfade',
    carouselTitle: apiSettings.carousel_title || defaultSettings.carouselTitle,
    carouselSubtitle: apiSettings.carousel_subtitle || defaultSettings.carouselSubtitle,
    categoriesTitle: apiSettings.categories_title || defaultSettings.categoriesTitle,
    categoriesSubtitle: apiSettings.categories_subtitle || defaultSettings.categoriesSubtitle,
    recentPostsTitle: apiSettings.recent_posts_title || defaultSettings.recentPostsTitle,
    recentPostsSubtitle: apiSettings.recent_posts_subtitle || defaultSettings.recentPostsSubtitle,
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
    newsletterEnabled: apiSettings.newsletter_enabled !== undefined ? apiSettings.newsletter_enabled : true,
    smtpHost: apiSettings.smtp_host || '',
    smtpPort: apiSettings.smtp_port || 587,
    smtpUsername: apiSettings.smtp_username || '',
    smtpPassword: apiSettings.smtp_password || '',
    smtpUseTls: apiSettings.smtp_use_tls !== undefined ? apiSettings.smtp_use_tls : true,
    smtpFromEmail: apiSettings.smtp_from_email || '',
    smtpFromName: apiSettings.smtp_from_name || '',
  };
};

interface SiteSettingsStore {
  // State
  settings: SiteSettings;
  isLoading: boolean;
  error: string | null;

  // Actions
  loadSettings: () => Promise<void>;
  updateSettings: (updates: Partial<SiteSettings>) => void;
  resetSettings: () => Promise<void>;
}

export const useSiteSettingsStore = create<SiteSettingsStore>()(
  devtools(
    persist(
      (set, get) => ({
        // Initial state
        settings: defaultSettings,
        isLoading: true,
        error: null,

        // Load settings from API
        loadSettings: async () => {
          set({ isLoading: true, error: null });

          try {
            const response = await fetch('/api/v1/site-settings');

            if (!response.ok) {
              throw new Error(`API error: ${response.status}`);
            }

            const apiSettings = await response.json();
            const camelCaseSettings = convertToCamelCase(apiSettings);

            set({
              settings: camelCaseSettings,
              isLoading: false,
              error: null,
            });

            console.log('✓ Site settings loaded from API');
          } catch (error) {
            console.error('Failed to load site settings:', error);
            set({
              isLoading: false,
              error: error instanceof Error ? error.message : 'Failed to load settings',
            });
          }
        },

        // Update settings (localStorage only - use admin panel to persist to DB)
        updateSettings: (updates: Partial<SiteSettings>) => {
          set((state) => ({
            settings: { ...state.settings, ...updates },
          }));
        },

        // Reset settings (clear cache and reload from API)
        resetSettings: async () => {
          set({ settings: defaultSettings });
          await get().loadSettings();
        },
      }),
      {
        name: 'blogcms_settings', // localStorage key (matches old hook)
        version: 1, // Version for migration support
      }
    ),
    {
      name: 'SiteSettingsStore', // DevTools name
    }
  )
);

/**
 * Backward-compatible hook wrapper for existing code
 *
 * Use this during migration, then gradually replace with direct store access:
 * const settings = useSiteSettingsStore((state) => state.settings);
 */
export const useSiteSettings = () => {
  const settings = useSiteSettingsStore((state) => state.settings);
  const isLoading = useSiteSettingsStore((state) => state.isLoading);
  const loadSettings = useSiteSettingsStore((state) => state.loadSettings);
  const updateSettings = useSiteSettingsStore((state) => state.updateSettings);
  const resetSettings = useSiteSettingsStore((state) => state.resetSettings);

  return {
    settings,
    isLoading,
    saveSettings: updateSettings, // Alias for backward compatibility
    resetSettings,
    reloadSettings: loadSettings, // Alias for backward compatibility
  };
};
