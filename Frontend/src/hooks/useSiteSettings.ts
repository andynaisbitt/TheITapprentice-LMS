// src/hooks/useSiteSettings.ts
/**
 * Hook for accessing site-wide settings stored in localStorage
 * Settings can be configured in the admin panel at /admin/settings
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

  // Stats (empty to hide)
  statsArticles: '',
  statsReaders: '',
  statsFree: '100% Free',

  twitterHandle: '',
  facebookUrl: '',
  linkedinUrl: '',
  githubUrl: '',
  contactEmail: '',
  supportEmail: '',
  siteUrl: 'https://yourdomain.com',
};

export const useSiteSettings = () => {
  const [settings, setSettings] = useState<SiteSettings>(defaultSettings);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = () => {
    try {
      const savedSettings = localStorage.getItem('blogcms_settings');
      if (savedSettings) {
        setSettings({ ...defaultSettings, ...JSON.parse(savedSettings) });
      }
    } catch (error) {
      console.error('Error loading site settings:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const saveSettings = (newSettings: Partial<SiteSettings>) => {
    const updated = { ...settings, ...newSettings };
    localStorage.setItem('blogcms_settings', JSON.stringify(updated));
    setSettings(updated);
  };

  const resetSettings = () => {
    localStorage.removeItem('blogcms_settings');
    setSettings(defaultSettings);
  };

  return {
    settings,
    isLoading,
    saveSettings,
    resetSettings,
    reloadSettings: loadSettings,
  };
};
