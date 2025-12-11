// src/pages/admin/SiteSettings.tsx
/**
 * Site Settings Admin Panel
 * Configure Google Analytics, Google AdSense, SEO defaults, and site info
 * Now connected to backend API!
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

interface SiteSettings {
  // Analytics & Ads
  google_analytics_id: string;
  google_adsense_client_id: string;

  // SEO Defaults
  site_title: string;
  site_tagline: string;
  meta_description: string;
  meta_keywords: string;
  og_image: string;

  // Homepage Hero
  hero_title: string;
  hero_subtitle: string;
  hero_badge_text: string;
  hero_cta_primary: string;
  hero_cta_secondary: string;

  // Homepage Stats (optional - empty string to hide)
  stats_articles: string;
  stats_readers: string;
  stats_free: string;

  // Social Media
  twitter_handle: string;
  facebook_url: string;
  linkedin_url: string;
  github_url: string;

  // Contact
  contact_email: string;
  support_email: string;

  // Domain
  site_url: string;

  // Logo
  logo_url: string;
  logo_dark_url: string;

  // Branding
  show_powered_by: boolean;

  // Newsletter & Email
  newsletter_enabled: boolean;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password: string;
  smtp_use_tls: boolean;
  smtp_from_email: string;
  smtp_from_name: string;
}

const defaultSettings: SiteSettings = {
  google_analytics_id: '',
  google_adsense_client_id: '',
  site_title: 'FastReactCMS',
  site_tagline: 'A modern, SEO-optimized blog platform',
  meta_description: 'Share your knowledge with the world using FastReactCMS - a modern blog platform built with React and FastAPI.',
  meta_keywords: 'blog, cms, react, fastapi, seo, content management',
  og_image: '',

  // Homepage defaults
  hero_title: 'Share Your Story',
  hero_subtitle: 'A modern blogging platform built for creators, writers, and developers who want full control.',
  hero_badge_text: 'Open Source',
  hero_cta_primary: 'Explore Articles',
  hero_cta_secondary: 'Learn More',

  // Stats (empty to hide entire stats section)
  stats_articles: '',
  stats_readers: '',
  stats_free: '',

  twitter_handle: '',
  facebook_url: '',
  linkedin_url: '',
  github_url: '',
  contact_email: '',
  support_email: '',
  site_url: 'https://yourdomain.com',
  logo_url: '',
  logo_dark_url: '',
  show_powered_by: true,

  // Newsletter & Email defaults
  newsletter_enabled: true,
  smtp_host: '',
  smtp_port: 587,
  smtp_username: '',
  smtp_password: '',
  smtp_use_tls: true,
  smtp_from_email: '',
  smtp_from_name: '',
};

export const SiteSettings: React.FC = () => {
  const navigate = useNavigate();
  const [settings, setSettings] = useState<SiteSettings>(defaultSettings);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'analytics' | 'seo' | 'homepage' | 'social' | 'contact' | 'branding' | 'email'>('homepage');
  const [uploadingLogo, setUploadingLogo] = useState<'light' | 'dark' | null>(null);

  // Fetch settings from API on mount
  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/v1/admin/site-settings', {
        credentials: 'include'
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
      setError('Failed to load settings. Using defaults.');
      setSettings(defaultSettings);
    } finally {
      setLoading(false);
    }
  };

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

      console.log('✓ Settings saved successfully to database!');
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      console.error('Error saving settings:', err);
      setError('Failed to save settings. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      setSettings(defaultSettings);
    }
  };

  const handleChange = (field: keyof SiteSettings, value: string | boolean | number) => {
    setSettings({ ...settings, [field]: value });
  };

  const handleLogoUpload = async (file: File, logoType: 'light' | 'dark') => {
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
      setError('Please upload an image file (JPEG, PNG, GIF, or WebP)');
      return;
    }

    // Validate file size (10MB max)
    if (file.size > 10 * 1024 * 1024) {
      setError('File size must be less than 10MB');
      return;
    }

    try {
      setUploadingLogo(logoType);
      setError(null);

      const formData = new FormData();
      formData.append('file', file);
      formData.append('alt_text', `Site logo (${logoType} mode)`);

      const response = await fetch('/api/v1/admin/blog/media/upload', {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      const data = await response.json();

      // Auto-populate the URL field
      const field = logoType === 'light' ? 'logo_url' : 'logo_dark_url';
      setSettings({ ...settings, [field]: data.url });

      console.log(`✓ ${logoType} logo uploaded successfully: ${data.url}`);
    } catch (err) {
      console.error('Error uploading logo:', err);
      setError(`Failed to upload ${logoType} logo. Please try again.`);
    } finally {
      setUploadingLogo(null);
    }
  };

  const tabs = [
    { id: 'homepage', label: 'Homepage', icon: '🏠' },
    { id: 'seo', label: 'SEO & Domain', icon: '🔍' },
    { id: 'branding', label: 'Branding & Logo', icon: '🎨' },
    { id: 'analytics', label: 'Analytics & Ads', icon: '📊' },
    { id: 'social', label: 'Social Media', icon: '🌐' },
    { id: 'contact', label: 'Contact Info', icon: '📧' },
    { id: 'email', label: 'Email & Newsletter', icon: '✉️' },
  ] as const;

  if (loading && !settings.site_title) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-8">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
            Site Settings
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Configure your blog's analytics, SEO, branding, and site information
          </p>
        </div>

        {/* Error Banner */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4"
          >
            <p className="text-red-800 dark:text-red-300 font-medium">
              ⚠️ {error}
            </p>
          </motion.div>
        )}

        {/* Save Success Banner */}
        {saved && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4"
          >
            <p className="text-green-800 dark:text-green-300 font-medium">
              ✓ Settings saved successfully to database!
            </p>
            <p className="text-sm text-green-700 dark:text-green-400 mt-1">
              Changes are live. RSS and Sitemap will use the new values immediately.
            </p>
          </motion.div>
        )}

        {/* Tabs */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-md border border-gray-200 dark:border-slate-700 overflow-hidden">
          <div className="border-b border-gray-200 dark:border-slate-700">
            <div className="flex space-x-1 p-1 overflow-x-auto">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-shrink-0 px-4 py-3 text-sm font-medium rounded-lg transition ${
                    activeTab === tab.id
                      ? 'bg-blue-600 dark:bg-blue-700 text-white'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700'
                  }`}
                >
                  <span className="mr-2">{tab.icon}</span>
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {/* Homepage Tab */}
            {activeTab === 'homepage' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-blue-900 dark:text-blue-300 mb-2">
                    🏠 Homepage Customization
                  </h3>
                  <p className="text-sm text-blue-800 dark:text-blue-400">
                    Customize your homepage hero section, CTAs, and stats. Changes take effect immediately!
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Hero Title
                  </label>
                  <input
                    type="text"
                    value={settings.hero_title}
                    onChange={(e) => handleChange('hero_title', e.target.value)}
                    placeholder="Share Your Story"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Main headline on your homepage
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Hero Subtitle
                  </label>
                  <textarea
                    value={settings.hero_subtitle}
                    onChange={(e) => handleChange('hero_subtitle', e.target.value)}
                    rows={2}
                    placeholder="A modern blogging platform..."
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Badge Text
                  </label>
                  <input
                    type="text"
                    value={settings.hero_badge_text}
                    onChange={(e) => handleChange('hero_badge_text', e.target.value)}
                    placeholder="Open Source"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Small badge above the title
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Primary CTA Button
                    </label>
                    <input
                      type="text"
                      value={settings.hero_cta_primary}
                      onChange={(e) => handleChange('hero_cta_primary', e.target.value)}
                      placeholder="Explore Articles"
                      className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Secondary CTA Button
                    </label>
                    <input
                      type="text"
                      value={settings.hero_cta_secondary}
                      onChange={(e) => handleChange('hero_cta_secondary', e.target.value)}
                      placeholder="Learn More"
                      className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                </div>

                <div className="border-t border-gray-200 dark:border-slate-700 pt-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                    Homepage Stats (Optional)
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    Leave blank to hide. Stats display below the hero section.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Articles Count
                      </label>
                      <input
                        type="text"
                        value={settings.stats_articles}
                        onChange={(e) => handleChange('stats_articles', e.target.value)}
                        placeholder="50+"
                        className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Readers Count
                      </label>
                      <input
                        type="text"
                        value={settings.stats_readers}
                        onChange={(e) => handleChange('stats_readers', e.target.value)}
                        placeholder="10K+"
                        className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Free Status
                      </label>
                      <input
                        type="text"
                        value={settings.stats_free}
                        onChange={(e) => handleChange('stats_free', e.target.value)}
                        placeholder="100% Free"
                        className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Analytics & Ads Tab */}
            {activeTab === 'analytics' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Google Analytics Measurement ID
                  </label>
                  <input
                    type="text"
                    value={settings.google_analytics_id}
                    onChange={(e) => handleChange('google_analytics_id', e.target.value)}
                    placeholder="G-XXXXXXXXXX"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Find this in your Google Analytics dashboard under Admin → Data Streams
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Google AdSense Client ID
                  </label>
                  <input
                    type="text"
                    value={settings.google_adsense_client_id}
                    onChange={(e) => handleChange('google_adsense_client_id', e.target.value)}
                    placeholder="ca-pub-XXXXXXXXXXXXXXXX"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Find this in your Google AdSense account under Sites
                  </p>
                </div>

                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                  <h3 className="font-medium text-blue-900 dark:text-blue-300 mb-2">
                    Important: Environment Variables Required
                  </h3>
                  <p className="text-sm text-blue-800 dark:text-blue-400 mb-3">
                    After saving, add these to your <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded">Frontend/.env</code> file:
                  </p>
                  <pre className="bg-white dark:bg-slate-800 p-3 rounded text-xs overflow-x-auto">
{`VITE_GA_MEASUREMENT_ID=${settings.google_analytics_id || 'G-XXXXXXXXXX'}
VITE_ADSENSE_CLIENT_ID=${settings.google_adsense_client_id || 'ca-pub-XXXXXXXXXXXXXXXX'}`}
                  </pre>
                  <p className="text-sm text-blue-800 dark:text-blue-400 mt-2">
                    Then rebuild: <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded">npm run build</code>
                  </p>
                </div>
              </motion.div>
            )}

            {/* SEO & Domain Tab */}
            {activeTab === 'seo' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-green-900 dark:text-green-300 mb-2">
                    🔍 SEO & RSS Feed
                  </h3>
                  <p className="text-sm text-green-800 dark:text-green-400">
                    These settings are used in your RSS feed, sitemap, and page metadata.
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Site Title
                  </label>
                  <input
                    type="text"
                    value={settings.site_title}
                    onChange={(e) => handleChange('site_title', e.target.value)}
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Used in RSS feed title and page titles
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Site Tagline
                  </label>
                  <input
                    type="text"
                    value={settings.site_tagline}
                    onChange={(e) => handleChange('site_tagline', e.target.value)}
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Site URL (Production)
                  </label>
                  <input
                    type="url"
                    value={settings.site_url}
                    onChange={(e) => handleChange('site_url', e.target.value)}
                    placeholder="https://yourdomain.com"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Used in sitemap and RSS feed URLs
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Default Meta Description
                  </label>
                  <textarea
                    value={settings.meta_description}
                    onChange={(e) => handleChange('meta_description', e.target.value)}
                    rows={3}
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Recommended: 150-160 characters. Used in RSS feed description.
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Default Meta Keywords
                  </label>
                  <input
                    type="text"
                    value={settings.meta_keywords}
                    onChange={(e) => handleChange('meta_keywords', e.target.value)}
                    placeholder="keyword1, keyword2, keyword3"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Open Graph Image URL
                  </label>
                  <input
                    type="url"
                    value={settings.og_image}
                    onChange={(e) => handleChange('og_image', e.target.value)}
                    placeholder="https://yourdomain.com/og-image.jpg"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Image displayed when your site is shared on social media (1200x630px recommended)
                  </p>
                </div>
              </motion.div>
            )}

            {/* Branding & Logo Tab */}
            {activeTab === 'branding' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-purple-900 dark:text-purple-300 mb-2">
                    🎨 Logo & Branding
                  </h3>
                  <p className="text-sm text-purple-800 dark:text-purple-400">
                    Upload logos and customize your site's branding
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Logo URL (Light Mode)
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="url"
                      value={settings.logo_url}
                      onChange={(e) => handleChange('logo_url', e.target.value)}
                      placeholder="https://yourdomain.com/logo.png"
                      className="flex-1 px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <label className="relative">
                      <input
                        type="file"
                        accept="image/*"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) handleLogoUpload(file, 'light');
                        }}
                        disabled={uploadingLogo === 'light'}
                      />
                      <button
                        type="button"
                        onClick={() => document.querySelector<HTMLInputElement>('input[type="file"]')?.click()}
                        disabled={uploadingLogo === 'light'}
                        className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                      >
                        {uploadingLogo === 'light' ? (
                          <span className="flex items-center gap-2">
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                            Uploading...
                          </span>
                        ) : (
                          '📤 Upload'
                        )}
                      </button>
                    </label>
                  </div>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Logo displayed in light mode (paste URL or upload image)
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Logo URL (Dark Mode)
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="url"
                      value={settings.logo_dark_url}
                      onChange={(e) => handleChange('logo_dark_url', e.target.value)}
                      placeholder="https://yourdomain.com/logo-dark.png"
                      className="flex-1 px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <label className="relative">
                      <input
                        type="file"
                        accept="image/*"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) handleLogoUpload(file, 'dark');
                        }}
                        disabled={uploadingLogo === 'dark'}
                      />
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          const input = (e.currentTarget.previousElementSibling as HTMLInputElement);
                          input?.click();
                        }}
                        disabled={uploadingLogo === 'dark'}
                        className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                      >
                        {uploadingLogo === 'dark' ? (
                          <span className="flex items-center gap-2">
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                            Uploading...
                          </span>
                        ) : (
                          '📤 Upload'
                        )}
                      </button>
                    </label>
                  </div>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Optional - falls back to light mode logo if not set (paste URL or upload image)
                  </p>
                </div>

                {(settings.logo_url || settings.logo_dark_url) && (
                  <div className="border-t border-gray-200 dark:border-slate-700 pt-6">
                    <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                      Logo Preview
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                      {settings.logo_url && (
                        <div className="bg-white dark:bg-slate-700 p-4 rounded-lg border border-gray-200 dark:border-slate-600">
                          <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Light Mode</p>
                          <img src={settings.logo_url} alt="Logo (Light)" className="max-h-16 mx-auto" />
                        </div>
                      )}
                      {settings.logo_dark_url && (
                        <div className="bg-slate-900 p-4 rounded-lg border border-slate-700">
                          <p className="text-xs text-gray-400 mb-2">Dark Mode</p>
                          <img src={settings.logo_dark_url} alt="Logo (Dark)" className="max-h-16 mx-auto" />
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="border-t border-gray-200 dark:border-slate-700 pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Show "Powered by FastReactCMS"
                      </label>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Display attribution in the footer (supports open source!)
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleChange('show_powered_by', !settings.show_powered_by)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.show_powered_by
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.show_powered_by ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Social Media Tab */}
            {activeTab === 'social' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Twitter Handle
                  </label>
                  <input
                    type="text"
                    value={settings.twitter_handle}
                    onChange={(e) => handleChange('twitter_handle', e.target.value)}
                    placeholder="@yourblog"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Facebook Page URL
                  </label>
                  <input
                    type="url"
                    value={settings.facebook_url}
                    onChange={(e) => handleChange('facebook_url', e.target.value)}
                    placeholder="https://facebook.com/yourblog"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    LinkedIn URL
                  </label>
                  <input
                    type="url"
                    value={settings.linkedin_url}
                    onChange={(e) => handleChange('linkedin_url', e.target.value)}
                    placeholder="https://linkedin.com/company/yourblog"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    GitHub URL
                  </label>
                  <input
                    type="url"
                    value={settings.github_url}
                    onChange={(e) => handleChange('github_url', e.target.value)}
                    placeholder="https://github.com/yourusername"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </motion.div>
            )}

            {/* Contact Tab */}
            {activeTab === 'contact' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Contact Email
                  </label>
                  <input
                    type="email"
                    value={settings.contact_email}
                    onChange={(e) => handleChange('contact_email', e.target.value)}
                    placeholder="contact@yourdomain.com"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Support Email
                  </label>
                  <input
                    type="email"
                    value={settings.support_email}
                    onChange={(e) => handleChange('support_email', e.target.value)}
                    placeholder="support@yourdomain.com"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </motion.div>
            )}

            {/* Email & Newsletter Tab */}
            {activeTab === 'email' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-blue-900 dark:text-blue-300 mb-2">
                    ✉️ Email & Newsletter Settings
                  </h3>
                  <p className="text-sm text-blue-800 dark:text-blue-400">
                    Configure SMTP settings for newsletter emails and enable/disable newsletter subscriptions
                  </p>
                </div>

                {/* Newsletter Toggle */}
                <div className="border-b border-gray-200 dark:border-slate-700 pb-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Enable Newsletter
                      </label>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Show newsletter subscription form in the footer
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleChange('newsletter_enabled', !settings.newsletter_enabled)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.newsletter_enabled
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.newsletter_enabled ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>
                </div>

                {/* SMTP Configuration */}
                <div className="border-t border-gray-200 dark:border-slate-700 pt-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                    SMTP Configuration
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    Configure email sending (supports SendGrid, Mailgun, SMTP, etc.)
                  </p>

                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="md:col-span-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          SMTP Host
                        </label>
                        <input
                          type="text"
                          value={settings.smtp_host}
                          onChange={(e) => handleChange('smtp_host', e.target.value)}
                          placeholder="smtp.sendgrid.net"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Port
                        </label>
                        <input
                          type="number"
                          value={settings.smtp_port}
                          onChange={(e) => handleChange('smtp_port', parseInt(e.target.value) || 587)}
                          placeholder="587"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          SMTP Username
                        </label>
                        <input
                          type="text"
                          value={settings.smtp_username}
                          onChange={(e) => handleChange('smtp_username', e.target.value)}
                          placeholder="apikey"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          SMTP Password / API Key
                        </label>
                        <input
                          type="password"
                          value={settings.smtp_password}
                          onChange={(e) => handleChange('smtp_password', e.target.value)}
                          placeholder="••••••••"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          From Email
                        </label>
                        <input
                          type="email"
                          value={settings.smtp_from_email}
                          onChange={(e) => handleChange('smtp_from_email', e.target.value)}
                          placeholder="newsletter@yourdomain.com"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          From Name
                        </label>
                        <input
                          type="text"
                          value={settings.smtp_from_name}
                          onChange={(e) => handleChange('smtp_from_name', e.target.value)}
                          placeholder="Your Blog Name"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                    </div>

                    <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-4 rounded-lg">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Use TLS
                        </label>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          Recommended for secure connections
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleChange('smtp_use_tls', !settings.smtp_use_tls)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.smtp_use_tls
                            ? 'bg-blue-600 dark:bg-blue-700'
                            : 'bg-gray-300 dark:bg-slate-600'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            settings.smtp_use_tls ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>
                  </div>
                </div>

                {/* Quick Setup Guide */}
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                  <h3 className="font-medium text-green-900 dark:text-green-300 mb-2">
                    Quick Setup for SendGrid
                  </h3>
                  <ul className="text-sm text-green-800 dark:text-green-400 space-y-1 list-disc list-inside">
                    <li>Host: <code className="bg-green-100 dark:bg-green-900 px-1 rounded">smtp.sendgrid.net</code></li>
                    <li>Port: <code className="bg-green-100 dark:bg-green-900 px-1 rounded">587</code></li>
                    <li>Username: <code className="bg-green-100 dark:bg-green-900 px-1 rounded">apikey</code></li>
                    <li>Password: Your SendGrid API Key</li>
                    <li>Use TLS: Enabled</li>
                  </ul>
                </div>
              </motion.div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="border-t border-gray-200 dark:border-slate-700 px-6 py-4 bg-gray-50 dark:bg-slate-800/50 flex justify-between items-center">
            <div className="flex gap-3">
              <button
                onClick={() => navigate('/admin')}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-slate-600 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 transition"
              >
                ← Back to Dashboard
              </button>
              <button
                onClick={handleReset}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-slate-600 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 transition"
              >
                Reset to Defaults
              </button>
            </div>
            <button
              onClick={handleSave}
              disabled={loading}
              className="px-6 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {loading && <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>}
              {loading ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SiteSettings;
