// src/pages/admin/SiteSettings.tsx
/**
 * Site Settings Admin Panel
 * Configure Google Analytics, Google AdSense, SEO defaults, and site info
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

interface SiteSettings {
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

export const SiteSettings: React.FC = () => {
  const navigate = useNavigate();
  const [settings, setSettings] = useState<SiteSettings>(defaultSettings);
  const [saved, setSaved] = useState(false);
  const [activeTab, setActiveTab] = useState<'analytics' | 'seo' | 'homepage' | 'social' | 'contact'>('homepage');

  // Load settings from localStorage on mount
  useEffect(() => {
    const savedSettings = localStorage.getItem('blogcms_settings');
    if (savedSettings) {
      setSettings({ ...defaultSettings, ...JSON.parse(savedSettings) });
    }
  }, []);

  const handleSave = () => {
    localStorage.setItem('blogcms_settings', JSON.stringify(settings));
    setSaved(true);

    // Update environment variables (requires rebuild to take effect)
    console.log('Settings saved! Update your .env file with:');
    console.log(`VITE_GA_MEASUREMENT_ID=${settings.googleAnalyticsId}`);
    console.log(`VITE_ADSENSE_CLIENT_ID=${settings.googleAdsenseClientId}`);

    setTimeout(() => setSaved(false), 3000);
  };

  const handleReset = () => {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      setSettings(defaultSettings);
      localStorage.removeItem('blogcms_settings');
    }
  };

  const handleChange = (field: keyof SiteSettings, value: string) => {
    setSettings({ ...settings, [field]: value });
  };

  const tabs = [
    { id: 'homepage', label: 'Homepage', icon: '🏠' },
    { id: 'seo', label: 'SEO & Branding', icon: '🔍' },
    { id: 'analytics', label: 'Analytics & Ads', icon: '📊' },
    { id: 'social', label: 'Social Media', icon: '🌐' },
    { id: 'contact', label: 'Contact Info', icon: '📧' },
  ] as const;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-8">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
            Site Settings
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Configure your blog's analytics, SEO, and site information
          </p>
        </div>

        {/* Save Success Banner */}
        {saved && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4"
          >
            <p className="text-green-800 dark:text-green-300 font-medium">
              ✓ Settings saved successfully!
            </p>
            <p className="text-sm text-green-700 dark:text-green-400 mt-1">
              Remember to update your .env file and rebuild for Analytics/AdSense changes to take effect.
            </p>
          </motion.div>
        )}

        {/* Tabs */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-md border border-gray-200 dark:border-slate-700 overflow-hidden">
          <div className="border-b border-gray-200 dark:border-slate-700">
            <div className="flex space-x-1 p-1">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 px-4 py-3 text-sm font-medium rounded-lg transition ${
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
                    value={settings.heroTitle}
                    onChange={(e) => handleChange('heroTitle', e.target.value)}
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
                    value={settings.heroSubtitle}
                    onChange={(e) => handleChange('heroSubtitle', e.target.value)}
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
                    value={settings.heroBadgeText}
                    onChange={(e) => handleChange('heroBadgeText', e.target.value)}
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
                      value={settings.heroCTAPrimary}
                      onChange={(e) => handleChange('heroCTAPrimary', e.target.value)}
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
                      value={settings.heroCTASecondary}
                      onChange={(e) => handleChange('heroCTASecondary', e.target.value)}
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
                        value={settings.statsArticles}
                        onChange={(e) => handleChange('statsArticles', e.target.value)}
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
                        value={settings.statsReaders}
                        onChange={(e) => handleChange('statsReaders', e.target.value)}
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
                        value={settings.statsFree}
                        onChange={(e) => handleChange('statsFree', e.target.value)}
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
                    value={settings.googleAnalyticsId}
                    onChange={(e) => handleChange('googleAnalyticsId', e.target.value)}
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
                    value={settings.googleAdsenseClientId}
                    onChange={(e) => handleChange('googleAdsenseClientId', e.target.value)}
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
{`VITE_GA_MEASUREMENT_ID=${settings.googleAnalyticsId || 'G-XXXXXXXXXX'}
VITE_ADSENSE_CLIENT_ID=${settings.googleAdsenseClientId || 'ca-pub-XXXXXXXXXXXXXXXX'}`}
                  </pre>
                  <p className="text-sm text-blue-800 dark:text-blue-400 mt-2">
                    Then rebuild: <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded">npm run build</code>
                  </p>
                </div>
              </motion.div>
            )}

            {/* SEO & Branding Tab */}
            {activeTab === 'seo' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Site Title
                  </label>
                  <input
                    type="text"
                    value={settings.siteTitle}
                    onChange={(e) => handleChange('siteTitle', e.target.value)}
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Site Tagline
                  </label>
                  <input
                    type="text"
                    value={settings.siteTagline}
                    onChange={(e) => handleChange('siteTagline', e.target.value)}
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Default Meta Description
                  </label>
                  <textarea
                    value={settings.metaDescription}
                    onChange={(e) => handleChange('metaDescription', e.target.value)}
                    rows={3}
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Recommended: 150-160 characters
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Default Meta Keywords
                  </label>
                  <input
                    type="text"
                    value={settings.metaKeywords}
                    onChange={(e) => handleChange('metaKeywords', e.target.value)}
                    placeholder="keyword1, keyword2, keyword3"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Site URL (Production)
                  </label>
                  <input
                    type="url"
                    value={settings.siteUrl}
                    onChange={(e) => handleChange('siteUrl', e.target.value)}
                    placeholder="https://yourdomain.com"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Update sitemap and RSS feed URLs in <code className="bg-gray-100 dark:bg-slate-700 px-1 rounded">Backend/app/api/v1/endpoints/blog/public.py</code>
                  </p>
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
                    value={settings.twitterHandle}
                    onChange={(e) => handleChange('twitterHandle', e.target.value)}
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
                    value={settings.facebookUrl}
                    onChange={(e) => handleChange('facebookUrl', e.target.value)}
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
                    value={settings.linkedinUrl}
                    onChange={(e) => handleChange('linkedinUrl', e.target.value)}
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
                    value={settings.githubUrl}
                    onChange={(e) => handleChange('githubUrl', e.target.value)}
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
                    value={settings.contactEmail}
                    onChange={(e) => handleChange('contactEmail', e.target.value)}
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
                    value={settings.supportEmail}
                    onChange={(e) => handleChange('supportEmail', e.target.value)}
                    placeholder="support@yourdomain.com"
                    className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </motion.div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="border-t border-gray-200 dark:border-slate-700 px-6 py-4 bg-gray-50 dark:bg-slate-800/50 flex justify-between">
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
              className="px-6 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium"
            >
              Save Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SiteSettings;
