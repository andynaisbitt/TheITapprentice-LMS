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
  heroCtaPrimary: string;
  heroCtaSecondary: string;

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

  // Favicon
  faviconUrl: string;
  faviconDarkUrl: string;

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

  // Homepage Layout - Blog Sections
  showCarousel: boolean;
  carouselTitle: string;
  carouselSubtitle: string;
  carouselLimit: number;
  carouselAutoplay: boolean;
  carouselInterval: number;

  showCategories: boolean;
  categoriesTitle: string;
  categoriesSubtitle: string;
  categoriesLimit: number;

  showRecentPosts: boolean;
  recentPostsTitle: string;
  recentPostsSubtitle: string;
  recentPostsLimit: number;

  // LMS Widget Visibility
  showFeaturedCourses: boolean;
  showTypingChallenge: boolean;
  showQuickQuiz: boolean;
  showTutorialPaths: boolean;
  showLeaderboardPreview: boolean;
  showDailyChallengeBanner: boolean;
  showHomepageStats: boolean;

  // LMS Widget Customization - Featured Courses
  featuredCoursesTitle: string;
  featuredCoursesSubtitle: string;
  featuredCoursesLimit: number;

  // LMS Widget Customization - Typing Challenge
  typingChallengeTitle: string;
  typingChallengeShowStats: boolean;
  typingChallengeShowPvp: boolean;

  // LMS Widget Customization - Quick Quiz
  quickQuizTitle: string;
  quickQuizSubtitle: string;
  quickQuizLimit: number;

  // LMS Widget Customization - Tutorial Paths
  tutorialPathsTitle: string;
  tutorialPathsSubtitle: string;
  tutorialPathsCategoriesLimit: number;

  // LMS Widget Customization - Leaderboard
  leaderboardTitle: string;
  leaderboardLimit: number;
  leaderboardShowStreak: boolean;

  // LMS Widget Customization - Daily Challenges
  dailyChallengeGuestMessage: string;
  dailyChallengeShowStreak: boolean;

  // LMS Widget Customization - Homepage Stats
  homepageStatsTitle: string;
  homepageStatsShowActiveToday: boolean;

  // Homepage Section Order
  homepageSectionOrder: string[] | null;
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
  heroCtaPrimary: 'Explore Articles',
  heroCtaSecondary: 'Learn More',

  // Stats (empty to hide entire stats section)
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
  faviconUrl: '',
  faviconDarkUrl: '',
  showPoweredBy: true,

  // Newsletter & Email defaults
  newsletterEnabled: true,
  smtpHost: '',
  smtpPort: 587,
  smtpUsername: '',
  smtpPassword: '',
  smtpUseTls: true,
  smtpFromEmail: '',
  smtpFromName: '',

  // Homepage Layout defaults
  showCarousel: true,
  carouselTitle: 'Featured Articles',
  carouselSubtitle: 'Hand-picked posts showcasing our best content',
  carouselLimit: 5,
  carouselAutoplay: true,
  carouselInterval: 7000,

  showCategories: true,
  categoriesTitle: 'Explore by Category',
  categoriesSubtitle: 'Dive into topics that interest you',
  categoriesLimit: 6,

  showRecentPosts: true,
  recentPostsTitle: 'Latest Posts',
  recentPostsSubtitle: 'Fresh content from our writers',
  recentPostsLimit: 6,

  // LMS Widget Visibility
  showFeaturedCourses: true,
  showTypingChallenge: true,
  showQuickQuiz: true,
  showTutorialPaths: true,
  showLeaderboardPreview: true,
  showDailyChallengeBanner: true,
  showHomepageStats: true,

  // LMS Widget Customization - Featured Courses
  featuredCoursesTitle: 'Featured Courses',
  featuredCoursesSubtitle: 'Start your learning journey',
  featuredCoursesLimit: 4,

  // LMS Widget Customization - Typing Challenge
  typingChallengeTitle: 'Test Your Typing Speed',
  typingChallengeShowStats: true,
  typingChallengeShowPvp: true,

  // LMS Widget Customization - Quick Quiz
  quickQuizTitle: 'Quick Quiz',
  quickQuizSubtitle: 'Test your knowledge',
  quickQuizLimit: 4,

  // LMS Widget Customization - Tutorial Paths
  tutorialPathsTitle: 'Learning Paths',
  tutorialPathsSubtitle: 'Structured tutorials to guide your learning',
  tutorialPathsCategoriesLimit: 4,

  // LMS Widget Customization - Leaderboard
  leaderboardTitle: 'Top Learners',
  leaderboardLimit: 5,
  leaderboardShowStreak: true,

  // LMS Widget Customization - Daily Challenges
  dailyChallengeGuestMessage: 'Sign up to track your progress and earn rewards!',
  dailyChallengeShowStreak: true,

  // LMS Widget Customization - Homepage Stats
  homepageStatsTitle: 'Community Progress',
  homepageStatsShowActiveToday: true,

  // Homepage Section Order
  homepageSectionOrder: null,
};

export const SiteSettings: React.FC = () => {
  const navigate = useNavigate();
  const [settings, setSettings] = useState<SiteSettings>(defaultSettings);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'analytics' | 'seo' | 'homepage' | 'layout' | 'lms' | 'social' | 'contact' | 'branding' | 'email'>('homepage');
  const [uploadingLogo, setUploadingLogo] = useState<'light' | 'dark' | null>(null);
  const [uploadingFavicon, setUploadingFavicon] = useState<'light' | 'dark' | null>(null);

  // Helper to convert null values to defaults
  const cleanSettings = (data: any): SiteSettings => {
    const cleaned = { ...defaultSettings };
    Object.keys(data).forEach((key) => {
      if (data[key] !== null && data[key] !== undefined) {
        (cleaned as any)[key] = data[key];
      }
    });
    return cleaned;
  };

  // Fetch settings from API on mount
  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      // Use public endpoint for reading (no auth required)
      const response = await fetch('/api/v1/site-settings');

      if (!response.ok) {
        if (response.status === 404) {
          // No settings yet, use defaults
          setSettings(defaultSettings);
        } else {
          throw new Error('Failed to fetch settings');
        }
      } else {
        const data = await response.json();
        // Convert null values to defaults
        setSettings(cleanSettings(data));
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
      const field = logoType === 'light' ? 'logoUrl' : 'logoDarkUrl';
      setSettings({ ...settings, [field]: data.url });

      console.log(`✓ ${logoType} logo uploaded successfully: ${data.url}`);
    } catch (err) {
      console.error('Error uploading logo:', err);
      setError(`Failed to upload ${logoType} logo. Please try again.`);
    } finally {
      setUploadingLogo(null);
    }
  };

  const handleFaviconUpload = async (file: File, faviconType: 'light' | 'dark') => {
    if (!file) return;

    // Validate file type (SVG, PNG, WebP, ICO)
    const validTypes = ['image/svg+xml', 'image/png', 'image/webp', 'image/x-icon'];
    if (!validTypes.includes(file.type)) {
      setError('Please upload a valid favicon (SVG, PNG, WebP, or ICO)');
      return;
    }

    // Validate file size (1MB max for favicon)
    if (file.size > 1024 * 1024) {
      setError('Favicon must be less than 1MB');
      return;
    }

    try {
      setUploadingFavicon(faviconType);
      setError(null);

      const formData = new FormData();
      formData.append('file', file);
      formData.append('alt_text', `Site favicon (${faviconType} mode)`);

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
      const field = faviconType === 'light' ? 'faviconUrl' : 'faviconDarkUrl';
      setSettings({ ...settings, [field]: data.url });

      console.log(`✓ ${faviconType} favicon uploaded successfully: ${data.url}`);
    } catch (err) {
      console.error('Error uploading favicon:', err);
      setError(`Failed to upload ${faviconType} favicon. Please try again.`);
    } finally {
      setUploadingFavicon(null);
    }
  };

  const tabs = [
    { id: 'homepage', label: 'Homepage', icon: '🏠' },
    { id: 'layout', label: 'Blog Sections', icon: '📐' },
    { id: 'lms', label: 'LMS Widgets', icon: '🎓' },
    { id: 'seo', label: 'SEO & Domain', icon: '🔍' },
    { id: 'branding', label: 'Branding & Logo', icon: '🎨' },
    { id: 'analytics', label: 'Analytics & Ads', icon: '📊' },
    { id: 'social', label: 'Social Media', icon: '🌐' },
    { id: 'contact', label: 'Contact Info', icon: '📧' },
    { id: 'email', label: 'Email & Newsletter', icon: '✉️' },
  ] as const;

  if (loading && !settings.siteTitle) {
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
                      value={settings.heroCtaPrimary}
                      onChange={(e) => handleChange('heroCtaPrimary', e.target.value)}
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
                      value={settings.heroCtaSecondary}
                      onChange={(e) => handleChange('heroCtaSecondary', e.target.value)}
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

            {/* Homepage Layout Tab */}
            {activeTab === 'layout' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-purple-900 dark:text-purple-300 mb-2">
                    📐 Homepage Layout Control
                  </h3>
                  <p className="text-sm text-purple-800 dark:text-purple-400">
                    Show/hide sections, customize titles, and control limits for carousel, categories, and recent posts.
                  </p>
                </div>

                {/* Carousel Section */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      Featured Carousel
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showCarousel', !settings.showCarousel)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showCarousel
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showCarousel ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showCarousel && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.carouselTitle}
                          onChange={(e) => handleChange('carouselTitle', e.target.value)}
                          placeholder="Featured Articles"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Subtitle
                        </label>
                        <input
                          type="text"
                          value={settings.carouselSubtitle}
                          onChange={(e) => handleChange('carouselSubtitle', e.target.value)}
                          placeholder="Hand-picked posts showcasing our best content"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Number of Posts
                          </label>
                          <input
                            type="number"
                            min="1"
                            max="10"
                            value={settings.carouselLimit}
                            onChange={(e) => handleChange('carouselLimit', parseInt(e.target.value) || 5)}
                            className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          />
                          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">1-10 posts</p>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Auto-play Interval (ms)
                          </label>
                          <input
                            type="number"
                            min="3000"
                            max="30000"
                            step="1000"
                            value={settings.carouselInterval}
                            onChange={(e) => handleChange('carouselInterval', parseInt(e.target.value) || 7000)}
                            className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          />
                          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">3000-30000 ms</p>
                        </div>

                        <div className="flex flex-col justify-end">
                          <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg">
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Auto-play</span>
                            <button
                              type="button"
                              onClick={() => handleChange('carouselAutoplay', !settings.carouselAutoplay)}
                              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                                settings.carouselAutoplay
                                  ? 'bg-blue-600 dark:bg-blue-700'
                                  : 'bg-gray-300 dark:bg-slate-600'
                              }`}
                            >
                              <span
                                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                  settings.carouselAutoplay ? 'translate-x-6' : 'translate-x-1'
                                }`}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Categories Section */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      Categories Showcase
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showCategories', !settings.showCategories)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showCategories
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showCategories ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showCategories && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.categoriesTitle}
                          onChange={(e) => handleChange('categoriesTitle', e.target.value)}
                          placeholder="Explore by Category"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Subtitle
                        </label>
                        <input
                          type="text"
                          value={settings.categoriesSubtitle}
                          onChange={(e) => handleChange('categoriesSubtitle', e.target.value)}
                          placeholder="Dive into topics that interest you"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Number of Categories
                        </label>
                        <input
                          type="number"
                          min="3"
                          max="12"
                          value={settings.categoriesLimit}
                          onChange={(e) => handleChange('categoriesLimit', parseInt(e.target.value) || 6)}
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">3-12 categories (best: 6 or 9)</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Recent Posts Section */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      Recent Posts Grid
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showRecentPosts', !settings.showRecentPosts)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showRecentPosts
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showRecentPosts ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showRecentPosts && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.recentPostsTitle}
                          onChange={(e) => handleChange('recentPostsTitle', e.target.value)}
                          placeholder="Latest Posts"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Subtitle
                        </label>
                        <input
                          type="text"
                          value={settings.recentPostsSubtitle}
                          onChange={(e) => handleChange('recentPostsSubtitle', e.target.value)}
                          placeholder="Fresh content from our writers"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Number of Posts
                        </label>
                        <input
                          type="number"
                          min="3"
                          max="12"
                          value={settings.recentPostsLimit}
                          onChange={(e) => handleChange('recentPostsLimit', parseInt(e.target.value) || 6)}
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">3-12 posts (best: 3, 6, or 9)</p>
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {/* LMS Widgets Tab */}
            {activeTab === 'lms' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
              >
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-green-900 dark:text-green-300 mb-2">
                    🎓 LMS Widgets
                  </h3>
                  <p className="text-sm text-green-800 dark:text-green-400">
                    Configure learning management widgets displayed on your homepage. Toggle visibility and customize titles for each section.
                  </p>
                </div>

                {/* Featured Courses Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      🎓 Featured Courses
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showFeaturedCourses', !settings.showFeaturedCourses)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showFeaturedCourses
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showFeaturedCourses ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showFeaturedCourses && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.featuredCoursesTitle}
                          onChange={(e) => handleChange('featuredCoursesTitle', e.target.value)}
                          placeholder="Featured Courses"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Subtitle
                        </label>
                        <input
                          type="text"
                          value={settings.featuredCoursesSubtitle}
                          onChange={(e) => handleChange('featuredCoursesSubtitle', e.target.value)}
                          placeholder="Start your learning journey"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Number of Courses
                        </label>
                        <input
                          type="number"
                          min="2"
                          max="8"
                          value={settings.featuredCoursesLimit}
                          onChange={(e) => handleChange('featuredCoursesLimit', parseInt(e.target.value) || 4)}
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">2-8 courses</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Typing Challenge Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      ⌨️ Typing Challenge
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showTypingChallenge', !settings.showTypingChallenge)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showTypingChallenge
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showTypingChallenge ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showTypingChallenge && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.typingChallengeTitle}
                          onChange={(e) => handleChange('typingChallengeTitle', e.target.value)}
                          placeholder="Test Your Typing Speed"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg">
                          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Show Speed/Accuracy Stats</span>
                          <button
                            type="button"
                            onClick={() => handleChange('typingChallengeShowStats', !settings.typingChallengeShowStats)}
                            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                              settings.typingChallengeShowStats
                                ? 'bg-blue-600 dark:bg-blue-700'
                                : 'bg-gray-300 dark:bg-slate-600'
                            }`}
                          >
                            <span
                              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                settings.typingChallengeShowStats ? 'translate-x-6' : 'translate-x-1'
                              }`}
                            />
                          </button>
                        </div>
                        <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg">
                          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Show PvP Button</span>
                          <button
                            type="button"
                            onClick={() => handleChange('typingChallengeShowPvp', !settings.typingChallengeShowPvp)}
                            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                              settings.typingChallengeShowPvp
                                ? 'bg-blue-600 dark:bg-blue-700'
                                : 'bg-gray-300 dark:bg-slate-600'
                            }`}
                          >
                            <span
                              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                settings.typingChallengeShowPvp ? 'translate-x-6' : 'translate-x-1'
                              }`}
                            />
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Quick Quiz Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      🧠 Quick Quiz
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showQuickQuiz', !settings.showQuickQuiz)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showQuickQuiz
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showQuickQuiz ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showQuickQuiz && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.quickQuizTitle}
                          onChange={(e) => handleChange('quickQuizTitle', e.target.value)}
                          placeholder="Quick Quiz"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Subtitle
                        </label>
                        <input
                          type="text"
                          value={settings.quickQuizSubtitle}
                          onChange={(e) => handleChange('quickQuizSubtitle', e.target.value)}
                          placeholder="Test your knowledge"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Number of Quizzes
                        </label>
                        <input
                          type="number"
                          min="2"
                          max="6"
                          value={settings.quickQuizLimit}
                          onChange={(e) => handleChange('quickQuizLimit', parseInt(e.target.value) || 4)}
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">2-6 quizzes</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Tutorial Paths Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      📚 Tutorial Paths
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showTutorialPaths', !settings.showTutorialPaths)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showTutorialPaths
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showTutorialPaths ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showTutorialPaths && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.tutorialPathsTitle}
                          onChange={(e) => handleChange('tutorialPathsTitle', e.target.value)}
                          placeholder="Learning Paths"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Subtitle
                        </label>
                        <input
                          type="text"
                          value={settings.tutorialPathsSubtitle}
                          onChange={(e) => handleChange('tutorialPathsSubtitle', e.target.value)}
                          placeholder="Structured tutorials to guide your learning"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Number of Categories
                        </label>
                        <input
                          type="number"
                          min="2"
                          max="6"
                          value={settings.tutorialPathsCategoriesLimit}
                          onChange={(e) => handleChange('tutorialPathsCategoriesLimit', parseInt(e.target.value) || 4)}
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">2-6 categories</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Leaderboard Preview Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      🏆 Leaderboard Preview
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showLeaderboardPreview', !settings.showLeaderboardPreview)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showLeaderboardPreview
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showLeaderboardPreview ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showLeaderboardPreview && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.leaderboardTitle}
                          onChange={(e) => handleChange('leaderboardTitle', e.target.value)}
                          placeholder="Top Learners"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Number of Users
                          </label>
                          <input
                            type="number"
                            min="3"
                            max="10"
                            value={settings.leaderboardLimit}
                            onChange={(e) => handleChange('leaderboardLimit', parseInt(e.target.value) || 5)}
                            className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          />
                          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">3-10 users</p>
                        </div>
                        <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg">
                          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Show Streak</span>
                          <button
                            type="button"
                            onClick={() => handleChange('leaderboardShowStreak', !settings.leaderboardShowStreak)}
                            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                              settings.leaderboardShowStreak
                                ? 'bg-blue-600 dark:bg-blue-700'
                                : 'bg-gray-300 dark:bg-slate-600'
                            }`}
                          >
                            <span
                              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                settings.leaderboardShowStreak ? 'translate-x-6' : 'translate-x-1'
                              }`}
                            />
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Daily Challenge Banner Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      🎯 Daily Challenge Banner
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showDailyChallengeBanner', !settings.showDailyChallengeBanner)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showDailyChallengeBanner
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showDailyChallengeBanner ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showDailyChallengeBanner && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Guest CTA Message
                        </label>
                        <input
                          type="text"
                          value={settings.dailyChallengeGuestMessage}
                          onChange={(e) => handleChange('dailyChallengeGuestMessage', e.target.value)}
                          placeholder="Sign up to track your progress and earn rewards!"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Shown to non-logged-in users</p>
                      </div>
                      <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg">
                        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Show Streak Bonus</span>
                        <button
                          type="button"
                          onClick={() => handleChange('dailyChallengeShowStreak', !settings.dailyChallengeShowStreak)}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            settings.dailyChallengeShowStreak
                              ? 'bg-blue-600 dark:bg-blue-700'
                              : 'bg-gray-300 dark:bg-slate-600'
                          }`}
                        >
                          <span
                            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                              settings.dailyChallengeShowStreak ? 'translate-x-6' : 'translate-x-1'
                            }`}
                          />
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Homepage Stats Widget */}
                <div className="border border-gray-200 dark:border-slate-700 rounded-lg p-6 bg-white dark:bg-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      📊 Community Stats
                    </h3>
                    <button
                      type="button"
                      onClick={() => handleChange('showHomepageStats', !settings.showHomepageStats)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showHomepageStats
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showHomepageStats ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {settings.showHomepageStats && (
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Section Title
                        </label>
                        <input
                          type="text"
                          value={settings.homepageStatsTitle}
                          onChange={(e) => handleChange('homepageStatsTitle', e.target.value)}
                          placeholder="Community Progress"
                          className="w-full px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div className="flex items-center justify-between bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg">
                        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Show "X Active Today"</span>
                        <button
                          type="button"
                          onClick={() => handleChange('homepageStatsShowActiveToday', !settings.homepageStatsShowActiveToday)}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            settings.homepageStatsShowActiveToday
                              ? 'bg-blue-600 dark:bg-blue-700'
                              : 'bg-gray-300 dark:bg-slate-600'
                          }`}
                        >
                          <span
                            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                              settings.homepageStatsShowActiveToday ? 'translate-x-6' : 'translate-x-1'
                            }`}
                          />
                        </button>
                      </div>
                    </div>
                  )}
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
                    ✅ Auto Ads Enabled
                  </h3>
                  <p className="text-sm text-blue-800 dark:text-blue-400 mb-3">
                    Once you save your AdSense Client ID, Auto Ads will be automatically enabled across all pages.
                  </p>
                  <ul className="text-sm text-blue-800 dark:text-blue-400 space-y-1 list-disc list-inside">
                    <li>Google will automatically place ads on your site</li>
                    <li>Fully integrated with GDPR cookie consent</li>
                    <li>CSP-compliant and secure</li>
                    <li>No additional setup required</li>
                  </ul>
                  <p className="text-xs text-blue-700 dark:text-blue-500 mt-3">
                    Note: It may take 24-48 hours for Google to start showing ads after enabling Auto Ads in your AdSense account.
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
                    value={settings.siteTitle}
                    onChange={(e) => handleChange('siteTitle', e.target.value)}
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
                    value={settings.siteTagline}
                    onChange={(e) => handleChange('siteTagline', e.target.value)}
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
                    Used in sitemap and RSS feed URLs
                  </p>
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
                    Recommended: 150-160 characters. Used in RSS feed description.
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
                    Open Graph Image URL
                  </label>
                  <input
                    type="url"
                    value={settings.ogImage}
                    onChange={(e) => handleChange('ogImage', e.target.value)}
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
                      value={settings.logoUrl}
                      onChange={(e) => handleChange('logoUrl', e.target.value)}
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
                      value={settings.logoDarkUrl}
                      onChange={(e) => handleChange('logoDarkUrl', e.target.value)}
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

                {(settings.logoUrl || settings.logoDarkUrl) && (
                  <div className="border-t border-gray-200 dark:border-slate-700 pt-6">
                    <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                      Logo Preview
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                      {settings.logoUrl && (
                        <div className="bg-white dark:bg-slate-700 p-4 rounded-lg border border-gray-200 dark:border-slate-600">
                          <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Light Mode</p>
                          <img src={settings.logoUrl} alt="Logo (Light)" className="max-h-16 mx-auto" />
                        </div>
                      )}
                      {settings.logoDarkUrl && (
                        <div className="bg-slate-900 p-4 rounded-lg border border-slate-700">
                          <p className="text-xs text-gray-400 mb-2">Dark Mode</p>
                          <img src={settings.logoDarkUrl} alt="Logo (Dark)" className="max-h-16 mx-auto" />
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Favicon Upload Section */}
                <div className="border-t border-gray-200 dark:border-slate-700 pt-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                    Favicon (Browser Tab Icon)
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    Upload custom favicons for light and dark modes. Recommended: 32x32px SVG or PNG.
                  </p>

                  <div className="space-y-4">
                    {/* Light Mode Favicon */}
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Favicon (Light Mode)
                      </label>
                      <div className="flex gap-2">
                        <input
                          type="url"
                          value={settings.faviconUrl}
                          onChange={(e) => handleChange('faviconUrl', e.target.value)}
                          placeholder="/apprentice.svg or https://yourdomain.com/favicon.svg"
                          className="flex-1 px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <label className="relative">
                          <input
                            type="file"
                            accept="image/svg+xml,image/png,image/webp,image/x-icon"
                            className="hidden"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) handleFaviconUpload(file, 'light');
                            }}
                            disabled={uploadingFavicon === 'light'}
                          />
                          <button
                            type="button"
                            onClick={(e) => {
                              e.preventDefault();
                              const inputs = document.querySelectorAll<HTMLInputElement>('input[type="file"][accept*="svg"]');
                              inputs[0]?.click();
                            }}
                            disabled={uploadingFavicon === 'light'}
                            className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                          >
                            {uploadingFavicon === 'light' ? (
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
                        Favicon for light mode (paste URL or upload: SVG, PNG, WebP, or ICO - max 1MB)
                      </p>
                    </div>

                    {/* Dark Mode Favicon */}
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Favicon (Dark Mode)
                      </label>
                      <div className="flex gap-2">
                        <input
                          type="url"
                          value={settings.faviconDarkUrl}
                          onChange={(e) => handleChange('faviconDarkUrl', e.target.value)}
                          placeholder="/apprentice-dark.svg or https://yourdomain.com/favicon-dark.svg"
                          className="flex-1 px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <label className="relative">
                          <input
                            type="file"
                            accept="image/svg+xml,image/png,image/webp,image/x-icon"
                            className="hidden"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) handleFaviconUpload(file, 'dark');
                            }}
                            disabled={uploadingFavicon === 'dark'}
                          />
                          <button
                            type="button"
                            onClick={(e) => {
                              e.preventDefault();
                              const input = (e.currentTarget.previousElementSibling as HTMLInputElement);
                              input?.click();
                            }}
                            disabled={uploadingFavicon === 'dark'}
                            className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                          >
                            {uploadingFavicon === 'dark' ? (
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
                        Optional - falls back to light mode favicon if not set
                      </p>
                    </div>
                  </div>

                  {/* Favicon Preview */}
                  {(settings.faviconUrl || settings.faviconDarkUrl) && (
                    <div className="mt-4 border-t border-gray-200 dark:border-slate-700 pt-4">
                      <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                        Favicon Preview
                      </h4>
                      <div className="grid grid-cols-2 gap-4">
                        {settings.faviconUrl && (
                          <div className="bg-white dark:bg-slate-700 p-4 rounded-lg border border-gray-200 dark:border-slate-600">
                            <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Light Mode</p>
                            <div className="flex items-center gap-3">
                              <img
                                src={settings.faviconUrl}
                                alt="Favicon (Light)"
                                className="w-8 h-8 border border-gray-300 dark:border-slate-500 rounded"
                                onError={(e) => {
                                  e.currentTarget.style.display = 'none';
                                }}
                              />
                              <code className="text-xs text-gray-600 dark:text-gray-300 break-all">
                                {settings.faviconUrl}
                              </code>
                            </div>
                          </div>
                        )}
                        {settings.faviconDarkUrl && (
                          <div className="bg-slate-900 p-4 rounded-lg border border-slate-700">
                            <p className="text-xs text-gray-400 mb-2">Dark Mode</p>
                            <div className="flex items-center gap-3">
                              <img
                                src={settings.faviconDarkUrl}
                                alt="Favicon (Dark)"
                                className="w-8 h-8 border border-slate-500 rounded"
                                onError={(e) => {
                                  e.currentTarget.style.display = 'none';
                                }}
                              />
                              <code className="text-xs text-gray-300 break-all">
                                {settings.faviconDarkUrl}
                              </code>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>

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
                      onClick={() => handleChange('showPoweredBy', !settings.showPoweredBy)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.showPoweredBy
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.showPoweredBy ? 'translate-x-6' : 'translate-x-1'
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
                      onClick={() => handleChange('newsletterEnabled', !settings.newsletterEnabled)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        settings.newsletterEnabled
                          ? 'bg-blue-600 dark:bg-blue-700'
                          : 'bg-gray-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          settings.newsletterEnabled ? 'translate-x-6' : 'translate-x-1'
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
                          value={settings.smtpHost}
                          onChange={(e) => handleChange('smtpHost', e.target.value)}
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
                          value={settings.smtpPort}
                          onChange={(e) => handleChange('smtpPort', parseInt(e.target.value) || 587)}
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
                          value={settings.smtpUsername}
                          onChange={(e) => handleChange('smtpUsername', e.target.value)}
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
                          value={settings.smtpPassword}
                          onChange={(e) => handleChange('smtpPassword', e.target.value)}
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
                          value={settings.smtpFromEmail}
                          onChange={(e) => handleChange('smtpFromEmail', e.target.value)}
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
                          value={settings.smtpFromName}
                          onChange={(e) => handleChange('smtpFromName', e.target.value)}
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
                        onClick={() => handleChange('smtpUseTls', !settings.smtpUseTls)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.smtpUseTls
                            ? 'bg-blue-600 dark:bg-blue-700'
                            : 'bg-gray-300 dark:bg-slate-600'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            settings.smtpUseTls ? 'translate-x-6' : 'translate-x-1'
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
