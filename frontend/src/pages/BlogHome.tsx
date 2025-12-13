// src/pages/BlogHome.tsx
/**
 * Enhanced Blog Homepage V2
 * Features: Hero, Featured Carousel, Recent Grid, Categories
 */

import { Helmet } from 'react-helmet-async';
import HeroSection from '../components/home/HeroSection';
import FeaturedCarousel from '../components/home/FeaturedCarousel';
import RecentPostsGrid from '../components/home/RecentPostsGrid';
import CategoryShowcase from '../components/home/CategoryShowcase';
import { Sparkles } from 'lucide-react';
import { useSiteSettings } from '../store/useSiteSettingsStore';

export const BlogHome: React.FC = () => {
  const { settings } = useSiteSettings();

  // Build full page title with tagline if available
  const pageTitle = settings.siteTagline
    ? `${settings.siteTitle} - ${settings.siteTagline}`
    : settings.siteTitle;

  // Use OG image from settings, fallback to /og-image.jpg
  const ogImage = settings.ogImage || `${settings.siteUrl}/og-image.jpg`;

  return (
    <>
      {/* SEO Meta Tags for Homepage */}
      <Helmet>
        <title>{pageTitle}</title>
        <meta name="description" content={settings.metaDescription} />
        {settings.metaKeywords && <meta name="keywords" content={settings.metaKeywords} />}

        {/* Open Graph / Facebook */}
        <meta property="og:type" content="website" />
        <meta property="og:url" content={settings.siteUrl} />
        <meta property="og:title" content={settings.siteTitle} />
        <meta property="og:description" content={settings.metaDescription} />
        <meta property="og:image" content={ogImage} />
        <meta property="og:site_name" content={settings.siteTitle} />

        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:url" content={settings.siteUrl} />
        <meta name="twitter:title" content={settings.siteTitle} />
        <meta name="twitter:description" content={settings.metaDescription} />
        <meta name="twitter:image" content={ogImage} />
        {settings.twitterHandle && <meta name="twitter:site" content={`@${settings.twitterHandle}`} />}

        {/* LinkedIn */}
        <meta property="og:locale" content="en_US" />

        {/* Canonical URL */}
        <link rel="canonical" href={settings.siteUrl} />
      </Helmet>

      <div className="min-h-screen bg-gray-50 dark:bg-slate-900 scroll-smooth">
        {/* Hero Section */}
        <HeroSection />

        {/* Featured Posts Carousel */}
        {settings.showCarousel && (
          <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
            <div className="mb-8 sm:mb-12">
              <div className="flex items-center gap-2 sm:gap-3 mb-3">
                <Sparkles className="text-yellow-500 w-6 h-6 sm:w-7 sm:h-7" size={28} />
                <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white">
                  {settings.carouselTitle || 'Featured Articles'}
                </h2>
              </div>
              <p className="text-base sm:text-lg text-gray-600 dark:text-gray-400">
                {settings.carouselSubtitle || 'Hand-picked posts showcasing our best content'}
              </p>
            </div>
            <FeaturedCarousel />
          </section>
        )}

        {/* Categories Showcase */}
        {settings.showCategories && (
          <section className="bg-white dark:bg-gray-800 py-12 sm:py-16">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="text-center mb-8 sm:mb-12">
                <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white mb-2 sm:mb-3">
                  {settings.categoriesTitle || 'Explore by Category'}
                </h2>
                <p className="text-base sm:text-lg text-gray-600 dark:text-gray-400">
                  {settings.categoriesSubtitle || 'Dive into topics that interest you'}
                </p>
              </div>
              <CategoryShowcase />
            </div>
          </section>
        )}

        {/* Recent Posts Grid */}
        {settings.showRecentPosts && (
          <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
            <div className="mb-8 sm:mb-12">
              <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white mb-2 sm:mb-3">
                {settings.recentPostsTitle || 'Latest Posts'}
              </h2>
              <p className="text-base sm:text-lg text-gray-600 dark:text-gray-400">
                {settings.recentPostsSubtitle || 'Fresh content from our writers'}
              </p>
            </div>
            <RecentPostsGrid />
          </section>
        )}
      </div>
    </>
  );
};

export default BlogHome;
