// src/pages/BlogHome.tsx
/**
 * Enhanced Blog Homepage V2
 * Features: Hero, Featured Carousel, Recent Grid, Categories
 */

import React from 'react';
import { Helmet } from 'react-helmet-async';
import HeroSection from '../components/home/HeroSection';
import FeaturedCarousel from '../components/home/FeaturedCarousel';
import RecentPostsGrid from '../components/home/RecentPostsGrid';
import CategoryShowcase from '../components/home/CategoryShowcase';
import { Sparkles } from 'lucide-react';

export const BlogHome: React.FC = () => {
  const siteTitle = 'The IT Apprentice';
  const siteDescription = 'Professional insights on technology, software development, and IT practices. Real-world guides for developers, IT professionals, and tech enthusiasts.';
  const siteUrl = 'https://theitapprentice.com';
  const ogImage = `${siteUrl}/og-image.jpg`; // You can create a custom OG image

  return (
    <>
      {/* SEO Meta Tags for Homepage */}
      <Helmet>
        <title>{siteTitle} - Professional Tech Insights & IT Guides</title>
        <meta name="description" content={siteDescription} />
        <meta name="keywords" content="technology blog, software development, IT guides, programming tutorials, tech insights, developer resources, hardware reviews, tech industry" />

        {/* Open Graph / Facebook */}
        <meta property="og:type" content="website" />
        <meta property="og:url" content={siteUrl} />
        <meta property="og:title" content={siteTitle} />
        <meta property="og:description" content={siteDescription} />
        <meta property="og:image" content={ogImage} />
        <meta property="og:site_name" content={siteTitle} />

        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:url" content={siteUrl} />
        <meta name="twitter:title" content={siteTitle} />
        <meta name="twitter:description" content={siteDescription} />
        <meta name="twitter:image" content={ogImage} />

        {/* LinkedIn */}
        <meta property="og:locale" content="en_US" />

        {/* Canonical URL */}
        <link rel="canonical" href={siteUrl} />
      </Helmet>

      <div className="min-h-screen bg-gray-50 dark:bg-slate-900">
      {/* Hero Section */}
      <HeroSection />

      {/* Featured Posts Carousel */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-3">
            <Sparkles className="text-yellow-500" size={28} />
            <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white">
              Featured Articles
            </h2>
          </div>
          <p className="text-lg text-gray-600 dark:text-gray-400">
            Hand-picked posts showcasing our best content
          </p>
        </div>
        <FeaturedCarousel />
      </section>

      {/* Categories Showcase */}
      <section className="bg-white dark:bg-gray-800 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-3">
              Explore by Category
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-400">
              Dive into topics that interest you
            </p>
          </div>
          <CategoryShowcase />
        </div>
      </section>

      {/* Recent Posts Grid */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="mb-12">
          <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-3">
            Latest Posts
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-400">
            Fresh content from our writers
          </p>
        </div>
        <RecentPostsGrid />
      </section>

      </div>
    </>
  );
};

export default BlogHome;
