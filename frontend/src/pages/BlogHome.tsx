// src/pages/BlogHome.tsx
/**
 * Homepage V4 - Streamlined Learning Platform
 * 5 focused sections with clear narrative flow
 *
 * Structure:
 * 1. FeatureShowcaseHero - Full viewport hero slider (8 features)
 * 2. ThePulse - Trending content + compact leaderboard
 * 3. BlogPreviewGrid - 3 latest articles (controlled by showCarousel)
 * 4. CategoryShowcase - Topics with 3+ articles (controlled by showCategories)
 * 5. FinalCTA - Bottom call to action with wave transition
 */

import { Helmet } from 'react-helmet-async';
import FeatureShowcaseHero from '../components/home/FeatureShowcaseHero';
import CategoryShowcase from '../components/home/CategoryShowcase';
import ThePulse from '../components/home/ThePulse';
// LearningPathsShowcase removed - shows static placeholder content, not real data
import BlogPreviewGrid from '../components/home/BlogPreviewGrid';
import FinalCTA from '../components/home/FinalCTA';
import Section from '../components/home/Section';
import { FolderOpen } from 'lucide-react';
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
        {/* ============================================ */}
        {/* SECTION 1: Feature Showcase Hero            */}
        {/* Auto-cycling hero showcasing LMS features   */}
        {/* ============================================ */}
        <FeatureShowcaseHero />

        {/* ============================================ */}
        {/* SECTION 2: The Pulse                        */}
        {/* Trending content + Leaderboard sidebar      */}
        {/* ============================================ */}
        <ThePulse />

        {/* LearningPaths section removed - was showing static placeholder content */}

        {/* ============================================ */}
        {/* SECTION 4: Blog Preview                     */}
        {/* Compact 3-post grid for SEO                 */}
        {/* ============================================ */}
        {settings.showCarousel && <BlogPreviewGrid />}

        {/* ============================================ */}
        {/* SECTION 5: Explore by Category              */}
        {/* Navigation / Table of Contents              */}
        {/* ============================================ */}
        {settings.showCategories && (
          <Section
            icon={FolderOpen}
            eyebrow="Explore"
            title={settings.categoriesTitle || 'Explore by Topic'}
            subtitle={settings.categoriesSubtitle || 'Pick a topic and start learning'}
            background="default"
            paddingY="md"
          >
            <CategoryShowcase />
          </Section>
        )}

        {/* ============================================ */}
        {/* SECTION 6: Final CTA                        */}
        {/* Clear next action                           */}
        {/* ============================================ */}
        <FinalCTA />
      </div>
    </>
  );
};

export default BlogHome;
