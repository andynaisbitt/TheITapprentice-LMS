// src/pages/BlogHome.tsx
/**
 * Enhanced Blog Homepage V3
 * Features: Feature Showcase Hero, LMS Widgets, then Blog Content
 */

import { Helmet } from 'react-helmet-async';
import FeatureShowcaseHero from '../components/home/FeatureShowcaseHero';
import FeaturedCarousel from '../components/home/FeaturedCarousel';
import RecentPostsGrid from '../components/home/RecentPostsGrid';
import CategoryShowcase from '../components/home/CategoryShowcase';
import DailyChallengeBanner from '../components/home/DailyChallengeBanner';
import FeaturedCoursesCarousel from '../components/home/FeaturedCoursesCarousel';
import TypingChallengeCTA from '../components/home/TypingChallengeCTA';
import QuickQuizWidget from '../components/home/QuickQuizWidget';
import TutorialPathsShowcase from '../components/home/TutorialPathsShowcase';
import LeaderboardPreview from '../components/home/LeaderboardPreview';
import HomepageStatsWidget from '../components/home/HomepageStatsWidget';
import MoreToExplore from '../components/home/MoreToExplore';
import Section from '../components/home/Section';
import { Sparkles, Newspaper, FolderOpen } from 'lucide-react';
import { useSiteSettings } from '../store/useSiteSettingsStore';
import { useAuth } from '../state/contexts/AuthContext';

export const BlogHome: React.FC = () => {
  const { settings } = useSiteSettings();
  const { user } = useAuth();

  // Build full page title with tagline if available
  const pageTitle = settings.siteTagline
    ? `${settings.siteTitle} - ${settings.siteTagline}`
    : settings.siteTitle;

  // Use OG image from settings, fallback to /og-image.jpg
  const ogImage = settings.ogImage || `${settings.siteUrl}/og-image.jpg`;

  // Check if any blog sections are enabled
  const hasBlogContent = settings.showCarousel || settings.showCategories || settings.showRecentPosts;

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
        {/* SECTION 2: Daily Challenge Banner           */}
        {/* Only shows for logged-in users              */}
        {/* ============================================ */}
        {user && settings.showDailyChallengeBanner && <DailyChallengeBanner />}

        {/* ============================================ */}
        {/* SECTION 3: Featured Courses                 */}
        {/* LMS courses carousel                        */}
        {/* ============================================ */}
        {settings.showFeaturedCourses && <FeaturedCoursesCarousel />}

        {/* ============================================ */}
        {/* SECTION 4: Tutorial Paths                   */}
        {/* Structured learning paths                   */}
        {/* ============================================ */}
        {settings.showTutorialPaths && <TutorialPathsShowcase />}

        {/* ============================================ */}
        {/* SECTION 5: Typing Challenge CTA             */}
        {/* Typing game promotion                       */}
        {/* ============================================ */}
        {settings.showTypingChallenge && <TypingChallengeCTA />}

        {/* ============================================ */}
        {/* SECTION 5b: More to Explore                 */}
        {/* Compact LMS feature showcase                */}
        {/* ============================================ */}
        <MoreToExplore exclude={['typing']} limit={6} />

        {/* ============================================ */}
        {/* SECTION 6: Quick Quiz Widget                */}
        {/* Quiz promotion section                      */}
        {/* ============================================ */}
        {settings.showQuickQuiz && <QuickQuizWidget />}

        {/* ============================================ */}
        {/* SECTION 7: Leaderboard Preview              */}
        {/* Top learners showcase                       */}
        {/* ============================================ */}
        {settings.showLeaderboardPreview && <LeaderboardPreview />}

        {/* ============================================ */}
        {/* SECTION 8: Community Stats                  */}
        {/* Platform statistics                         */}
        {/* ============================================ */}
        {settings.showHomepageStats && (
          <section className="bg-gradient-to-b from-gray-50 to-gray-100 dark:from-slate-900 dark:to-slate-800 py-8">
            <HomepageStatsWidget />
          </section>
        )}

        {/* ============================================ */}
        {/* BLOG CONTENT SECTION                        */}
        {/* Blog articles and categories below LMS      */}
        {/* ============================================ */}
        {hasBlogContent && (
          <div className="border-t border-slate-200 dark:border-slate-800">
            {/* Blog Section Header */}
            <Section
              icon={Newspaper}
              eyebrow="Blog"
              title="Latest from the Blog"
              subtitle="Articles, tutorials, and insights from our community"
              centerHeader
              paddingY="lg"
              noPadding={false}
            >
              {/* Empty content - header only */}
              <div className="hidden" />
            </Section>

            {/* Featured Posts Carousel */}
            {settings.showCarousel && (
              <Section
                icon={Sparkles}
                eyebrow="Featured"
                title={settings.carouselTitle || 'Featured Articles'}
                subtitle={settings.carouselSubtitle || 'Hand-picked posts showcasing our best content'}
                paddingY="md"
              >
                <FeaturedCarousel />
              </Section>
            )}

            {/* Categories Showcase */}
            {settings.showCategories && (
              <Section
                icon={FolderOpen}
                eyebrow="Categories"
                title={settings.categoriesTitle || 'Explore by Category'}
                subtitle={settings.categoriesSubtitle || 'Dive into topics that interest you'}
                background="muted"
                centerHeader
                viewAllLink="/blog"
                viewAllText="Browse all categories"
                paddingY="md"
              >
                <CategoryShowcase />
              </Section>
            )}

            {/* Recent Posts Grid */}
            {settings.showRecentPosts && (
              <Section
                eyebrow="Latest"
                title={settings.recentPostsTitle || 'Latest Posts'}
                subtitle={settings.recentPostsSubtitle || 'Fresh content from our writers'}
                viewAllLink="/blog"
                viewAllText="View all posts"
                paddingY="lg"
              >
                <RecentPostsGrid limit={6} />
              </Section>
            )}
          </div>
        )}
      </div>
    </>
  );
};

export default BlogHome;
