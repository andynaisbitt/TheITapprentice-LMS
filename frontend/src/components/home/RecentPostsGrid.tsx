// src/components/home/RecentPostsGrid.tsx
/**
 * Recent Posts Grid - Responsive grid of latest posts
 * Mobile-optimized with lazy loading and reduced motion support
 */

import { useState, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import { Calendar, Clock, ArrowRight, TrendingUp, RefreshCw } from 'lucide-react';
import { resolveImageUrl } from '../../utils/imageUrl';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

interface RecentPost {
  id: number;
  title: string;
  slug: string;
  excerpt: string;
  featured_image?: string | null;
  published_at: string | null;
  read_time_minutes?: number;
  categories: Array<{ id: number; name: string; slug: string; color?: string | null; icon?: string | null }>;
  view_count?: number;
}

interface RecentPostsGridProps {
  limit?: number;
}

export const RecentPostsGrid: React.FC<RecentPostsGridProps> = ({ limit }) => {
  const { settings } = useSiteSettings();
  const [posts, setPosts] = useState<RecentPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Check for reduced motion preference
  const prefersReducedMotion = useMemo(() => {
    if (typeof window === 'undefined') return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }, []);

  const effectiveLimit = limit ?? settings.recentPostsLimit ?? 6;

  // Load posts on mount and when limit changes
  useEffect(() => {
    const fetchRecentPosts = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await blogApi.getRecent(effectiveLimit);
        setPosts(data);
      } catch (err) {
        console.error('Failed to load recent posts:', err);
        setError('Failed to load posts');
      } finally {
        setLoading(false);
      }
    };
    fetchRecentPosts();
  }, [effectiveLimit]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const handleRetry = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await blogApi.getRecent(effectiveLimit);
      setPosts(data);
    } catch (err) {
      console.error('Failed to load recent posts:', err);
      setError('Failed to load posts');
    } finally {
      setLoading(false);
    }
  };

  // Loading skeleton
  if (loading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6 lg:gap-8">
        {[...Array(effectiveLimit)].map((_, i) => (
          <div
            key={i}
            className="bg-white dark:bg-gray-800 rounded-xl overflow-hidden shadow-lg animate-pulse"
          >
            <div className="h-40 sm:h-48 bg-gray-200 dark:bg-gray-700" />
            <div className="p-4 sm:p-5 space-y-3">
              <div className="flex gap-3">
                <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-20" />
                <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-16" />
              </div>
              <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded w-full" />
              <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-full" />
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-2/3" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="text-center py-8 sm:py-12 bg-white dark:bg-gray-800 rounded-xl">
        <p className="text-gray-500 dark:text-gray-400 mb-4">{error}</p>
        <button
          onClick={handleRetry}
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition text-sm"
        >
          <RefreshCw size={16} />
          Try Again
        </button>
      </div>
    );
  }

  // Empty state
  if (posts.length === 0) {
    return (
      <div className="text-center py-8 sm:py-12 bg-white dark:bg-gray-800 rounded-xl">
        <p className="text-gray-600 dark:text-gray-400">No posts yet. Check back soon!</p>
      </div>
    );
  }

  // Animation variants - enhanced for better visual appeal
  const containerVariants = {
    hidden: { opacity: prefersReducedMotion ? 1 : 0 },
    visible: {
      opacity: 1,
      transition: prefersReducedMotion ? {} : { staggerChildren: 0.1, delayChildren: 0.1 },
    },
  };

  const cardVariants = {
    hidden: { opacity: prefersReducedMotion ? 1 : 0, y: prefersReducedMotion ? 0 : 30, scale: prefersReducedMotion ? 1 : 0.95 },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: prefersReducedMotion ? {} : { duration: 0.5, ease: [0.25, 0.1, 0.25, 1] as const },
    },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial={prefersReducedMotion ? false : 'hidden'}
      whileInView="visible"
      viewport={{ once: true, margin: '-50px' }}
      className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 sm:gap-6 lg:gap-8"
    >
      {posts.map((post, index) => {
        const categoryColor = post.categories?.[0]?.color || '#6366f1';

        return (
          <motion.article
            key={post.id}
            variants={cardVariants}
            whileHover={prefersReducedMotion ? {} : { y: -8, scale: 1.02 }}
            whileTap={prefersReducedMotion ? {} : { scale: 0.98 }}
            transition={{ duration: 0.2 }}
            className="group relative bg-white dark:bg-gray-800 rounded-2xl overflow-hidden shadow-md hover:shadow-2xl transition-all duration-300"
          >
            {/* Colored top border accent */}
            <div
              className="absolute top-0 left-0 right-0 h-1 z-10"
              style={{ backgroundColor: categoryColor }}
            />

            <Link to={`/blog/${post.slug}`} className="block">
              {/* Image Container with parallax-like effect */}
              <div className="relative h-44 sm:h-52 overflow-hidden">
                {post.featured_image ? (
                  <motion.img
                    src={resolveImageUrl(post.featured_image)}
                    alt={post.title}
                    loading="lazy"
                    decoding="async"
                    className="w-full h-full object-cover"
                    whileHover={prefersReducedMotion ? {} : { scale: 1.1 }}
                    transition={{ duration: 0.6, ease: 'easeOut' }}
                  />
                ) : (
                  <div
                    className="w-full h-full flex items-center justify-center"
                    style={{
                      background: `linear-gradient(135deg, ${categoryColor}40 0%, ${categoryColor}80 100%)`,
                    }}
                  >
                    <span className="text-white/60 text-6xl font-bold">
                      {post.title.charAt(0)}
                    </span>
                  </div>
                )}

                {/* Enhanced gradient overlay */}
                <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent" />

                {/* Category Badge - repositioned with animation */}
                {post.categories?.[0] && (
                  <motion.div
                    className="absolute top-3 left-3"
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 + 0.3 }}
                  >
                    <span
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold backdrop-blur-md shadow-lg transition-transform duration-300 group-hover:scale-105"
                      style={{
                        backgroundColor: `${categoryColor}ee`,
                        color: 'white',
                      }}
                    >
                      {post.categories[0].icon && <span>{post.categories[0].icon}</span>}
                      <span className="max-w-[100px] truncate">{post.categories[0].name}</span>
                    </span>
                  </motion.div>
                )}

                {/* View Count Badge with pulse on hover */}
                {post.view_count != null && post.view_count > 0 && (
                  <div className="absolute bottom-3 right-3 flex items-center gap-1.5 px-2.5 py-1.5 bg-white/20 backdrop-blur-md rounded-full text-white text-xs font-medium group-hover:bg-white/30 transition-colors">
                    <TrendingUp size={14} className="text-green-400" />
                    <span>{post.view_count.toLocaleString()}</span>
                  </div>
                )}

                {/* Reading time pill at bottom left */}
                {post.read_time_minutes && (
                  <div className="absolute bottom-3 left-3 flex items-center gap-1 px-2 py-1 bg-white/20 backdrop-blur-md rounded-full text-white text-xs font-medium">
                    <Clock size={12} />
                    <span>{post.read_time_minutes} min read</span>
                  </div>
                )}
              </div>

              {/* Content with improved spacing */}
              <div className="p-5 sm:p-6">
                {/* Meta - date only since read time is on image */}
                <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-3">
                  <Calendar size={14} className="text-gray-400" />
                  <span className="font-medium">{post.published_at ? formatDate(post.published_at) : 'Draft'}</span>
                </div>

                {/* Title with gradient underline on hover */}
                <h3 className="relative text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-3 line-clamp-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors duration-300">
                  {post.title}
                </h3>

                {/* Excerpt with better typography */}
                {post.excerpt && (
                  <p className="text-gray-600 dark:text-gray-300 text-sm leading-relaxed mb-4 line-clamp-2">
                    {post.excerpt}
                  </p>
                )}

                {/* Enhanced Read More CTA */}
                <div className="flex items-center justify-between pt-3 border-t border-gray-100 dark:border-gray-700">
                  <span className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-sm group-hover:text-blue-700 dark:group-hover:text-blue-300 transition-colors">
                    Read article
                    <ArrowRight
                      size={16}
                      className="transform transition-transform duration-300 group-hover:translate-x-1.5"
                    />
                  </span>

                  {/* Animated dot indicator */}
                  <span
                    className="w-2 h-2 rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                    style={{ backgroundColor: categoryColor }}
                  />
                </div>
              </div>
            </Link>
          </motion.article>
        );
      })}
    </motion.div>
  );
};

export default RecentPostsGrid;
