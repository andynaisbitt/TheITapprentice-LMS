// src/components/home/RecentPostsGrid.tsx
/**
 * Recent Posts Grid - 3-column grid of latest posts
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import { Calendar, Clock, ArrowRight, TrendingUp } from 'lucide-react';
import { resolveImageUrl } from '../../utils/imageUrl';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

interface RecentPost {
  id: number;
  title: string;
  slug: string;
  excerpt: string;
  featured_image?: string | null;
  published_at: string | null;
  categories: Array<{ id: number; name: string; color?: string | null; icon?: string | null }>;
  view_count?: number;
}

interface RecentPostsGridProps {
  limit?: number;
}

export const RecentPostsGrid: React.FC<RecentPostsGridProps> = ({ limit }) => {
  const { settings } = useSiteSettings();
  const [posts, setPosts] = useState<RecentPost[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRecentPosts();
  }, [limit, settings.recentPostsLimit]);

  const loadRecentPosts = async () => {
    try {
      const effectiveLimit = limit ?? settings.recentPostsLimit ?? 6;
      const data = await blogApi.getRecent(effectiveLimit);
      setPosts(data);
    } catch (error) {
      console.error('Failed to load recent posts:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {[...Array(6)].map((_, i) => (
          <div
            key={i}
            className="bg-gray-200 dark:bg-gray-800 rounded-xl h-96 animate-pulse"
          ></div>
        ))}
      </div>
    );
  }

  if (posts.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600 dark:text-gray-400">No posts yet. Check back soon!</p>
      </div>
    );
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.5,
      },
    },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: '-100px' }}
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8"
    >
      {posts.map((post) => (
        <motion.article
          key={post.id}
          variants={cardVariants}
          whileHover={{ y: -8 }}
          className="group bg-white dark:bg-gray-800 rounded-xl overflow-hidden shadow-lg hover:shadow-2xl transition-all duration-300 active:scale-98"
        >
          <Link to={`/blog/${post.slug}`} className="block touch-manipulation">
            {/* Image */}
            <div className="relative h-48 overflow-hidden bg-gradient-to-br from-blue-500 to-purple-600">
              {post.featured_image ? (
                <img
                  src={resolveImageUrl(post.featured_image)}
                  alt={post.title}
                  className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300"
                />
              ) : (
                <div className="w-full h-full bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500"></div>
              )}
              <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent"></div>

              {/* Category Badge */}
              {post.categories && post.categories[0] && (
                <div className="absolute top-3 left-3 sm:top-4 sm:left-4">
                  <span
                    className="inline-flex items-center gap-1 sm:gap-1.5 px-2.5 sm:px-3 py-1 rounded-full text-xs font-semibold backdrop-blur-sm"
                    style={{
                      backgroundColor: post.categories[0].color
                        ? `${post.categories[0].color}dd`
                        : '#6366f1dd',
                      color: 'white',
                    }}
                  >
                    {post.categories[0].icon && <span>{post.categories[0].icon}</span>}
                    {post.categories[0].name}
                  </span>
                </div>
              )}

              {/* View Count */}
              {post.view_count && post.view_count > 0 && (
                <div className="absolute bottom-3 right-3 sm:bottom-4 sm:right-4 flex items-center gap-1 sm:gap-1.5 px-2 sm:px-2.5 py-1 bg-black/50 backdrop-blur-sm rounded-full text-white text-xs font-medium">
                  <TrendingUp size={12} />
                  <span className="hidden xs:inline">{post.view_count.toLocaleString()} views</span>
                  <span className="xs:hidden">{post.view_count.toLocaleString()}</span>
                </div>
              )}
            </div>

            {/* Content */}
            <div className="p-4 sm:p-6">
              {/* Meta */}
              <div className="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400 mb-3">
                <div className="flex items-center gap-1">
                  <Calendar size={14} />
                  <span>{post.published_at ? formatDate(post.published_at) : 'Draft'}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Clock size={14} />
                  <span>5 min read</span>
                </div>
              </div>

              {/* Title */}
              <h3 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-2 sm:mb-3 line-clamp-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                {post.title}
              </h3>

              {/* Excerpt */}
              <p className="text-gray-600 dark:text-gray-300 text-sm mb-3 sm:mb-4 line-clamp-2 sm:line-clamp-3">
                {post.excerpt}
              </p>

              {/* Read More Link */}
              <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-semibold text-sm group-hover:gap-3 transition-all">
                <span>Read More</span>
                <ArrowRight size={14} className="sm:w-4 sm:h-4 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          </Link>
        </motion.article>
      ))}
    </motion.div>
  );
};

export default RecentPostsGrid;
