// src/components/home/BlogPreviewGrid.tsx
/**
 * Blog Preview Grid - Compact 3-post section for SEO + content discovery
 * Replaces the massive FeaturedCarousel + RecentPostsGrid combo
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Newspaper,
  ChevronRight,
  Clock,
  Loader2,
  ArrowRight,
} from 'lucide-react';
import { blogApi } from '../../services/api';
import Section from './Section';

interface BlogPost {
  id: number;
  title: string;
  slug: string;
  excerpt?: string;
  featured_image?: string | null;
  created_at: string;
  category?: {
    name: string;
    slug: string;
  };
}

const BlogPreviewGrid: React.FC = () => {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchPosts = async () => {
      try {
        // Use getRecent endpoint which returns BlogPost[] directly
        const posts = await blogApi.getRecent(3);
        setPosts(Array.isArray(posts) ? posts : []);
      } catch (error) {
        console.error('Failed to load blog posts:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchPosts();
  }, []);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };

  const truncateExcerpt = (text?: string, maxLength = 100) => {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength).trim() + '...';
  };

  return (
    <Section
      icon={Newspaper}
      eyebrow="From the Blog"
      title="Latest Articles"
      subtitle="Tips, tutorials, and tech news for beginners"
      action={
        <Link
          to="/blog"
          className="inline-flex items-center gap-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
        >
          View All Posts
          <ArrowRight className="w-4 h-4" />
        </Link>
      }
    >
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="w-8 h-8 animate-spin text-slate-400" />
        </div>
      ) : posts.length === 0 ? (
        <div className="text-center py-16 text-slate-500 dark:text-slate-400">
          No blog posts available yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {posts.map((post, index) => (
            <motion.article
              key={post.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="group"
            >
              <Link to={`/blog/${post.slug}`} className="block">
                {/* Image */}
                <div className="relative aspect-video rounded-xl overflow-hidden mb-4 bg-slate-100 dark:bg-slate-800">
                  {post.featured_image ? (
                    <img
                      src={post.featured_image}
                      alt={post.title}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/30 dark:to-indigo-900/30">
                      <Newspaper className="w-12 h-12 text-blue-300 dark:text-blue-600" />
                    </div>
                  )}

                  {/* Category badge */}
                  {post.category && (
                    <span className="absolute top-3 left-3 px-2 py-1 text-xs font-medium bg-white/90 dark:bg-slate-900/90 text-slate-700 dark:text-slate-300 rounded-md backdrop-blur-sm">
                      {post.category.name}
                    </span>
                  )}
                </div>

                {/* Content */}
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors line-clamp-2 mb-2">
                    {post.title}
                  </h3>

                  {post.excerpt && (
                    <p className="text-sm text-slate-600 dark:text-slate-400 line-clamp-2 mb-3">
                      {truncateExcerpt(post.excerpt)}
                    </p>
                  )}

                  <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-500">
                    <Clock className="w-3.5 h-3.5" />
                    <time dateTime={post.created_at}>{formatDate(post.created_at)}</time>
                  </div>
                </div>
              </Link>
            </motion.article>
          ))}
        </div>
      )}

      {/* Mobile: View All link */}
      <div className="mt-6 text-center md:hidden">
        <Link
          to="/blog"
          className="inline-flex items-center gap-2 px-4 py-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg font-medium text-sm hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
        >
          View All Posts
          <ChevronRight className="w-4 h-4" />
        </Link>
      </div>
    </Section>
  );
};

export default BlogPreviewGrid;
