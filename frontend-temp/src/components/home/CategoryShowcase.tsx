// src/components/home/CategoryShowcase.tsx
/**
 * Category Showcase - Icon cards for top categories
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import { ArrowRight } from 'lucide-react';
import { useSiteSettings } from '../../hooks/useSiteSettings';

interface Category {
  id: number;
  name: string;
  slug: string;
  description?: string;
  color?: string;
  icon?: string;
  post_count?: number;
}

interface CategoryShowcaseProps {
  limit?: number;
}

export const CategoryShowcase: React.FC<CategoryShowcaseProps> = ({ limit }) => {
  const { settings } = useSiteSettings();
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadCategories();
  }, [limit, settings.categoriesLimit]);

  const loadCategories = async () => {
    try {
      const data = await blogApi.getCategories();
      // Get top N categories by post count
      const effectiveLimit = limit ?? settings.categoriesLimit ?? 6;
      const topCategories = data
        .sort((a, b) => (b.post_count || 0) - (a.post_count || 0))
        .slice(0, effectiveLimit);
      setCategories(topCategories);
    } catch (error) {
      console.error('Failed to load categories:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="bg-gray-200 dark:bg-gray-800 rounded-xl h-32 animate-pulse"></div>
        ))}
      </div>
    );
  }

  if (categories.length === 0) {
    return null;
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.08,
      },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, scale: 0.9 },
    visible: {
      opacity: 1,
      scale: 1,
      transition: {
        duration: 0.4,
      },
    },
  };

  return (
    <>
      <motion.div
        variants={containerVariants}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, margin: '-50px' }}
        className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4"
      >
        {categories.map((category) => (
          <motion.div key={category.id} variants={cardVariants}>
            <Link
              to={`/blog?category=${category.slug}`}
              className="group block p-4 sm:p-6 bg-white dark:bg-gray-800 rounded-xl shadow-md hover:shadow-xl transition-all hover:-translate-y-2 active:scale-95 transform touch-manipulation"
              style={{
                background: category.color
                  ? `linear-gradient(135deg, ${category.color}15, ${category.color}05)`
                  : undefined,
              }}
            >
              <div className="flex flex-col items-center text-center">
                {/* Icon */}
                <div
                  className="w-12 h-12 sm:w-16 sm:h-16 rounded-full flex items-center justify-center text-2xl sm:text-3xl mb-2 sm:mb-3 group-hover:scale-110 transition-transform"
                  style={{
                    backgroundColor: category.color ? `${category.color}20` : '#e0e7ff',
                  }}
                >
                  {category.icon || '📁'}
                </div>

                {/* Name */}
                <h3
                  className="font-semibold text-xs sm:text-sm mb-1 group-hover:scale-105 transition-transform"
                  style={{ color: category.color || '#4f46e5' }}
                >
                  {category.name}
                </h3>

                {/* Post Count */}
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {category.post_count || 0} {category.post_count === 1 ? 'post' : 'posts'}
                </p>
              </div>
            </Link>
          </motion.div>
        ))}
      </motion.div>

      {/* View All Categories Button - Mobile Optimized */}
      <div className="mt-6 sm:mt-8 text-center">
        <Link
          to="/blog"
          className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 text-white rounded-lg transition-all font-medium shadow-md hover:shadow-lg touch-manipulation active:scale-95"
        >
          View All Categories
          <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5" />
        </Link>
      </div>
    </>
  );
};

export default CategoryShowcase;
