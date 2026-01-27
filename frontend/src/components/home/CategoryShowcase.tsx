// src/components/home/CategoryShowcase.tsx
/**
 * Category Showcase - Clean category grid with sanitization and proper icons
 * Mobile: 2 columns | Desktop: 3-4 columns
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import {
  Code,
  Palette,
  Database,
  Server,
  Globe,
  Layers,
  BookOpen,
  Terminal,
  Cloud,
  Shield,
  Smartphone,
  Cpu,
  FileCode,
  Folder,
} from 'lucide-react';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

interface Category {
  id: number;
  name: string;
  slug: string;
  description?: string;
  color?: string;
  icon?: string;
  post_count?: number;
}

// Icon mapping based on category name/slug keywords
const getCategoryIcon = (name: string, slug: string) => {
  const text = `${name} ${slug}`.toLowerCase();

  if (text.includes('frontend') || text.includes('react') || text.includes('vue') || text.includes('css')) return Globe;
  if (text.includes('backend') || text.includes('api') || text.includes('server')) return Server;
  if (text.includes('database') || text.includes('sql') || text.includes('data')) return Database;
  if (text.includes('devops') || text.includes('cloud') || text.includes('aws') || text.includes('docker')) return Cloud;
  if (text.includes('security') || text.includes('auth')) return Shield;
  if (text.includes('mobile') || text.includes('ios') || text.includes('android') || text.includes('flutter')) return Smartphone;
  if (text.includes('ai') || text.includes('machine') || text.includes('ml')) return Cpu;
  if (text.includes('design') || text.includes('ui') || text.includes('ux')) return Palette;
  if (text.includes('terminal') || text.includes('cli') || text.includes('bash') || text.includes('linux')) return Terminal;
  if (text.includes('fullstack') || text.includes('full-stack')) return Layers;
  if (text.includes('code') || text.includes('programming') || text.includes('tutorial')) return FileCode;
  if (text.includes('javascript') || text.includes('typescript') || text.includes('python') || text.includes('java')) return Code;

  return BookOpen; // Default
};

// Sanitize category name - remove weird chars, enforce max length
const sanitizeName = (name: string): string => {
  if (!name) return 'Untitled';

  // Remove control characters and trim
  let clean = name.replace(/[\x00-\x1F\x7F]/g, '').trim();

  // Check for SQL injection patterns or weird strings
  if (clean.includes('--') || clean.includes(';') || clean.includes('DROP') || clean.includes('SELECT')) {
    return 'Category';
  }

  // Enforce max length
  if (clean.length > 28) {
    clean = clean.slice(0, 28) + '...';
  }

  return clean || 'Untitled';
};

// Default colors for categories
const defaultColors = [
  '#3B82F6', // blue
  '#8B5CF6', // violet
  '#10B981', // emerald
  '#F59E0B', // amber
  '#EC4899', // pink
  '#06B6D4', // cyan
  '#EF4444', // red
  '#6366F1', // indigo
];

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
      const effectiveLimit = limit ?? settings.categoriesLimit ?? 8;

      // Filter out categories with 0 posts, sort by post count, limit
      const validCategories = data
        .filter((cat) => (cat.post_count || 0) > 0)
        .sort((a, b) => (b.post_count || 0) - (a.post_count || 0))
        .slice(0, effectiveLimit);

      setCategories(validCategories);
    } catch (error) {
      console.error('Failed to load categories:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-slate-100 dark:bg-slate-800 rounded-2xl h-28 animate-pulse" />
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
      transition: { staggerChildren: 0.05 },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] as const },
    },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, amount: 0.2 }}
      className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 sm:gap-4"
    >
      {categories.map((category, idx) => {
        const Icon = getCategoryIcon(category.name, category.slug);
        const color = category.color || defaultColors[idx % defaultColors.length];
        const name = sanitizeName(category.name);

        return (
          <motion.div key={category.id} variants={cardVariants}>
            <Link
              to={`/blog?category=${category.slug}`}
              className="group block relative overflow-hidden rounded-2xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 transition-all"
            >
              <motion.div
                whileHover={{ y: -4 }}
                whileTap={{ scale: 0.98 }}
                className="p-4 sm:p-5"
              >
                {/* Icon */}
                <div
                  className="w-11 h-11 sm:w-12 sm:h-12 rounded-xl flex items-center justify-center mb-3 transition-transform group-hover:scale-110"
                  style={{ backgroundColor: `${color}15` }}
                >
                  <Icon className="w-5 h-5 sm:w-6 sm:h-6" style={{ color }} />
                </div>

                {/* Name */}
                <h3
                  className="font-semibold text-sm sm:text-base text-slate-900 dark:text-white mb-1 truncate"
                  title={category.name}
                >
                  {name}
                </h3>

                {/* Post Count */}
                <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400">
                  {category.post_count} {category.post_count === 1 ? 'article' : 'articles'}
                </p>

                {/* Hover accent */}
                <div
                  className="absolute bottom-0 left-0 right-0 h-1 transform scale-x-0 group-hover:scale-x-100 transition-transform origin-left"
                  style={{ backgroundColor: color }}
                />
              </motion.div>
            </Link>
          </motion.div>
        );
      })}
    </motion.div>
  );
};

export default CategoryShowcase;
