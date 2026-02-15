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
  const [error, setError] = useState(false);

  const effectiveLimit = limit ?? settings.categoriesLimit ?? 8;

  // Load categories on mount
  useEffect(() => {
    const fetchCategories = async () => {
      setLoading(true);
      setError(false);
      try {
        const data = await blogApi.getCategories();

        // Filter out categories with less than 3 posts (1-2 articles looks weak)
        const safeData = Array.isArray(data) ? data : [];
        const validCategories = safeData
          .filter((cat) => (cat.post_count || 0) >= 3)
          .sort((a, b) => (b.post_count || 0) - (a.post_count || 0))
          .slice(0, effectiveLimit);

        setCategories(validCategories);
      } catch (err) {
        console.error('Failed to load categories:', err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };
    fetchCategories();
  }, [effectiveLimit]);

  if (loading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-slate-100 dark:bg-slate-800 rounded-2xl h-28 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return null; // Silently fail for categories - not critical
  }

  if (categories.length === 0) {
    return null;
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.06, delayChildren: 0.1 },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 24, scale: 0.95 },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: { duration: 0.5, ease: [0.25, 0.1, 0.25, 1] as const },
    },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, amount: 0.15 }}
      className="
        flex gap-3 overflow-x-auto pb-4 snap-x snap-mandatory scrollbar-hide
        sm:grid sm:grid-cols-3 sm:overflow-visible sm:pb-0 sm:snap-none
        lg:grid-cols-4 sm:gap-4
      "
    >
      {categories.map((category, idx) => {
        const Icon = getCategoryIcon(category.name, category.slug);
        const color = category.color || defaultColors[idx % defaultColors.length];
        const name = sanitizeName(category.name);

        return (
          <motion.div
            key={category.id}
            variants={cardVariants}
            whileHover={{
              y: -8,
              scale: 1.02,
              transition: { duration: 0.2 }
            }}
            whileTap={{ scale: 0.97 }}
            className="flex-shrink-0 w-[160px] snap-start sm:w-auto sm:flex-shrink"
          >
            <Link
              to={`/blog?category=${category.slug}`}
              className="group block relative overflow-hidden rounded-2xl bg-white dark:bg-slate-800 border-2 border-slate-200 dark:border-slate-700 hover:border-transparent transition-all duration-300 shadow-sm hover:shadow-xl"
              style={{
                // Add colored border on hover
                boxShadow: 'none',
              }}
            >
              {/* Animated gradient background on hover */}
              <div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                style={{
                  background: `linear-gradient(135deg, ${color}08 0%, ${color}15 100%)`,
                }}
              />

              {/* Floating particles effect */}
              <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div
                  className="absolute w-20 h-20 rounded-full blur-2xl opacity-0 group-hover:opacity-30 transition-all duration-500 -top-10 -right-10 group-hover:top-0 group-hover:right-0"
                  style={{ backgroundColor: color }}
                />
              </div>

              <div className="relative p-4 sm:p-5">
                {/* Icon with animated ring */}
                <div className="relative mb-3">
                  <div
                    className="w-12 h-12 sm:w-14 sm:h-14 rounded-xl flex items-center justify-center transition-all duration-300 group-hover:scale-110 group-hover:rotate-3"
                    style={{ backgroundColor: `${color}15` }}
                  >
                    <Icon
                      className="w-6 h-6 sm:w-7 sm:h-7 transition-transform duration-300 group-hover:scale-110"
                      style={{ color }}
                    />
                  </div>
                  {/* Pulse ring on hover */}
                  <div
                    className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 animate-ping pointer-events-none"
                    style={{ backgroundColor: `${color}20`, animationDuration: '1.5s' }}
                  />
                </div>

                {/* Name with color change on hover */}
                <h3
                  className="font-bold text-sm sm:text-base text-slate-900 dark:text-white mb-1.5 truncate transition-colors duration-300"
                  style={{ color: undefined }}
                  title={category.name}
                >
                  <span className="group-hover:hidden">{name}</span>
                  <span className="hidden group-hover:inline" style={{ color }}>{name}</span>
                </h3>

                {/* Post Count with badge style */}
                <div className="flex items-center gap-1.5">
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium transition-colors duration-300"
                    style={{
                      backgroundColor: `${color}15`,
                      color: color,
                    }}
                  >
                    {category.post_count} {category.post_count === 1 ? 'article' : 'articles'}
                  </span>
                </div>

                {/* Animated arrow indicator */}
                <div
                  className="absolute bottom-4 right-4 w-8 h-8 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transform translate-x-2 group-hover:translate-x-0 transition-all duration-300"
                  style={{ backgroundColor: `${color}15` }}
                >
                  <svg
                    className="w-4 h-4 transition-transform duration-300 group-hover:translate-x-0.5"
                    style={{ color }}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>

                {/* Bottom accent bar */}
                <div
                  className="absolute bottom-0 left-0 right-0 h-1 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-300 origin-left"
                  style={{ backgroundColor: color }}
                />
              </div>
            </Link>
          </motion.div>
        );
      })}
    </motion.div>
  );
};

export default CategoryShowcase;
