// src/components/home/TutorialPathsShowcase.tsx
/**
 * Tutorial Paths Showcase - Homepage widget displaying tutorial learning paths
 * Shows categories as "paths" with featured tutorials in each
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  BookOpen,
  ChevronRight,
  Clock,
  Star,
  Sparkles,
  Loader2,
  Code,
  Palette,
  Database,
  Server,
  Globe,
  Layers,
} from 'lucide-react';
import {
  getTutorialCategories,
  getTutorials,
} from '../../plugins/tutorials/services/tutorialApi';
import type {
  TutorialCategory,
  TutorialListItem,
} from '../../plugins/tutorials/types';

// Icon mapping for categories
const categoryIcons: Record<string, React.ReactNode> = {
  code: <Code className="w-5 h-5" />,
  design: <Palette className="w-5 h-5" />,
  database: <Database className="w-5 h-5" />,
  backend: <Server className="w-5 h-5" />,
  frontend: <Globe className="w-5 h-5" />,
  fullstack: <Layers className="w-5 h-5" />,
  default: <BookOpen className="w-5 h-5" />,
};

// Default colors for categories without custom colors
const defaultColors = [
  'from-blue-500 to-indigo-600',
  'from-purple-500 to-pink-600',
  'from-green-500 to-teal-600',
  'from-orange-500 to-red-600',
  'from-cyan-500 to-blue-600',
  'from-rose-500 to-orange-600',
];

interface CategoryWithTutorials extends TutorialCategory {
  tutorials: TutorialListItem[];
}

const TutorialPathsShowcase: React.FC = () => {
  const [categories, setCategories] = useState<CategoryWithTutorials[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch categories
        const cats = await getTutorialCategories();

        // Defensive: ensure cats is an array
        if (!Array.isArray(cats) || cats.length === 0) {
          setCategories([]);
          setLoading(false);
          return;
        }

        // Fetch tutorials for each category (limit 3 per category)
        const categoriesWithTutorials = await Promise.all(
          cats.slice(0, 4).map(async (cat) => {
            try {
              const tutorials = await getTutorials({
                category_id: cat.id,
                is_featured: true,
                limit: 3,
              });
              return {
                ...cat,
                tutorials: Array.isArray(tutorials) ? tutorials : [],
              };
            } catch {
              return { ...cat, tutorials: [] };
            }
          })
        );

        // Filter out categories with no tutorials
        const nonEmptyCategories = categoriesWithTutorials.filter(
          (cat) => cat.tutorials && cat.tutorials.length > 0
        );

        setCategories(nonEmptyCategories);
      } catch (error) {
        console.error('Failed to load tutorial paths:', error);
        setCategories([]); // Ensure empty array on error
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
        </div>
      </section>
    );
  }

  if (categories.length === 0) {
    return null; // Hide if no categories with tutorials
  }

  const getCategoryIcon = (iconName: string | null) => {
    if (iconName && categoryIcons[iconName.toLowerCase()]) {
      return categoryIcons[iconName.toLowerCase()];
    }
    return categoryIcons.default;
  };

  const getCategoryColor = (color: string | null, index: number) => {
    if (color) {
      return `from-${color}-500 to-${color}-600`;
    }
    return defaultColors[index % defaultColors.length];
  };

  const difficultyColors: Record<string, string> = {
    beginner: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    intermediate: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
    advanced: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  };

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <BookOpen className="w-7 h-7 text-indigo-600 dark:text-indigo-400" />
            <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
              Learning Paths
            </h2>
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Follow structured paths to master new skills
          </p>
        </div>

        <Link
          to="/tutorials"
          className="hidden sm:flex items-center gap-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 font-medium"
        >
          Browse all tutorials
          <ChevronRight className="w-5 h-5" />
        </Link>
      </div>

      {/* Category Cards */}
      <div className="grid md:grid-cols-2 gap-6">
        {categories.map((category, idx) => (
          <motion.div
            key={category.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: idx * 0.1 }}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden border border-gray-100 dark:border-gray-700"
          >
            {/* Category Header */}
            <div
              className={`bg-gradient-to-r ${getCategoryColor(category.color, idx)} px-6 py-4`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-white/20 backdrop-blur-sm rounded-lg text-white">
                    {getCategoryIcon(category.icon)}
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">{category.name}</h3>
                    <p className="text-sm text-white/80">
                      {category.tutorials.length} tutorial
                      {category.tutorials.length !== 1 ? 's' : ''} available
                    </p>
                  </div>
                </div>
                <Link
                  to={`/tutorials?category=${category.id}`}
                  className="px-3 py-1.5 bg-white/20 backdrop-blur-sm text-white text-sm font-medium rounded-lg hover:bg-white/30 transition-colors flex items-center gap-1"
                >
                  View Path
                  <ChevronRight className="w-4 h-4" />
                </Link>
              </div>
            </div>

            {/* Tutorials List */}
            <div className="p-4">
              <div className="space-y-3">
                {category.tutorials.map((tutorial, tIdx) => (
                  <Link
                    key={tutorial.id}
                    to={`/tutorials/${tutorial.slug}`}
                    className="flex items-center justify-between p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors group"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center text-xs font-medium text-gray-600 dark:text-gray-400">
                        {tIdx + 1}
                      </span>
                      <div className="min-w-0">
                        <p className="font-medium text-gray-900 dark:text-white truncate group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                          {tutorial.title}
                        </p>
                        <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                          {tutorial.estimated_time_minutes && (
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {tutorial.estimated_time_minutes}m
                            </span>
                          )}
                          <span
                            className={`px-1.5 py-0.5 rounded ${
                              difficultyColors[tutorial.difficulty] || difficultyColors.beginner
                            }`}
                          >
                            {tutorial.difficulty}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="flex items-center gap-1 text-sm text-yellow-600 dark:text-yellow-400">
                        <Sparkles className="w-4 h-4" />
                        {tutorial.xp_reward}
                      </span>
                      <ChevronRight className="w-4 h-4 text-gray-400 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors" />
                    </div>
                  </Link>
                ))}
              </div>

              {/* View all link */}
              {category.tutorials.length >= 3 && (
                <div className="mt-4 pt-3 border-t border-gray-100 dark:border-gray-700">
                  <Link
                    to={`/tutorials?category=${category.id}`}
                    className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 font-medium flex items-center gap-1"
                  >
                    See all {category.name} tutorials
                    <ChevronRight className="w-4 h-4" />
                  </Link>
                </div>
              )}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Mobile link */}
      <div className="mt-8 sm:hidden text-center">
        <Link
          to="/tutorials"
          className="inline-flex items-center gap-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 font-medium"
        >
          Browse all tutorials
          <ChevronRight className="w-5 h-5" />
        </Link>
      </div>
    </section>
  );
};

export default TutorialPathsShowcase;
