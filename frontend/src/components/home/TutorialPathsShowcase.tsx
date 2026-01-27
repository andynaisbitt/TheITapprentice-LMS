// src/components/home/TutorialPathsShowcase.tsx
/**
 * Tutorial Paths Showcase - Modern horizontal scroll on mobile, grid on desktop
 * Redesigned cards with better hierarchy and micro-interactions
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import {
  BookOpen,
  ChevronRight,
  Clock,
  Sparkles,
  Loader2,
  Code,
  Palette,
  Database,
  Server,
  Globe,
  Layers,
  GraduationCap,
  Zap,
} from 'lucide-react';
import {
  getTutorialCategories,
  getTutorials,
} from '../../plugins/tutorials/services/tutorialApi';
import type {
  TutorialCategory,
  TutorialListItem,
} from '../../plugins/tutorials/types';
import Section from './Section';

// Icon mapping for categories
const categoryIcons: Record<string, typeof Code> = {
  code: Code,
  design: Palette,
  database: Database,
  backend: Server,
  frontend: Globe,
  fullstack: Layers,
  default: BookOpen,
};

// Gradient colors for cards
const cardGradients = [
  'from-blue-500 to-indigo-600',
  'from-purple-500 to-pink-600',
  'from-emerald-500 to-teal-600',
  'from-orange-500 to-amber-600',
  'from-cyan-500 to-blue-600',
  'from-rose-500 to-pink-600',
];

interface CategoryWithTutorials extends TutorialCategory {
  tutorials: TutorialListItem[];
}

const TutorialPathsShowcase: React.FC = () => {
  const navigate = useNavigate();
  const [categories, setCategories] = useState<CategoryWithTutorials[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const cats = await getTutorialCategories();

        if (!Array.isArray(cats) || cats.length === 0) {
          setCategories([]);
          setLoading(false);
          return;
        }

        const categoriesWithTutorials = await Promise.all(
          cats.slice(0, 6).map(async (cat) => {
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

        const nonEmptyCategories = categoriesWithTutorials.filter(
          (cat) => cat.tutorials && cat.tutorials.length > 0
        );

        setCategories(nonEmptyCategories);
      } catch (error) {
        console.error('Failed to load tutorial paths:', error);
        setCategories([]);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <Section>
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-8 h-8 animate-spin text-slate-400" />
        </div>
      </Section>
    );
  }

  if (categories.length === 0) {
    return null;
  }

  const getIcon = (iconName: string | null) => {
    if (iconName && categoryIcons[iconName.toLowerCase()]) {
      return categoryIcons[iconName.toLowerCase()];
    }
    return categoryIcons.default;
  };

  const getGradient = (index: number) => cardGradients[index % cardGradients.length];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner':
        return 'text-emerald-600 dark:text-emerald-400';
      case 'intermediate':
        return 'text-amber-600 dark:text-amber-400';
      case 'advanced':
        return 'text-rose-600 dark:text-rose-400';
      default:
        return 'text-slate-600 dark:text-slate-400';
    }
  };

  return (
    <Section
      icon={GraduationCap}
      eyebrow="Learning Paths"
      title="Master New Skills"
      subtitle="Follow structured paths designed to take you from beginner to expert"
      viewAllLink="/tutorials"
      viewAllText="Browse all tutorials"
    >
      {/* Mobile: Horizontal Scroll | Desktop: Grid */}
      <div className="relative">
        {/* Mobile Scroll Container */}
        <div className="flex gap-4 overflow-x-auto snap-x snap-mandatory pb-4 -mx-4 px-4 lg:hidden scrollbar-hide">
          {categories.map((category, idx) => {
            const Icon = getIcon(category.icon);
            const nextTutorial = category.tutorials[0];

            return (
              <motion.div
                key={category.id}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.4, delay: idx * 0.05 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => navigate(`/tutorials?category=${category.id}`)}
                className="flex-shrink-0 w-[300px] snap-start cursor-pointer"
              >
                <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm hover:shadow-lg transition-shadow h-full">
                  {/* Card Header */}
                  <div className={`bg-gradient-to-r ${getGradient(idx)} p-4`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-white/20 backdrop-blur-sm rounded-xl flex items-center justify-center">
                          <Icon className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <h3 className="font-bold text-white text-base">{category.name}</h3>
                          <p className="text-white/80 text-xs">
                            {category.tutorials.length} tutorials
                          </p>
                        </div>
                      </div>
                      <span className="px-2.5 py-1 bg-white/20 backdrop-blur-sm rounded-lg text-white text-xs font-medium">
                        View path
                      </span>
                    </div>
                  </div>

                  {/* Card Body */}
                  <div className="p-4 space-y-3">
                    {/* Meta Row */}
                    <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
                      <span className="flex items-center gap-1">
                        <BookOpen className="w-3.5 h-3.5" />
                        {category.tutorials.length} lessons
                      </span>
                      <span className={getDifficultyColor(category.tutorials[0]?.difficulty || 'beginner')}>
                        {category.tutorials[0]?.difficulty || 'Beginner'}
                      </span>
                    </div>

                    {/* Next Lesson Preview */}
                    {nextTutorial && (
                      <div className="bg-slate-50 dark:bg-slate-900/50 rounded-xl p-3">
                        <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Next lesson</p>
                        <p className="font-medium text-slate-900 dark:text-white text-sm line-clamp-1">
                          {nextTutorial.title}
                        </p>
                        <div className="flex items-center justify-between mt-2">
                          <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
                            {nextTutorial.estimated_time_minutes && (
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {nextTutorial.estimated_time_minutes}m
                              </span>
                            )}
                            <span className="flex items-center gap-1 text-amber-600 dark:text-amber-400">
                              <Sparkles className="w-3 h-3" />
                              {nextTutorial.xp_reward} XP
                            </span>
                          </div>
                          <ChevronRight className="w-4 h-4 text-slate-400" />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Desktop Grid */}
        <div className="hidden lg:grid grid-cols-2 xl:grid-cols-3 gap-6">
          {categories.map((category, idx) => {
            const Icon = getIcon(category.icon);
            const nextTutorial = category.tutorials[0];

            return (
              <motion.div
                key={category.id}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: idx * 0.1 }}
                whileHover={{ y: -4 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => navigate(`/tutorials?category=${category.id}`)}
                className="cursor-pointer"
              >
                <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm hover:shadow-xl hover:border-slate-300 dark:hover:border-slate-600 transition-all h-full">
                  {/* Card Header */}
                  <div className={`bg-gradient-to-r ${getGradient(idx)} p-5`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 bg-white/20 backdrop-blur-sm rounded-xl flex items-center justify-center">
                          <Icon className="w-6 h-6 text-white" />
                        </div>
                        <div>
                          <h3 className="font-bold text-white text-lg">{category.name}</h3>
                          <p className="text-white/80 text-sm">
                            {category.tutorials.length} tutorials available
                          </p>
                        </div>
                      </div>
                      <span className="px-3 py-1.5 bg-white/20 backdrop-blur-sm rounded-lg text-white text-sm font-medium flex items-center gap-1 hover:bg-white/30 transition-colors">
                        View path
                        <ChevronRight className="w-4 h-4" />
                      </span>
                    </div>
                  </div>

                  {/* Card Body */}
                  <div className="p-5 space-y-4">
                    {/* Meta Row */}
                    <div className="flex items-center gap-4 text-sm text-slate-500 dark:text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <BookOpen className="w-4 h-4" />
                        {category.tutorials.length} lessons
                      </span>
                      <span className={`font-medium ${getDifficultyColor(category.tutorials[0]?.difficulty || 'beginner')}`}>
                        {category.tutorials[0]?.difficulty || 'Beginner'}
                      </span>
                    </div>

                    {/* Next Lesson Preview */}
                    {nextTutorial && (
                      <div className="bg-slate-50 dark:bg-slate-900/50 rounded-xl p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Zap className="w-4 h-4 text-blue-500" />
                          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                            Start here
                          </p>
                        </div>
                        <p className="font-semibold text-slate-900 dark:text-white line-clamp-1">
                          {nextTutorial.title}
                        </p>
                        <div className="flex items-center justify-between mt-3">
                          <div className="flex items-center gap-4 text-sm text-slate-500 dark:text-slate-400">
                            {nextTutorial.estimated_time_minutes && (
                              <span className="flex items-center gap-1">
                                <Clock className="w-4 h-4" />
                                {nextTutorial.estimated_time_minutes} min
                              </span>
                            )}
                            <span className="flex items-center gap-1 text-amber-600 dark:text-amber-400 font-medium">
                              <Sparkles className="w-4 h-4" />
                              +{nextTutorial.xp_reward} XP
                            </span>
                          </div>
                          <ChevronRight className="w-5 h-5 text-slate-400" />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </Section>
  );
};

export default TutorialPathsShowcase;
