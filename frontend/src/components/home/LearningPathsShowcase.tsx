// src/components/home/LearningPathsShowcase.tsx
/**
 * Learning Paths Showcase - Unified view of Tutorials, Courses, and Quizzes
 * Features tabbed navigation and consistent card design
 */

import { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  BookOpen,
  ChevronRight,
  Clock,
  Sparkles,
  Loader2,
  GraduationCap,
  HelpCircle,
  Layers,
  Star,
} from 'lucide-react';
import { getTutorials } from '../../plugins/tutorials/services/tutorialApi';
import { coursesApi } from '../../plugins/courses/services/coursesApi';
import { apiClient } from '../../services/api/client';
import type { TutorialListItem } from '../../plugins/tutorials/types';
import type { Course } from '../../plugins/courses/types';
import Section from './Section';

// Types
interface QuizSummary {
  id: string;
  title: string;
  description?: string;
  category?: string;
  difficulty: string;
  question_count: number;
  time_limit_minutes?: number;
  xp_reward: number;
  is_featured?: boolean;
}

interface UnifiedContentItem {
  id: string;
  type: 'tutorial' | 'course' | 'quiz';
  title: string;
  description?: string;
  category?: string;
  difficulty: string;
  timeMinutes?: number;
  xpReward: number;
  isFeatured?: boolean;
  itemCount?: number; // lessons for tutorials, modules for courses, questions for quizzes
  link: string;
}

// Type colors and icons
const typeConfig = {
  tutorial: {
    color: 'purple',
    bgClass: 'bg-purple-500',
    textClass: 'text-purple-600 dark:text-purple-400',
    borderClass: 'border-purple-200 dark:border-purple-800',
    icon: BookOpen,
    label: 'Tutorial',
    gradient: 'from-purple-500 to-violet-600',
  },
  course: {
    color: 'blue',
    bgClass: 'bg-blue-500',
    textClass: 'text-blue-600 dark:text-blue-400',
    borderClass: 'border-blue-200 dark:border-blue-800',
    icon: GraduationCap,
    label: 'Course',
    gradient: 'from-blue-500 to-indigo-600',
  },
  quiz: {
    color: 'amber',
    bgClass: 'bg-amber-500',
    textClass: 'text-amber-600 dark:text-amber-400',
    borderClass: 'border-amber-200 dark:border-amber-800',
    icon: HelpCircle,
    label: 'Quiz',
    gradient: 'from-amber-500 to-orange-600',
  },
};

const tabs = [
  { id: 'all', label: 'All' },
  { id: 'course', label: 'Courses' },
  { id: 'tutorial', label: 'Tutorials' },
  { id: 'quiz', label: 'Quizzes' },
];

const LearningPathsShowcase: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'all' | 'tutorial' | 'course' | 'quiz'>('all');
  const [tutorials, setTutorials] = useState<TutorialListItem[]>([]);
  const [courses, setCourses] = useState<Course[]>([]);
  const [quizzes, setQuizzes] = useState<QuizSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [tutorialsRes, coursesRes, quizzesRes] = await Promise.all([
          getTutorials({ limit: 6 }).catch(() => []),
          coursesApi.getCourses({ status: 'published', page_size: 6 }).catch(() => ({ courses: [] })),
          apiClient.get('/api/v1/quizzes/featured?limit=6').catch(() => ({ data: [] })),
        ]);

        setTutorials(Array.isArray(tutorialsRes) ? tutorialsRes : []);
        setCourses(coursesRes?.courses || []);
        setQuizzes(Array.isArray(quizzesRes?.data) ? quizzesRes.data : []);
      } catch (error) {
        console.error('Failed to load content:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  // Normalize all content to a unified format
  const allContent = useMemo((): UnifiedContentItem[] => {
    const items: UnifiedContentItem[] = [];

    tutorials.forEach((t) => {
      items.push({
        id: t.id.toString(),
        type: 'tutorial',
        title: t.title,
        description: t.description ?? undefined,
        category: t.category?.name ?? undefined,
        difficulty: t.difficulty || 'beginner',
        timeMinutes: t.estimated_time_minutes ?? undefined,
        xpReward: t.xp_reward || 50,
        isFeatured: t.is_featured,
        link: `/tutorials/${t.slug || t.id}`,
      });
    });

    courses.forEach((c) => {
      items.push({
        id: c.id,
        type: 'course',
        title: c.title,
        description: c.short_description || c.description,
        category: c.category,
        difficulty: c.level || 'beginner',
        timeMinutes: (c.estimated_hours || 0) * 60,
        xpReward: c.xp_reward || 100,
        isFeatured: c.is_featured,
        itemCount: c.modules?.length,
        link: `/courses/${c.id}`,
      });
    });

    quizzes.forEach((q) => {
      items.push({
        id: q.id,
        type: 'quiz',
        title: q.title,
        description: q.description,
        category: q.category,
        difficulty: q.difficulty || 'easy',
        timeMinutes: q.time_limit_minutes,
        xpReward: q.xp_reward || 25,
        isFeatured: q.is_featured,
        itemCount: q.question_count,
        link: `/quizzes/${q.id}`,
      });
    });

    // Sort by featured first, then by type variety
    return items.sort((a, b) => {
      if (a.isFeatured && !b.isFeatured) return -1;
      if (!a.isFeatured && b.isFeatured) return 1;
      return 0;
    });
  }, [tutorials, courses, quizzes]);

  // Filter based on active tab
  const filteredContent = useMemo(() => {
    if (activeTab === 'all') return allContent.slice(0, 9);
    return allContent.filter((item) => item.type === activeTab).slice(0, 6);
  }, [allContent, activeTab]);

  // Get counts for tab badges
  const counts = useMemo(() => ({
    all: allContent.length,
    tutorial: tutorials.length,
    course: courses.length,
    quiz: quizzes.length,
  }), [allContent.length, tutorials.length, courses.length, quizzes.length]);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty.toLowerCase()) {
      case 'beginner':
      case 'easy':
        return 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/30';
      case 'intermediate':
      case 'medium':
        return 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/30';
      case 'advanced':
      case 'hard':
        return 'text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-900/30';
      default:
        return 'text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/30';
    }
  };

  const formatTime = (minutes?: number) => {
    if (!minutes) return null;
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  };

  const getItemCountLabel = (type: string, count?: number) => {
    if (!count) return null;
    switch (type) {
      case 'tutorial':
        return `${count} steps`;
      case 'course':
        return `${count} modules`;
      case 'quiz':
        return `${count} questions`;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <Section>
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-8 h-8 animate-spin text-slate-400" />
        </div>
      </Section>
    );
  }

  if (allContent.length === 0) {
    return null;
  }

  return (
    <Section
      icon={Layers}
      eyebrow="Learning Paths"
      title="Start Your IT Journey"
      subtitle="Choose from courses, tutorials, and quizzes designed for IT beginners"
    >
      {/* Tab Navigation */}
      <div className="flex flex-wrap gap-2 mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`px-4 py-2 rounded-full text-sm font-medium transition-all ${
              activeTab === tab.id
                ? 'bg-blue-600 text-white shadow-md'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
            }`}
          >
            {tab.label}
            <span
              className={`ml-1.5 px-1.5 py-0.5 rounded-full text-xs ${
                activeTab === tab.id
                  ? 'bg-white/20 text-white'
                  : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400'
              }`}
            >
              {counts[tab.id as keyof typeof counts]}
            </span>
          </button>
        ))}
      </div>

      {/* Content Grid */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.2 }}
        >
          {/* Mobile: Horizontal Scroll */}
          <div className="flex gap-4 overflow-x-auto snap-x snap-mandatory pb-4 -mx-4 px-4 lg:hidden scrollbar-hide">
            {filteredContent.map((item, idx) => {
              const config = typeConfig[item.type];
              const Icon = config.icon;

              return (
                <motion.div
                  key={`${item.type}-${item.id}`}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3, delay: idx * 0.05 }}
                  onClick={() => navigate(item.link)}
                  className="flex-shrink-0 w-[280px] snap-start cursor-pointer"
                >
                  <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm hover:shadow-lg transition-all h-full">
                    {/* Card Header */}
                    <div className={`bg-gradient-to-r ${config.gradient} p-3`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 bg-white/20 backdrop-blur-sm rounded-lg flex items-center justify-center">
                            <Icon className="w-4 h-4 text-white" />
                          </div>
                          <span className="text-white/90 text-xs font-medium uppercase tracking-wide">
                            {config.label}
                          </span>
                        </div>
                        {item.isFeatured && (
                          <Star className="w-4 h-4 text-yellow-300 fill-yellow-300" />
                        )}
                      </div>
                    </div>

                    {/* Card Body */}
                    <div className="p-4 space-y-3">
                      {item.category && (
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {item.category}
                        </span>
                      )}
                      <h3 className="font-semibold text-slate-900 dark:text-white line-clamp-2">
                        {item.title}
                      </h3>

                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className={`px-2 py-0.5 rounded-full ${getDifficultyColor(item.difficulty)}`}>
                          {item.difficulty}
                        </span>
                        {item.timeMinutes && (
                          <span className="flex items-center gap-1 text-slate-500 dark:text-slate-400">
                            <Clock className="w-3 h-3" />
                            {formatTime(item.timeMinutes)}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-slate-100 dark:border-slate-700">
                        <span className="flex items-center gap-1 text-amber-600 dark:text-amber-400 font-medium text-sm">
                          <Sparkles className="w-3.5 h-3.5" />
                          +{item.xpReward} XP
                        </span>
                        <ChevronRight className="w-4 h-4 text-slate-400" />
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>

          {/* Desktop: Grid */}
          <div className="hidden lg:grid grid-cols-3 gap-5">
            {filteredContent.map((item, idx) => {
              const config = typeConfig[item.type];
              const Icon = config.icon;

              return (
                <motion.div
                  key={`${item.type}-${item.id}`}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.4, delay: idx * 0.05 }}
                  whileHover={{ y: -4 }}
                  onClick={() => navigate(item.link)}
                  className="cursor-pointer"
                >
                  <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm hover:shadow-xl hover:border-slate-300 dark:hover:border-slate-600 transition-all h-full">
                    {/* Card Header */}
                    <div className={`bg-gradient-to-r ${config.gradient} p-4`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-white/20 backdrop-blur-sm rounded-xl flex items-center justify-center">
                            <Icon className="w-5 h-5 text-white" />
                          </div>
                          <div>
                            <span className="text-white/90 text-xs font-medium uppercase tracking-wide">
                              {config.label}
                            </span>
                            {item.category && (
                              <p className="text-white/70 text-xs">
                                {item.category}
                              </p>
                            )}
                          </div>
                        </div>
                        {item.isFeatured && (
                          <div className="flex items-center gap-1 px-2 py-1 bg-white/20 rounded-lg">
                            <Star className="w-3.5 h-3.5 text-yellow-300 fill-yellow-300" />
                            <span className="text-white text-xs">Featured</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Card Body */}
                    <div className="p-5 space-y-4">
                      <h3 className="font-bold text-lg text-slate-900 dark:text-white line-clamp-2">
                        {item.title}
                      </h3>

                      {item.description && (
                        <p className="text-sm text-slate-500 dark:text-slate-400 line-clamp-2">
                          {item.description}
                        </p>
                      )}

                      <div className="flex flex-wrap items-center gap-3 text-sm">
                        <span className={`px-2.5 py-1 rounded-full font-medium ${getDifficultyColor(item.difficulty)}`}>
                          {item.difficulty}
                        </span>
                        {item.timeMinutes && (
                          <span className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                            <Clock className="w-4 h-4" />
                            {formatTime(item.timeMinutes)}
                          </span>
                        )}
                        {getItemCountLabel(item.type, item.itemCount) && (
                          <span className="text-slate-500 dark:text-slate-400">
                            {getItemCountLabel(item.type, item.itemCount)}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center justify-between pt-3 border-t border-slate-100 dark:border-slate-700">
                        <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400 font-semibold">
                          <Sparkles className="w-4 h-4" />
                          +{item.xpReward} XP
                        </span>
                        <span className="flex items-center gap-1 text-blue-600 dark:text-blue-400 text-sm font-medium group">
                          Start learning
                          <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>
      </AnimatePresence>

      {/* View All Link */}
      <div className="mt-8 text-center">
        <button
          onClick={() => {
            if (activeTab === 'tutorial') navigate('/tutorials');
            else if (activeTab === 'course') navigate('/courses');
            else if (activeTab === 'quiz') navigate('/quizzes');
            else navigate('/tutorials');
          }}
          className="inline-flex items-center gap-2 px-6 py-3 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors font-medium"
        >
          Browse all {activeTab === 'all' ? 'content' : `${activeTab}s`}
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </Section>
  );
};

export default LearningPathsShowcase;
