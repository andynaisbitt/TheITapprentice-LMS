// src/components/home/ThePulse.tsx
/**
 * The Pulse - Animated trending content section
 * Features: animated counters, auto-rotating tabs, staggered cards,
 * leaderboard with animated badges, breathing background
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence, useInView } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import {
  TrendingUp,
  GraduationCap,
  BookOpen,
  Brain,
  Trophy,
  ChevronRight,
  Zap,
  ArrowRight,
  Loader2,
  Users,
  Target,
} from 'lucide-react';
import { coursesApi } from '../../plugins/courses/services/coursesApi';
import { getTutorials } from '../../plugins/tutorials/services/tutorialApi';
import { progressApi } from '../../plugins/shared/services/progressApi';
import { apiClient } from '../../services/api/client';
import { typingGameApi } from '../../plugins/typing-game/services/typingGameApi';

interface ContentItem {
  id: string;
  title: string;
  type: 'course' | 'tutorial' | 'quiz';
  category?: string;
  xp?: number;
  link: string;
}

interface LeaderEntry {
  rank: number;
  username: string;
  xp: number;
}

interface FastestTyper {
  username: string;
  wpm: number;
}

interface PlatformStats {
  totalCourses: number;
  totalTutorials: number;
  totalQuizzes: number;
  totalLearners: number;
}

const tabs = [
  { id: 'trending', label: 'Trending', icon: TrendingUp },
  { id: 'courses', label: 'Courses', icon: GraduationCap },
  { id: 'tutorials', label: 'Tutorials', icon: BookOpen },
  { id: 'quizzes', label: 'Quizzes', icon: Brain },
];

// Animated counter hook
const useAnimatedCounter = (end: number, duration = 2000, shouldAnimate: boolean) => {
  const [count, setCount] = useState(0);
  const hasAnimated = useRef(false);

  useEffect(() => {
    if (!shouldAnimate || hasAnimated.current || end === 0) return;
    hasAnimated.current = true;

    let startTime: number;
    const step = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.floor(eased * end));
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        setCount(end);
      }
    };
    requestAnimationFrame(step);
  }, [end, duration, shouldAnimate]);

  return count;
};

const ThePulse: React.FC = () => {
  const navigate = useNavigate();
  const sectionRef = useRef<HTMLElement>(null);
  const isInView = useInView(sectionRef, { once: true, margin: '-100px' });

  const [activeTab, setActiveTab] = useState('trending');
  const [content, setContent] = useState<ContentItem[]>([]);
  const [leaderboard, setLeaderboard] = useState<LeaderEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<PlatformStats>({
    totalCourses: 0,
    totalTutorials: 0,
    totalQuizzes: 0,
    totalLearners: 0,
  });
  const [fastestTyper, setFastestTyper] = useState<FastestTyper | null>(null);
  const [isAutoRotating, setIsAutoRotating] = useState(true);
  const autoRotateTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Animated counters
  const animCourses = useAnimatedCounter(stats.totalCourses, 1800, isInView);
  const animTutorials = useAnimatedCounter(stats.totalTutorials, 2000, isInView);
  const animQuizzes = useAnimatedCounter(stats.totalQuizzes, 1600, isInView);
  const animLearners = useAnimatedCounter(stats.totalLearners, 2200, isInView);

  // Auto-rotate tabs every 5s
  useEffect(() => {
    if (!isAutoRotating) return;

    autoRotateTimer.current = setInterval(() => {
      setActiveTab(prev => {
        const currentIndex = tabs.findIndex(t => t.id === prev);
        return tabs[(currentIndex + 1) % tabs.length].id;
      });
    }, 5000);

    return () => {
      if (autoRotateTimer.current) clearInterval(autoRotateTimer.current);
    };
  }, [isAutoRotating]);

  const handleManualTabChange = useCallback((tabId: string) => {
    setActiveTab(tabId);
    setIsAutoRotating(false);
    // Resume auto-rotation after 15 seconds of inactivity
    if (autoRotateTimer.current) clearInterval(autoRotateTimer.current);
    const resumeTimer = setTimeout(() => setIsAutoRotating(true), 15000);
    return () => clearTimeout(resumeTimer);
  }, []);

  // Fetch stats once
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [coursesRes, tutorialsRes, quizzesRes, homepageStatsRes, typingLeaderboardRes] = await Promise.allSettled([
          coursesApi.getCourses({ status: 'published', page_size: 1 }),
          getTutorials({ limit: 1 }),
          apiClient.get('/api/v1/quizzes?limit=1'),
          progressApi.getHomepageStats(),
          typingGameApi.getLeaderboard('wpm', 1),
        ]);

        const homepageStats = homepageStatsRes.status === 'fulfilled' ? homepageStatsRes.value : null;

        setStats({
          totalCourses: coursesRes.status === 'fulfilled' ? (coursesRes.value?.total || coursesRes.value?.courses?.length || 0) : 0,
          totalTutorials: tutorialsRes.status === 'fulfilled' ? (Array.isArray(tutorialsRes.value) ? tutorialsRes.value.length : 0) : 0,
          totalQuizzes: quizzesRes.status === 'fulfilled' ? (Array.isArray(quizzesRes.value?.data) ? quizzesRes.value.data.length : 0) : 0,
          totalLearners: homepageStats?.total_learners || 0,
        });

        // Set fastest typer
        if (typingLeaderboardRes.status === 'fulfilled') {
          const entries = typingLeaderboardRes.value?.entries || [];
          if (entries.length > 0) {
            setFastestTyper({
              username: entries[0].display_name || entries[0].username,
              wpm: entries[0].best_wpm,
            });
          }
        }
      } catch (error) {
        console.error('Failed to load stats:', error);
      }
    };
    fetchStats();
  }, []);

  // Fetch content based on active tab
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        let items: ContentItem[] = [];

        if (activeTab === 'trending' || activeTab === 'courses') {
          const coursesRes = await coursesApi.getCourses({ status: 'published', page_size: 4 });
          items = (coursesRes?.courses || []).map((c: any) => ({
            id: c.id,
            title: c.title,
            type: 'course' as const,
            category: c.category,
            xp: c.xp_reward || 100,
            link: `/courses/${c.id}`,
          }));
        }

        if (activeTab === 'trending' || activeTab === 'tutorials') {
          const tutorialsRes = await getTutorials({ limit: 4 });
          const tutorialItems = (Array.isArray(tutorialsRes) ? tutorialsRes : []).map((t: any) => ({
            id: t.id.toString(),
            title: t.title,
            type: 'tutorial' as const,
            category: t.category?.name,
            xp: t.xp_reward || 50,
            link: `/tutorials/${t.slug || t.id}`,
          }));

          if (activeTab === 'tutorials') {
            items = tutorialItems;
          } else {
            items = [...items.slice(0, 2), ...tutorialItems.slice(0, 2)];
          }
        }

        if (activeTab === 'quizzes') {
          const quizzesRes = await apiClient.get('/api/v1/quizzes/featured?limit=4');
          items = (Array.isArray(quizzesRes?.data) ? quizzesRes.data : []).map((q: any) => ({
            id: q.id,
            title: q.title,
            type: 'quiz' as const,
            category: q.category,
            xp: q.xp_reward || 25,
            link: `/quizzes/${q.id}`,
          }));
        }

        setContent(items.slice(0, 4));

        // Fetch leaderboard
        const leaderData = await progressApi.getXPLeaderboard(5, 0);
        setLeaderboard(
          (Array.isArray(leaderData) ? leaderData : []).map((entry: any, i: number) => ({
            rank: i + 1,
            username: entry.username || `User${i + 1}`,
            xp: entry.total_xp || 0,
          }))
        );
      } catch (error) {
        console.error('Failed to load pulse data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [activeTab]);

  const getRankStyle = (rank: number) => {
    if (rank === 1) return 'bg-gradient-to-r from-yellow-400 to-amber-500 text-white shadow-lg shadow-amber-200/50 dark:shadow-amber-900/30';
    if (rank === 2) return 'bg-gradient-to-r from-gray-300 to-slate-400 text-white';
    if (rank === 3) return 'bg-gradient-to-r from-orange-400 to-amber-600 text-white';
    return 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400';
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'course': return { bg: 'from-blue-500 to-indigo-600', text: 'text-blue-600 dark:text-blue-400', border: 'border-blue-200 dark:border-blue-800 hover:border-blue-400 dark:hover:border-blue-600' };
      case 'tutorial': return { bg: 'from-purple-500 to-violet-600', text: 'text-purple-600 dark:text-purple-400', border: 'border-purple-200 dark:border-purple-800 hover:border-purple-400 dark:hover:border-purple-600' };
      case 'quiz': return { bg: 'from-amber-500 to-orange-600', text: 'text-amber-600 dark:text-amber-400', border: 'border-amber-200 dark:border-amber-800 hover:border-amber-400 dark:hover:border-amber-600' };
      default: return { bg: 'from-gray-500 to-slate-600', text: 'text-gray-600 dark:text-gray-400', border: 'border-gray-200 dark:border-gray-700' };
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'course': return <GraduationCap className="w-4 h-4" />;
      case 'tutorial': return <BookOpen className="w-4 h-4" />;
      case 'quiz': return <Brain className="w-4 h-4" />;
      default: return <TrendingUp className="w-4 h-4" />;
    }
  };

  const statItems = [
    { label: 'Courses', value: animCourses, icon: GraduationCap, color: 'from-blue-500 to-indigo-600' },
    { label: 'Tutorials', value: animTutorials, icon: BookOpen, color: 'from-purple-500 to-violet-600' },
    { label: 'Quizzes', value: animQuizzes, icon: Brain, color: 'from-amber-500 to-orange-600' },
    { label: 'Learners', value: animLearners, icon: Users, color: 'from-emerald-500 to-teal-600' },
  ];

  return (
    <section ref={sectionRef} className="relative py-14 sm:py-20 overflow-hidden">
      {/* Breathing background pulse */}
      <div className="absolute inset-0 bg-gray-50 dark:bg-slate-900" />
      <motion.div
        animate={{
          opacity: [0.03, 0.08, 0.03],
          scale: [1, 1.1, 1],
        }}
        transition={{
          duration: 6,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-gradient-radial from-blue-500/20 via-purple-500/10 to-transparent blur-3xl"
      />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-10"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl shadow-lg shadow-blue-500/20">
              <GraduationCap className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white">Start Learning Today</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">Check out our latest content and start building your skills</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {fastestTyper && (
              <Link
                to="/typing-practice/leaderboard"
                className="inline-flex items-center gap-2 px-4 py-2 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 rounded-lg text-sm font-medium hover:bg-orange-200 dark:hover:bg-orange-900/50 transition-colors"
              >
                <Zap className="w-4 h-4" />
                <span className="hidden sm:inline">Fastest Typer:</span> {fastestTyper.username} ({fastestTyper.wpm} WPM)
              </Link>
            )}
            <Link
              to="/leaderboard"
              className="inline-flex items-center gap-2 px-4 py-2 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 rounded-lg text-sm font-medium hover:bg-amber-200 dark:hover:bg-amber-900/50 transition-colors"
            >
              <Trophy className="w-4 h-4" />
              Leaderboard
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </motion.div>

        {/* Animated stat counters */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
          {statItems.map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: index * 0.1, duration: 0.5 }}
              className="bg-white dark:bg-slate-800/80 rounded-xl p-4 border border-gray-200 dark:border-slate-700/50 shadow-sm"
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg bg-gradient-to-br ${stat.color}`}>
                  <stat.icon className="w-4 h-4 text-white" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-slate-900 dark:text-white tabular-nums">
                    {stat.value > 0 ? stat.value.toLocaleString() : '--'}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">{stat.label}</div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main content area */}
          <div className="lg:col-span-2">
            {/* Tabs with auto-rotate indicator */}
            <div className="flex gap-2 mb-6 overflow-x-auto pb-1">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => handleManualTabChange(tab.id)}
                  className={`relative flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === tab.id
                      ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 shadow-lg'
                      : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 border border-gray-200 dark:border-slate-700'
                  }`}
                >
                  <tab.icon className="w-3.5 h-3.5" />
                  {tab.label}
                  {/* Auto-rotate progress indicator */}
                  {activeTab === tab.id && isAutoRotating && (
                    <motion.div
                      className="absolute bottom-0 left-0 h-0.5 bg-blue-400 dark:bg-blue-500 rounded-full"
                      initial={{ width: '0%' }}
                      animate={{ width: '100%' }}
                      transition={{ duration: 5, ease: 'linear' }}
                      key={`progress-${activeTab}`}
                    />
                  )}
                </button>
              ))}
            </div>

            {/* Content cards */}
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -12 }}
                transition={{ duration: 0.2 }}
              >
                {loading ? (
                  <div className="flex items-center justify-center py-16">
                    <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
                  </div>
                ) : content.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-center">
                    <Target className="w-8 h-8 text-slate-300 dark:text-slate-600 mb-2" />
                    <p className="text-slate-500 dark:text-slate-400 text-sm">
                      No {activeTab === 'trending' ? 'trending content' : activeTab} yet
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {content.map((item, index) => {
                      const colors = getTypeColor(item.type);
                      return (
                        <motion.div
                          key={item.id}
                          initial={{ opacity: 0, y: 16 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: index * 0.08 }}
                          onClick={() => navigate(item.link)}
                          className="group cursor-pointer"
                        >
                          <div className={`relative bg-white dark:bg-slate-800/80 rounded-xl p-5 border ${colors.border} transition-all duration-300 hover:shadow-lg hover:-translate-y-1`}>
                            {/* Gradient top border */}
                            <div className={`absolute top-0 left-4 right-4 h-0.5 bg-gradient-to-r ${colors.bg} rounded-full opacity-0 group-hover:opacity-100 transition-opacity`} />

                            <div className="flex items-center gap-2 mb-3">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-gray-100 dark:bg-slate-700/50 ${colors.text} text-xs font-medium`}>
                                {getTypeIcon(item.type)}
                                <span className="capitalize">{item.type}</span>
                              </span>
                              {item.category && (
                                <span className="text-xs text-slate-400 dark:text-slate-500">
                                  {item.category}
                                </span>
                              )}
                            </div>

                            <h3 className="font-semibold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors line-clamp-2 mb-3 min-h-[2.5rem]">
                              {item.title}
                            </h3>

                            <div className="flex items-center justify-between">
                              <span className="flex items-center gap-1.5 text-amber-500 text-sm font-semibold">
                                <Zap className="w-3.5 h-3.5" />
                                +{item.xp} XP
                              </span>
                              <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-blue-500 group-hover:translate-x-1 transition-all" />
                            </div>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Leaderboard sidebar */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={isInView ? { opacity: 1, x: 0 } : {}}
            transition={{ delay: 0.3, duration: 0.5 }}
          >
            <div className="bg-white dark:bg-slate-800/80 rounded-xl border border-gray-200 dark:border-slate-700/50 overflow-hidden shadow-sm">
              <div className="px-5 py-4 border-b border-gray-100 dark:border-slate-700/50">
                <div className="flex items-center gap-2">
                  <Trophy className="w-5 h-5 text-amber-500" />
                  <h3 className="font-bold text-slate-900 dark:text-white">Top Learners</h3>
                </div>
              </div>

              <div className="p-3">
                {leaderboard.length === 0 ? (
                  <div className="text-center py-6 text-slate-400 dark:text-slate-500 text-sm">
                    No leaderboard data yet
                  </div>
                ) : (
                  <div className="space-y-2">
                    {leaderboard.map((entry, index) => (
                      <motion.div
                        key={entry.rank}
                        initial={{ opacity: 0, x: -10 }}
                        animate={isInView ? { opacity: 1, x: 0 } : {}}
                        transition={{ delay: 0.4 + index * 0.1 }}
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors"
                      >
                        {/* Rank badge */}
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${getRankStyle(entry.rank)}`}>
                          {entry.rank}
                        </div>

                        {/* Username */}
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-slate-900 dark:text-white truncate text-sm">
                            {entry.username}
                          </div>
                        </div>

                        {/* XP with animated bar */}
                        <div className="flex-shrink-0 text-right">
                          <div className="text-sm font-bold text-slate-900 dark:text-white">
                            {entry.xp.toLocaleString()}
                          </div>
                          <div className="text-xs text-slate-400 dark:text-slate-500">XP</div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                )}
              </div>

              <div className="px-5 py-3 border-t border-gray-100 dark:border-slate-700/50">
                <Link
                  to="/leaderboard"
                  className="flex items-center justify-center gap-1.5 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
                >
                  View all rankings
                  <ChevronRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default ThePulse;
