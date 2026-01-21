// src/components/home/HomepageStatsWidget.tsx
/**
 * Homepage Stats Widget - Displays platform-wide learning statistics
 * Shows community activity and engagement metrics
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Users,
  Star,
  BookOpen,
  GraduationCap,
  HelpCircle,
  Keyboard,
  Trophy,
  TrendingUp,
  Loader2,
} from 'lucide-react';
import { progressApi } from '../../plugins/shared/services/progressApi';
import type { HomepageStats } from '../../plugins/shared/types';

interface StatCardProps {
  icon: React.ReactNode;
  value: string | number;
  label: string;
  color: string;
  delay: number;
}

const StatCard: React.FC<StatCardProps> = ({ icon, value, label, color, delay }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-md border border-gray-100 dark:border-gray-700 hover:shadow-lg transition-shadow"
    >
      <div className="flex items-center gap-3">
        <div className={`p-2.5 rounded-lg ${color}`}>
          {icon}
        </div>
        <div>
          <div className="text-xl font-bold text-gray-900 dark:text-white">
            {value}
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            {label}
          </div>
        </div>
      </div>
    </motion.div>
  );
};

const HomepageStatsWidget: React.FC = () => {
  const [stats, setStats] = useState<HomepageStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await progressApi.getHomepageStats();
        setStats(data);
      } catch (error) {
        console.error('Failed to load homepage stats:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading) {
    return (
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-center h-32">
          <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
        </div>
      </section>
    );
  }

  if (!stats) {
    return null;
  }

  const formatNumber = (num: number | undefined | null) => {
    if (num == null) return '0';
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  const statItems = [
    {
      icon: <Users className="w-5 h-5 text-blue-600" />,
      value: formatNumber(stats.total_learners),
      label: 'Active Learners',
      color: 'bg-blue-100 dark:bg-blue-900/30',
    },
    {
      icon: <Star className="w-5 h-5 text-yellow-600" />,
      value: formatNumber(stats.total_xp_earned),
      label: 'Total XP Earned',
      color: 'bg-yellow-100 dark:bg-yellow-900/30',
    },
    {
      icon: <BookOpen className="w-5 h-5 text-green-600" />,
      value: formatNumber(stats.tutorials_completed),
      label: 'Tutorials Completed',
      color: 'bg-green-100 dark:bg-green-900/30',
    },
    {
      icon: <GraduationCap className="w-5 h-5 text-purple-600" />,
      value: formatNumber(stats.courses_completed),
      label: 'Courses Completed',
      color: 'bg-purple-100 dark:bg-purple-900/30',
    },
    {
      icon: <HelpCircle className="w-5 h-5 text-indigo-600" />,
      value: formatNumber(stats.quizzes_completed),
      label: 'Quizzes Passed',
      color: 'bg-indigo-100 dark:bg-indigo-900/30',
    },
    {
      icon: <Keyboard className="w-5 h-5 text-pink-600" />,
      value: formatNumber(stats.typing_games_played),
      label: 'Typing Games',
      color: 'bg-pink-100 dark:bg-pink-900/30',
    },
    {
      icon: <Trophy className="w-5 h-5 text-orange-600" />,
      value: formatNumber(stats.total_achievements_unlocked),
      label: 'Achievements Unlocked',
      color: 'bg-orange-100 dark:bg-orange-900/30',
    },
    {
      icon: <TrendingUp className="w-5 h-5 text-teal-600" />,
      value: `Lvl ${stats.highest_level}`,
      label: 'Highest Level',
      color: 'bg-teal-100 dark:bg-teal-900/30',
    },
  ];

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="text-center mb-8"
      >
        <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Join Our Learning Community
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          See what our community has accomplished together
        </p>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {statItems.map((item, idx) => (
          <StatCard
            key={item.label}
            {...item}
            delay={idx * 0.1}
          />
        ))}
      </div>

      {/* Active Today Badge */}
      {stats.active_learners_today > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.8 }}
          className="mt-6 text-center"
        >
          <span className="inline-flex items-center gap-2 px-4 py-2 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-full text-sm font-medium">
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            {stats.active_learners_today} learners active today
          </span>
        </motion.div>
      )}
    </section>
  );
};

export default HomepageStatsWidget;
