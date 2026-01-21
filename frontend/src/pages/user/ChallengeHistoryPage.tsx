// src/pages/user/ChallengeHistoryPage.tsx
/**
 * Challenge History Page
 * Shows user's past daily challenge completions with calendar view
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Target,
  Flame,
  Trophy,
  Calendar,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  Loader2,
  Shield,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { challengesApi, ChallengeHistoryEntry } from '../../plugins/shared/services/challengesApi';
import type { ChallengeStreak } from '../../plugins/shared/types';
import { DIFFICULTY_COLORS } from '../../plugins/shared/types';

export const ChallengeHistoryPage: React.FC = () => {
  const [history, setHistory] = useState<ChallengeHistoryEntry[]>([]);
  const [streak, setStreak] = useState<ChallengeStreak | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [currentMonth, setCurrentMonth] = useState(new Date());

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setLoading(true);
    try {
      const [historyData, streakData] = await Promise.all([
        challengesApi.getHistory(50, 0),
        challengesApi.getStreak(),
      ]);
      setHistory(historyData.history);
      setStreak(streakData);
      setHasMore(historyData.has_more);
    } catch (error) {
      console.error('Failed to load challenge history:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadMore = async () => {
    if (loadingMore || !hasMore) return;

    setLoadingMore(true);
    try {
      const data = await challengesApi.getHistory(50, history.length);
      setHistory([...history, ...data.history]);
      setHasMore(data.has_more);
    } catch (error) {
      console.error('Failed to load more history:', error);
    } finally {
      setLoadingMore(false);
    }
  };

  // Group history by date
  const historyByDate = history.reduce<Record<string, ChallengeHistoryEntry[]>>((acc, entry) => {
    const date = entry.challenge_date;
    if (!acc[date]) {
      acc[date] = [];
    }
    acc[date].push(entry);
    return acc;
  }, {});

  // Get calendar days for current month
  const getCalendarDays = () => {
    const year = currentMonth.getFullYear();
    const month = currentMonth.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const daysInMonth = lastDay.getDate();
    const startingDay = firstDay.getDay();

    const days: (Date | null)[] = [];

    // Add empty cells for days before the first of the month
    for (let i = 0; i < startingDay; i++) {
      days.push(null);
    }

    // Add all days of the month
    for (let i = 1; i <= daysInMonth; i++) {
      days.push(new Date(year, month, i));
    }

    return days;
  };

  const formatDate = (date: Date) => {
    return date.toISOString().split('T')[0];
  };

  const getDayStatus = (date: Date) => {
    const dateStr = formatDate(date);
    const entries = historyByDate[dateStr];

    if (!entries) return null;

    const completed = entries.filter((e) => e.is_completed).length;
    const total = entries.length;

    if (completed === total && total > 0) {
      return 'complete';
    } else if (completed > 0) {
      return 'partial';
    }
    return 'none';
  };

  const prevMonth = () => {
    setCurrentMonth(new Date(currentMonth.getFullYear(), currentMonth.getMonth() - 1, 1));
  };

  const nextMonth = () => {
    setCurrentMonth(new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 1));
  };

  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];

  const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
      </div>
    );
  }

  const totalCompleted = history.filter((e) => e.is_completed).length;
  const totalXPEarned = history.reduce((sum, e) => sum + (e.xp_earned || 0), 0);
  const uniqueDays = Object.keys(historyByDate).length;

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
            <Calendar className="w-6 h-6 text-orange-600 dark:text-orange-400" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Challenge History
          </h1>
        </div>
        <p className="text-gray-600 dark:text-gray-400">
          Track your daily challenge progress and streak
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-100 dark:border-gray-700">
          <div className="flex items-center gap-2 text-orange-600 dark:text-orange-400 mb-1">
            <Flame className="w-5 h-5" />
            <span className="text-sm font-medium">Current Streak</span>
          </div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {streak?.current_streak || 0} days
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-100 dark:border-gray-700">
          <div className="flex items-center gap-2 text-purple-600 dark:text-purple-400 mb-1">
            <Trophy className="w-5 h-5" />
            <span className="text-sm font-medium">Best Streak</span>
          </div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {streak?.longest_streak || 0} days
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-100 dark:border-gray-700">
          <div className="flex items-center gap-2 text-green-600 dark:text-green-400 mb-1">
            <CheckCircle className="w-5 h-5" />
            <span className="text-sm font-medium">Completed</span>
          </div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {totalCompleted}
          </p>
        </div>

        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-100 dark:border-gray-700">
          <div className="flex items-center gap-2 text-yellow-600 dark:text-yellow-400 mb-1">
            <Sparkles className="w-5 h-5" />
            <span className="text-sm font-medium">XP Earned</span>
          </div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {totalXPEarned.toLocaleString()}
          </p>
        </div>
      </div>

      {/* Freeze Tokens */}
      {streak && (
        <div className="mb-8 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-200 dark:border-blue-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  Freeze Tokens
                </p>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Protect your streak when life gets busy
                </p>
              </div>
            </div>
            <div className="flex gap-1">
              {[...Array(3)].map((_, i) => (
                <div
                  key={i}
                  className={`w-8 h-8 rounded-full flex items-center justify-center ${
                    i < streak.freeze_tokens
                      ? 'bg-blue-100 dark:bg-blue-800'
                      : 'bg-gray-100 dark:bg-gray-700'
                  }`}
                >
                  <Shield
                    className={`w-4 h-4 ${
                      i < streak.freeze_tokens
                        ? 'text-blue-600 dark:text-blue-400'
                        : 'text-gray-400'
                    }`}
                  />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Calendar View */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow border border-gray-100 dark:border-gray-700 p-6 mb-8">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {monthNames[currentMonth.getMonth()]} {currentMonth.getFullYear()}
          </h2>
          <div className="flex gap-2">
            <button
              onClick={prevMonth}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-gray-400" />
            </button>
            <button
              onClick={nextMonth}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              <ChevronRight className="w-5 h-5 text-gray-600 dark:text-gray-400" />
            </button>
          </div>
        </div>

        {/* Day names */}
        <div className="grid grid-cols-7 gap-1 mb-2">
          {dayNames.map((day) => (
            <div
              key={day}
              className="text-center text-xs font-medium text-gray-500 dark:text-gray-400 py-2"
            >
              {day}
            </div>
          ))}
        </div>

        {/* Calendar grid */}
        <div className="grid grid-cols-7 gap-1">
          {getCalendarDays().map((date, idx) => {
            if (!date) {
              return <div key={`empty-${idx}`} className="aspect-square" />;
            }

            const status = getDayStatus(date);
            const isToday = formatDate(date) === formatDate(new Date());
            const isFuture = date > new Date();

            return (
              <motion.div
                key={formatDate(date)}
                whileHover={{ scale: 1.05 }}
                className={`aspect-square flex items-center justify-center rounded-lg text-sm font-medium cursor-default transition-colors ${
                  isToday
                    ? 'ring-2 ring-orange-500'
                    : ''
                } ${
                  isFuture
                    ? 'text-gray-300 dark:text-gray-600'
                    : status === 'complete'
                    ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                    : status === 'partial'
                    ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400'
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                {date.getDate()}
              </motion.div>
            );
          })}
        </div>

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-6 pt-4 border-t border-gray-100 dark:border-gray-700">
          <div className="flex items-center gap-2 text-sm">
            <div className="w-4 h-4 bg-green-100 dark:bg-green-900/30 rounded" />
            <span className="text-gray-600 dark:text-gray-400">All completed</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <div className="w-4 h-4 bg-yellow-100 dark:bg-yellow-900/30 rounded" />
            <span className="text-gray-600 dark:text-gray-400">Partial</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <div className="w-4 h-4 ring-2 ring-orange-500 rounded" />
            <span className="text-gray-600 dark:text-gray-400">Today</span>
          </div>
        </div>
      </div>

      {/* Recent History List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow border border-gray-100 dark:border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Recent Challenges
          </h2>
        </div>

        {history.length === 0 ? (
          <div className="p-8 text-center">
            <Target className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              No challenge history yet
            </p>
            <Link
              to="/"
              className="text-orange-600 dark:text-orange-400 font-medium hover:underline"
            >
              Start your first challenge
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {history.slice(0, 20).map((entry, idx) => (
              <motion.div
                key={`${entry.challenge_id}-${idx}`}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.05 }}
                className="px-6 py-4 flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`p-2 rounded-lg ${
                      entry.is_completed
                        ? 'bg-green-100 dark:bg-green-900/30'
                        : 'bg-gray-100 dark:bg-gray-700'
                    }`}
                  >
                    {entry.is_completed ? (
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-gray-400" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {entry.title}
                    </p>
                    <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                      <span>{entry.challenge_date}</span>
                      <span
                        className={`px-1.5 py-0.5 text-xs rounded ${
                          DIFFICULTY_COLORS[entry.difficulty] || ''
                        }`}
                      >
                        {entry.difficulty}
                      </span>
                    </div>
                  </div>
                </div>

                {entry.xp_earned > 0 && (
                  <div className="flex items-center gap-1 text-yellow-600 dark:text-yellow-400">
                    <Sparkles className="w-4 h-4" />
                    <span className="font-medium">+{entry.xp_earned}</span>
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        )}

        {hasMore && (
          <div className="px-6 py-4 border-t border-gray-100 dark:border-gray-700">
            <button
              onClick={loadMore}
              disabled={loadingMore}
              className="w-full py-2 text-orange-600 dark:text-orange-400 font-medium hover:text-orange-700 dark:hover:text-orange-300 disabled:opacity-50"
            >
              {loadingMore ? (
                <Loader2 className="w-5 h-5 animate-spin mx-auto" />
              ) : (
                'Load more'
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default ChallengeHistoryPage;
