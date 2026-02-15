// frontend/src/plugins/typing-game/pages/TypingGamePage.tsx
/**
 * Typing Game main landing page — mobile-first redesign
 * Compact hero, slim stats bar, featured QBF card, 2x2 game grid,
 * horizontal top-3 leaderboard, compact guest CTA
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  RefreshCw,
  Keyboard,
  Zap,
  Swords,
  Trophy,
  Target,
  TrendingUp,
  Play,
  Award,
  Infinity,
  Ghost,
  Crown,
  Medal,
  Flame,
  ChevronRight,
} from 'lucide-react';
import { useAuth } from '../../../state/contexts/AuthContext';
import { typingGameApi, type StreakInfo } from '../services/typingGameApi';
import { StreakDisplay } from '../components/StreakDisplay';
import type { UserTypingStats, LeaderboardEntry } from '../types';

export const TypingGamePage: React.FC = () => {
  const { isAuthenticated, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [stats, setStats] = useState<UserTypingStats | null>(null);
  const [streakInfo, setStreakInfo] = useState<StreakInfo | null>(null);
  const [topPlayers, setTopPlayers] = useState<LeaderboardEntry[]>([]);
  const [pvpEnabled, setPvpEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = useCallback(async (showRefreshIndicator = false) => {
    if (showRefreshIndicator) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const [leaderboard, pvpSettings] = await Promise.all([
        typingGameApi.getLeaderboard('wpm', 3).catch(() => ({ entries: [] })),
        typingGameApi.getPVPSettings().catch(() => ({ pvp_enabled: false })),
      ]);
      setTopPlayers(leaderboard.entries);
      setPvpEnabled(pvpSettings.pvp_enabled);

      if (isAuthenticated) {
        const [userStats, streak] = await Promise.all([
          typingGameApi.getMyStats(),
          typingGameApi.getMyStreak().catch(() => null),
        ]);
        setStats(userStats);
        if (streak) setStreakInfo(streak);
      }
    } catch (error) {
      console.error('Failed to fetch typing game data:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    fetchData();
  }, [fetchData, location.key]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        fetchData(true);
      }
    };
    const handleFocus = () => {
      fetchData(true);
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleFocus);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleFocus);
    };
  }, [fetchData]);

  useEffect(() => {
    if (location.state?.gameCompleted) {
      navigate(location.pathname, { replace: true, state: {} });
      fetchData(true);
    }
  }, [location.state, location.pathname, navigate, fetchData]);

  const handleRefresh = () => {
    fetchData(true);
  };

  const gridModes: Array<{
    id: string;
    title: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    color: string;
    link: string;
    badge?: string;
  }> = [
    {
      id: 'infinite-rush',
      title: 'Infinite Rush',
      description: '60s speed typing',
      icon: Infinity,
      color: 'from-orange-500 to-red-600',
      link: '/typing-practice/infinite-rush',
      badge: 'New',
    },
    {
      id: 'ghost-mode',
      title: 'Ghost Mode',
      description: 'Beat your best',
      icon: Ghost,
      color: 'from-purple-500 to-indigo-600',
      link: '/typing-practice/ghost',
      badge: 'New',
    },
    {
      id: 'practice',
      title: 'Practice',
      description: 'Custom word lists',
      icon: Target,
      color: 'from-green-500 to-teal-600',
      link: '/typing-practice/practice',
    },
    {
      id: 'pvp',
      title: 'PVP Battle',
      description: pvpEnabled ? 'Challenge players' : 'Coming soon',
      icon: Swords,
      color: 'from-red-500 to-orange-600',
      link: '/typing-practice/pvp',
      badge: pvpEnabled ? undefined : 'Soon',
    },
  ];

  const getRankIcon = (idx: number) => {
    if (idx === 0) return <Crown className="w-5 h-5 text-yellow-500" />;
    if (idx === 1) return <Medal className="w-5 h-5 text-gray-400" />;
    return <Medal className="w-5 h-5 text-orange-600" />;
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-4 sm:py-8">
      <div className="max-w-3xl mx-auto px-3 sm:px-4 space-y-3 sm:space-y-5">

        {/* ─── 1. Compact Hero ─── */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-3"
        >
          <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center shadow-md">
            <Keyboard className="w-6 h-6 text-white" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white truncate">
                Typing Practice
              </h1>
              {isAuthenticated && streakInfo && (
                <StreakDisplay streak={streakInfo} compact />
              )}
            </div>
            <p className="hidden sm:block text-sm text-gray-500 dark:text-gray-400">
              Improve your speed and accuracy with fun challenges
            </p>
          </div>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex-shrink-0 p-2 text-gray-400 hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded-lg transition-colors disabled:opacity-50"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </motion.div>

        {/* ─── 2. Quick Stats Bar ─── */}
        {isAuthenticated && stats && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className={`flex items-center justify-between px-4 py-2.5 bg-white/80 dark:bg-gray-800/80 backdrop-blur rounded-xl border border-gray-200 dark:border-gray-700 transition-opacity ${refreshing ? 'opacity-50' : ''}`}
          >
            <div className="flex items-center gap-1.5">
              <Zap className="w-4 h-4 text-blue-500" />
              <span className="font-bold text-sm text-gray-900 dark:text-white">{stats.best_wpm}</span>
              <span className="hidden sm:inline text-xs text-gray-500">WPM</span>
            </div>
            <div className="w-px h-4 bg-gray-200 dark:bg-gray-700" />
            <div className="flex items-center gap-1.5">
              <Target className="w-4 h-4 text-green-500" />
              <span className="font-bold text-sm text-gray-900 dark:text-white">{(stats.avg_accuracy ?? 0).toFixed(1)}%</span>
              <span className="hidden sm:inline text-xs text-gray-500">Accuracy</span>
            </div>
            <div className="w-px h-4 bg-gray-200 dark:bg-gray-700" />
            <div className="flex items-center gap-1.5">
              <TrendingUp className="w-4 h-4 text-purple-500" />
              <span className="font-bold text-sm text-gray-900 dark:text-white">{stats.total_games_completed}</span>
              <span className="hidden sm:inline text-xs text-gray-500">Games</span>
            </div>
            <div className="w-px h-4 bg-gray-200 dark:bg-gray-700" />
            <div className="flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-orange-500" />
              <span className="font-bold text-sm text-gray-900 dark:text-white">{stats.current_streak_days}</span>
              <span className="hidden sm:inline text-xs text-gray-500">Streak</span>
            </div>
          </motion.div>
        )}

        {/* ─── 3. Featured Quick Brown Fox Card ─── */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Link
            to="/typing-practice/play"
            className="group relative block overflow-hidden rounded-xl bg-gradient-to-r from-blue-500 to-purple-600 p-4 sm:p-5 shadow-lg hover:shadow-xl transition-shadow"
          >
            {/* Decorative circles */}
            <div className="absolute -right-6 -top-6 w-24 h-24 bg-white/10 rounded-full" />
            <div className="absolute -right-2 -bottom-8 w-16 h-16 bg-white/5 rounded-full" />

            <div className="relative flex items-center gap-4">
              <div className="flex-shrink-0 w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center backdrop-blur-sm">
                <Zap className="w-6 h-6 text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <h2 className="text-lg font-bold text-white">Quick Brown Fox</h2>
                <p className="text-sm text-white/80">3-round progressive challenge</p>
              </div>
              <div className="flex-shrink-0 flex items-center gap-1.5 px-4 py-2 bg-white/20 hover:bg-white/30 backdrop-blur-sm rounded-lg text-white font-semibold text-sm transition-colors group-hover:bg-white/30">
                <Play className="w-4 h-4" />
                <span className="hidden sm:inline">Quick Play</span>
                <span className="sm:hidden">Play</span>
              </div>
            </div>
          </Link>
        </motion.div>

        {/* ─── 4. Game Mode Grid (2×2) ─── */}
        <div className="grid grid-cols-2 gap-2.5 sm:gap-3">
          {gridModes.map((mode, idx) => {
            const isDisabled = mode.badge === 'Soon';
            return (
              <motion.div
                key={mode.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 + idx * 0.04 }}
              >
                <Link
                  to={isDisabled ? '#' : mode.link}
                  onClick={(e) => isDisabled && e.preventDefault()}
                  className={`group relative block overflow-hidden rounded-xl bg-gradient-to-br ${mode.color} p-3.5 sm:p-4 shadow-md hover:shadow-lg transition-shadow ${isDisabled ? 'opacity-60 cursor-not-allowed' : ''}`}
                >
                  {mode.badge && (
                    <div className={`absolute top-2 right-2 text-[10px] font-bold px-1.5 py-0.5 rounded text-white ${
                      mode.badge === 'New' ? 'bg-white/25' : 'bg-black/20'
                    }`}>
                      {mode.badge}
                    </div>
                  )}

                  <mode.icon className="w-7 h-7 sm:w-8 sm:h-8 text-white/90 mb-2" />
                  <h3 className="text-sm sm:text-base font-bold text-white leading-tight">
                    {mode.title}
                  </h3>
                  <p className="text-[11px] sm:text-xs text-white/70 mt-0.5 leading-snug">
                    {mode.description}
                  </p>
                </Link>
              </motion.div>
            );
          })}
        </div>

        {/* ─── 5. Horizontal Top 3 Leaderboard ─── */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4"
        >
          <div className="flex justify-between items-center mb-3">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-1.5">
              <Trophy className="w-4 h-4 text-yellow-500" />
              Top Players
            </h2>
            <Link
              to="/typing-practice/leaderboard"
              className="text-blue-500 hover:text-blue-600 text-xs font-medium flex items-center gap-0.5"
            >
              View All
              <ChevronRight className="w-3 h-3" />
            </Link>
          </div>

          {loading ? (
            <div className="text-center py-4 text-gray-500 text-sm">Loading...</div>
          ) : topPlayers.length > 0 ? (
            <div className="grid grid-cols-3 gap-2">
              {topPlayers.map((player, idx) => (
                <div
                  key={player.user_id}
                  className={`relative text-center p-3 rounded-xl ${
                    idx === 0
                      ? 'bg-yellow-50 dark:bg-yellow-900/20 ring-1 ring-yellow-300 dark:ring-yellow-700'
                      : 'bg-gray-50 dark:bg-gray-700/50'
                  }`}
                >
                  <div className="flex justify-center mb-1">
                    {getRankIcon(idx)}
                  </div>
                  <div className="text-xl sm:text-2xl font-bold text-blue-600 dark:text-blue-400">
                    {player.best_wpm}
                  </div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide">WPM</div>
                  <div className="text-xs font-medium text-gray-700 dark:text-gray-300 truncate mt-1">
                    {player.display_name || player.username}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-4 text-gray-500 text-sm">
              No players yet. Be the first to play!
            </div>
          )}
        </motion.div>

        {/* ─── 6. Compact Guest CTA ─── */}
        {!isAuthenticated && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="flex items-center gap-3 bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl px-4 py-3.5 text-white"
          >
            <Award className="w-8 h-8 flex-shrink-0 opacity-80" />
            <div className="flex-1 min-w-0">
              <h3 className="font-bold text-sm">Track Your Progress</h3>
              <p className="text-xs text-white/80 hidden sm:block">
                Save scores, compete on leaderboards, and earn achievements
              </p>
            </div>
            <Link
              to="/login"
              className="flex-shrink-0 px-4 py-1.5 bg-white text-blue-600 rounded-lg font-semibold text-sm hover:bg-gray-100 transition-colors"
            >
              Sign In
            </Link>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default TypingGamePage;
