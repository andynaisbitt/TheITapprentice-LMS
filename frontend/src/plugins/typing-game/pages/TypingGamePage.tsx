// frontend/src/plugins/typing-game/pages/TypingGamePage.tsx
/**
 * Typing Game main landing page
 * Shows game modes, stats, and leaderboard preview
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { RefreshCw } from 'lucide-react';
import {
  Keyboard,
  Zap,
  Swords,
  Trophy,
  Target,
  Clock,
  TrendingUp,
  Play,
  Users,
  Award,
  Infinity,
  Ghost,
} from 'lucide-react';
import { useAuth } from '../../../state/contexts/AuthContext';
import { typingGameApi } from '../services/typingGameApi';
import type { UserTypingStats, LeaderboardEntry } from '../types';

export const TypingGamePage: React.FC = () => {
  const { isAuthenticated, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [stats, setStats] = useState<UserTypingStats | null>(null);
  const [topPlayers, setTopPlayers] = useState<LeaderboardEntry[]>([]);
  const [pvpEnabled, setPvpEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Fetch all data - extracted as callback for manual refresh
  const fetchData = useCallback(async (showRefreshIndicator = false) => {
    if (showRefreshIndicator) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      // Fetch leaderboard and PVP settings in parallel
      const [leaderboard, pvpSettings] = await Promise.all([
        typingGameApi.getLeaderboard('wpm', 5).catch(() => ({ entries: [] })),
        typingGameApi.getPVPSettings().catch(() => ({ pvp_enabled: false })),
      ]);
      setTopPlayers(leaderboard.entries);
      setPvpEnabled(pvpSettings.pvp_enabled);

      // Fetch user stats if authenticated
      if (isAuthenticated) {
        const userStats = await typingGameApi.getMyStats();
        setStats(userStats);
      }
    } catch (error) {
      console.error('Failed to fetch typing game data:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [isAuthenticated]);

  // Re-fetch data when navigating back to this page
  useEffect(() => {
    fetchData();
  }, [fetchData, location.key]);

  // Also refresh when page becomes visible (user returns via browser back/tab switch)
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        fetchData(true);
      }
    };

    // Refresh on focus (when user comes back to the tab/window)
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

  // Check for navigation state that indicates a game was just completed
  useEffect(() => {
    if (location.state?.gameCompleted) {
      // Clear the state and refresh
      navigate(location.pathname, { replace: true, state: {} });
      fetchData(true);
    }
  }, [location.state, location.pathname, navigate, fetchData]);

  // Manual refresh handler
  const handleRefresh = () => {
    fetchData(true);
  };

  const gameModes: Array<{
    id: string;
    title: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    color: string;
    link: string;
    badge?: string;
  }> = [
    {
      id: 'quick-brown-fox',
      title: 'Quick Brown Fox',
      description: '3-round progressive challenge',
      icon: Zap,
      color: 'from-blue-500 to-purple-600',
      link: '/typing-practice/play'
    },
    {
      id: 'infinite-rush',
      title: 'Infinite Rush',
      description: '60 seconds of pure speed typing',
      icon: Infinity,
      color: 'from-orange-500 to-red-600',
      link: '/typing-practice/infinite-rush',
      badge: 'New'
    },
    {
      id: 'ghost-mode',
      title: 'Ghost Mode',
      description: 'Race against your personal best',
      icon: Ghost,
      color: 'from-purple-500 to-indigo-600',
      link: '/typing-practice/ghost',
      badge: 'New'
    },
    {
      id: 'practice',
      title: 'Practice Mode',
      description: 'Train with custom word lists',
      icon: Target,
      color: 'from-green-500 to-teal-600',
      link: '/typing-practice/practice'
    },
    {
      id: 'pvp',
      title: 'PVP Battle',
      description: pvpEnabled ? 'Challenge other players' : 'PVP mode is currently disabled',
      icon: Swords,
      color: 'from-red-500 to-orange-600',
      link: '/typing-practice/pvp',
      badge: pvpEnabled ? undefined : 'Disabled'
    }
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-6xl mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl mb-4 shadow-lg">
            <Keyboard className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
            Typing Practice
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            Improve your typing speed and accuracy with fun challenges
          </p>
        </motion.div>

        {/* User Stats (if authenticated) */}
        {isAuthenticated && stats && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-8"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-blue-500" />
                Your Stats
              </h2>
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="p-2 text-gray-500 hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded-lg transition-colors disabled:opacity-50"
                title="Refresh stats"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              </button>
            </div>
            <div className={`grid grid-cols-2 md:grid-cols-4 gap-4 transition-opacity ${refreshing ? 'opacity-50' : ''}`}>
              <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/30 rounded-lg">
                <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                  {stats.best_wpm}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Best WPM</div>
              </div>
              <div className="text-center p-4 bg-green-50 dark:bg-green-900/30 rounded-lg">
                <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                  {(stats.avg_accuracy ?? 0).toFixed(1)}%
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Avg Accuracy</div>
              </div>
              <div className="text-center p-4 bg-purple-50 dark:bg-purple-900/30 rounded-lg">
                <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
                  {stats.total_games_completed}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Games Played</div>
              </div>
              <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/30 rounded-lg">
                <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                  {stats.current_streak_days}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Day Streak</div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Game Modes */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6 mb-8"
        >
          {gameModes.map((mode, idx) => {
            const isDisabled = mode.badge === 'Disabled';
            return (
              <motion.div
                key={mode.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 + idx * 0.05 }}
                className="relative bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden group hover:shadow-xl transition-shadow"
              >
                {mode.badge && (
                  <div className={`absolute top-3 right-3 text-white text-xs font-bold px-2 py-1 rounded ${
                    mode.badge === 'New' ? 'bg-green-500' :
                    mode.badge === 'Hot' ? 'bg-orange-500' :
                    'bg-yellow-500'
                  }`}>
                    {mode.badge}
                  </div>
                )}

                <div className={`h-2 bg-gradient-to-r ${mode.color}`} />

                <div className="p-5 sm:p-6">
                  <div className={`w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br ${mode.color} rounded-xl flex items-center justify-center mb-3 sm:mb-4 shadow-md`}>
                    <mode.icon className="w-6 h-6 sm:w-7 sm:h-7 text-white" />
                  </div>

                  <h3 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-2">
                    {mode.title}
                  </h3>
                  <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mb-4">
                    {mode.description}
                  </p>

                  <Link
                    to={isDisabled ? '#' : mode.link}
                    className={`inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r ${mode.color} text-white rounded-lg font-medium hover:opacity-90 transition-opacity ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}`}
                    onClick={(e) => isDisabled && e.preventDefault()}
                  >
                    <Play className="w-4 h-4" />
                    Play Now
                  </Link>
                </div>
              </motion.div>
            );
          })}
        </motion.div>

        {/* Leaderboard Preview */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6"
        >
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Trophy className="w-5 h-5 text-yellow-500" />
              Top Players
            </h2>
            <Link
              to="/typing-practice/leaderboard"
              className="text-blue-500 hover:text-blue-600 text-sm font-medium"
            >
              View All
            </Link>
          </div>

          {loading ? (
            <div className="text-center py-8 text-gray-500">Loading...</div>
          ) : topPlayers.length > 0 ? (
            <div className="space-y-3">
              {topPlayers.map((player, idx) => (
                <div
                  key={player.user_id}
                  className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-white ${
                      idx === 0 ? 'bg-yellow-500' :
                      idx === 1 ? 'bg-gray-400' :
                      idx === 2 ? 'bg-orange-600' :
                      'bg-gray-300'
                    }`}>
                      {idx + 1}
                    </div>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">
                        {player.display_name || player.username}
                      </div>
                      <div className="text-sm text-gray-500">
                        {player.games_played} games played
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="font-bold text-blue-600 dark:text-blue-400">
                      {player.best_wpm} WPM
                    </div>
                    <div className="text-sm text-gray-500">
                      {(player.avg_accuracy ?? 0).toFixed(1)}% accuracy
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No players yet. Be the first to play!
            </div>
          )}
        </motion.div>

        {/* CTA for non-authenticated users */}
        {!isAuthenticated && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="mt-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl p-8 text-center text-white"
          >
            <Award className="w-12 h-12 mx-auto mb-4 opacity-80" />
            <h3 className="text-2xl font-bold mb-2">Track Your Progress</h3>
            <p className="mb-4 opacity-90">
              Sign in to save your scores, compete on leaderboards, and earn achievements!
            </p>
            <Link
              to="/login"
              className="inline-flex items-center gap-2 px-6 py-3 bg-white text-blue-600 rounded-lg font-semibold hover:bg-gray-100 transition-colors"
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
