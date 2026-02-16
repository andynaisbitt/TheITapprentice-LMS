// frontend/src/pages/user/XPLeaderboardPage.tsx
/**
 * XP Leaderboard Page
 * Shows top users ranked by total XP and level
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowLeft,
  Trophy,
  Medal,
  Crown,
  Flame,
  Star,
  TrendingUp,
  Users,
  Shield
} from 'lucide-react';
import { useAuth } from '../../state/contexts/AuthContext';
import { progressApi } from '../../plugins/shared/services/progressApi';
import type { XPLeaderboardEntry } from '../../plugins/shared/types';

export const XPLeaderboardPage: React.FC = () => {
  const { user } = useAuth();
  const [leaderboard, setLeaderboard] = useState<XPLeaderboardEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [userRank, setUserRank] = useState<number | null>(null);

  useEffect(() => {
    const fetchLeaderboard = async () => {
      setLoading(true);
      try {
        const data = await progressApi.getXPLeaderboard(100, 0);
        setLeaderboard(data);

        // Find current user's rank if they're in the top 100
        if (user) {
          const userEntry = data.find(entry => entry.user_id === user.id);
          if (userEntry) {
            setUserRank(userEntry.rank);
          }
        }
      } catch (error) {
        console.error('Failed to fetch leaderboard:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchLeaderboard();
  }, [user]);

  const getRankIcon = (rank: number) => {
    switch (rank) {
      case 1:
        return <Crown className="w-6 h-6 text-yellow-500" />;
      case 2:
        return <Medal className="w-6 h-6 text-gray-400" />;
      case 3:
        return <Medal className="w-6 h-6 text-orange-600" />;
      default:
        return null;
    }
  };

  const getRankBg = (rank: number) => {
    switch (rank) {
      case 1:
        return 'bg-gradient-to-r from-yellow-50 to-orange-50 dark:from-yellow-900/20 dark:to-orange-900/20 border-yellow-200 dark:border-yellow-800';
      case 2:
        return 'bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-800/50 dark:to-slate-800/50 border-gray-200 dark:border-gray-700';
      case 3:
        return 'bg-gradient-to-r from-orange-50 to-amber-50 dark:from-orange-900/20 dark:to-amber-900/20 border-orange-200 dark:border-orange-800';
      default:
        return 'bg-white dark:bg-gray-800 border-gray-100 dark:border-gray-700';
    }
  };

  const getLevelColor = (level: number) => {
    if (level >= 50) return 'text-purple-600 dark:text-purple-400';
    if (level >= 30) return 'text-blue-600 dark:text-blue-400';
    if (level >= 15) return 'text-green-600 dark:text-green-400';
    if (level >= 5) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  const formatXP = (xp: number) => {
    if (xp >= 1000000) return `${(xp / 1000000).toFixed(1)}M`;
    if (xp >= 1000) return `${(xp / 1000).toFixed(1)}K`;
    return xp.toString();
  };

  // Calculate some stats
  const totalUsers = leaderboard.length;
  const avgLevel = totalUsers > 0
    ? Math.round(leaderboard.reduce((sum, e) => sum + e.level, 0) / totalUsers)
    : 0;
  const totalXP = leaderboard.reduce((sum, e) => sum + e.total_xp, 0);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Back button */}
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Dashboard
        </Link>

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8"
        >
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl mb-4 shadow-lg">
            <Trophy className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            XP Leaderboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Top learners ranked by experience points
          </p>
        </motion.div>

        {/* Stats cards */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow text-center"
          >
            <Users className="w-6 h-6 text-blue-500 mx-auto mb-2" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{totalUsers}</div>
            <div className="text-sm text-gray-500">Active Learners</div>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow text-center"
          >
            <TrendingUp className="w-6 h-6 text-green-500 mx-auto mb-2" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">Lvl {avgLevel}</div>
            <div className="text-sm text-gray-500">Average Level</div>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow text-center"
          >
            <Star className="w-6 h-6 text-yellow-500 mx-auto mb-2" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{formatXP(totalXP)}</div>
            <div className="text-sm text-gray-500">Total XP Earned</div>
          </motion.div>
        </div>

        {/* User's rank (if on leaderboard) */}
        {userRank && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded-xl p-4 mb-6"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                  #{userRank}
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Your Rank</div>
                  <div className="text-sm text-gray-500">
                    {userRank <= 10
                      ? "You're in the top 10!"
                      : userRank <= 50
                        ? "You're in the top 50!"
                        : "Keep learning to climb higher!"}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Leaderboard list */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden"
        >
          {loading ? (
            <div className="text-center py-12 text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full mx-auto mb-4" />
              Loading leaderboard...
            </div>
          ) : leaderboard.length > 0 ? (
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {leaderboard.map((entry, idx) => (
                <motion.div
                  key={entry.user_id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.03 }}
                  className={`flex items-center justify-between p-4 border-l-4 ${getRankBg(entry.rank)} ${
                    user?.id === entry.user_id ? 'ring-2 ring-blue-500 ring-inset' : ''
                  }`}
                >
                  <div className="flex items-center gap-4">
                    <div className="w-12 flex justify-center">
                      {getRankIcon(entry.rank) || (
                        <span className="text-xl font-bold text-gray-400">
                          {entry.rank}
                        </span>
                      )}
                    </div>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
                        <Link
                          to={`/profile/${entry.username}`}
                          className="hover:text-blue-600 dark:hover:text-blue-400 hover:underline"
                        >
                          {entry.display_name || entry.username}
                        </Link>
                        {user?.id === entry.user_id && (
                          <span className="text-xs bg-blue-500 text-white px-2 py-0.5 rounded">You</span>
                        )}
                      </div>
                      <div className="text-sm text-gray-500 flex items-center gap-2">
                        <span className={`font-medium ${getLevelColor(entry.level)}`}>
                          Level {entry.level}
                        </span>
                        {entry.streak > 0 && (
                          <span className="flex items-center gap-1 text-orange-500">
                            <Flame className="w-3 h-3" />
                            {entry.streak} day streak
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-xl font-bold text-purple-600 dark:text-purple-400">
                      {formatXP(entry.total_xp)} XP
                    </div>
                    <div className="text-sm text-gray-500">
                      Total Experience
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              No entries yet. Start learning to make the leaderboard!
            </div>
          )}
        </motion.div>

        {/* Privacy notice for authenticated users */}
        {user && !userRank && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mt-6 bg-gray-50 dark:bg-gray-800/50 border border-gray-200 dark:border-gray-700 rounded-xl p-4"
          >
            <div className="flex items-start gap-3">
              <Shield className="w-5 h-5 text-gray-400 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Not seeing yourself on the leaderboard? Your privacy settings may be hiding your profile.
                  You can manage your leaderboard visibility in{' '}
                  <Link to="/settings" className="text-blue-600 dark:text-blue-400 hover:underline font-medium">
                    Settings
                  </Link>.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* Call to action for non-authenticated users */}
        {!user && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="mt-6 text-center"
          >
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Want to join the leaderboard?
            </p>
            <Link
              to="/register"
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 text-white rounded-lg font-medium hover:bg-purple-700 transition-colors"
            >
              <Star className="w-5 h-5" />
              Sign Up & Start Learning
            </Link>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default XPLeaderboardPage;
