// src/components/home/LeaderboardPreview.tsx
/**
 * Leaderboard Preview Widget - Homepage component showing top learners
 * Displays top 5 users by XP with social proof and CTA
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Trophy,
  Crown,
  Medal,
  Flame,
  ChevronRight,
  Loader2,
  Star,
  Users,
} from 'lucide-react';
import { progressApi } from '../../plugins/shared/services/progressApi';
import type { XPLeaderboardEntry } from '../../plugins/shared/types';
import { useAuth } from '../../state/contexts/AuthContext';

const LeaderboardPreview: React.FC = () => {
  const { user } = useAuth();
  const [leaderboard, setLeaderboard] = useState<XPLeaderboardEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLeaderboard = async () => {
      try {
        const data = await progressApi.getXPLeaderboard(5, 0);
        // Defensive check: ensure data is an array
        setLeaderboard(Array.isArray(data) ? data : []);
      } catch (error) {
        console.error('Failed to load leaderboard preview:', error);
        setLeaderboard([]); // Ensure empty array on error
      } finally {
        setLoading(false);
      }
    };
    fetchLeaderboard();
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

  if (leaderboard.length === 0) {
    return null; // Hide if no entries
  }

  const formatXP = (xp: number | undefined | null) => {
    if (xp == null) return '0';
    if (xp >= 1000000) return `${(xp / 1000000).toFixed(1)}M`;
    if (xp >= 1000) return `${(xp / 1000).toFixed(1)}K`;
    return xp.toString();
  };

  const getRankIcon = (rank: number) => {
    switch (rank) {
      case 1:
        return <Crown className="w-5 h-5 text-yellow-500" />;
      case 2:
        return <Medal className="w-5 h-5 text-gray-400" />;
      case 3:
        return <Medal className="w-5 h-5 text-orange-500" />;
      default:
        return <span className="text-sm font-bold text-gray-400">#{rank}</span>;
    }
  };

  const getRankStyles = (rank: number) => {
    switch (rank) {
      case 1:
        return 'bg-gradient-to-r from-yellow-50 to-amber-50 dark:from-yellow-900/20 dark:to-amber-900/20 border-yellow-200 dark:border-yellow-700';
      case 2:
        return 'bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-800/50 dark:to-slate-800/50 border-gray-200 dark:border-gray-600';
      case 3:
        return 'bg-gradient-to-r from-orange-50 to-amber-50 dark:from-orange-900/20 dark:to-amber-900/20 border-orange-200 dark:border-orange-700';
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

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Trophy className="w-7 h-7 text-yellow-500" />
            <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
              Top Learners
            </h2>
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Join our community of dedicated learners
          </p>
        </div>

        <Link
          to="/leaderboard"
          className="hidden sm:flex items-center gap-2 text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 font-medium"
        >
          View full leaderboard
          <ChevronRight className="w-5 h-5" />
        </Link>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Leaderboard List */}
        <div className="lg:col-span-2">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden border border-gray-100 dark:border-gray-700">
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {leaderboard.map((entry, idx) => (
                <motion.div
                  key={entry.user_id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: idx * 0.1 }}
                  className={`flex items-center justify-between p-4 border-l-4 transition-all hover:scale-[1.01] ${getRankStyles(entry.rank)} ${
                    user?.id === entry.user_id ? 'ring-2 ring-purple-500 ring-inset' : ''
                  }`}
                >
                  <div className="flex items-center gap-4">
                    {/* Rank */}
                    <div className="w-10 flex justify-center">
                      {getRankIcon(entry.rank)}
                    </div>

                    {/* User info */}
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
                        <Link
                          to={`/profile/${entry.username}`}
                          className="hover:text-purple-600 dark:hover:text-purple-400 hover:underline"
                        >
                          {entry.display_name || entry.username}
                        </Link>
                        {user?.id === entry.user_id && (
                          <span className="text-xs bg-purple-500 text-white px-2 py-0.5 rounded">
                            You
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <span className={`font-medium ${getLevelColor(entry.level)}`}>
                          Level {entry.level}
                        </span>
                        {entry.streak > 0 && (
                          <span className="flex items-center gap-1 text-orange-500">
                            <Flame className="w-3 h-3" />
                            {entry.streak}d
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* XP */}
                  <div className="text-right">
                    <div className="font-bold text-purple-600 dark:text-purple-400">
                      {formatXP(entry.total_xp)} XP
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* CTA Card */}
        <div className="lg:col-span-1">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.3 }}
            className="bg-gradient-to-br from-purple-600 via-indigo-600 to-blue-700 rounded-xl shadow-lg p-6 text-white h-full flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Star className="w-6 h-6 text-yellow-300" />
                <h3 className="text-xl font-bold">Earn XP & Level Up</h3>
              </div>
              <ul className="space-y-3 text-purple-100 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-yellow-300">✓</span>
                  Complete tutorials & courses
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-yellow-300">✓</span>
                  Take quizzes to test your knowledge
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-yellow-300">✓</span>
                  Practice typing to boost your speed
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-yellow-300">✓</span>
                  Maintain streaks for bonus XP
                </li>
              </ul>
            </div>

            <div className="mt-6 space-y-3">
              {!user ? (
                <Link
                  to="/register"
                  className="block w-full text-center px-4 py-3 bg-white text-purple-700 rounded-lg font-semibold hover:bg-purple-50 transition-colors"
                >
                  Join the Leaderboard
                </Link>
              ) : (
                <Link
                  to="/dashboard"
                  className="block w-full text-center px-4 py-3 bg-white/20 text-white border border-white/30 rounded-lg font-medium hover:bg-white/30 transition-colors"
                >
                  View Your Progress
                </Link>
              )}

              <div className="flex items-center justify-center gap-2 text-purple-200 text-sm">
                <Users className="w-4 h-4" />
                <span>{leaderboard.length > 0 ? `${leaderboard.length}+ active learners` : 'Join our community'}</span>
              </div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Mobile link */}
      <div className="mt-6 sm:hidden text-center">
        <Link
          to="/leaderboard"
          className="inline-flex items-center gap-2 text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 font-medium"
        >
          View full leaderboard
          <ChevronRight className="w-5 h-5" />
        </Link>
      </div>
    </section>
  );
};

export default LeaderboardPreview;
