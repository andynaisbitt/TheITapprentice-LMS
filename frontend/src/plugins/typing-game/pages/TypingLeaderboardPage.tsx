// frontend/src/plugins/typing-game/pages/TypingLeaderboardPage.tsx
/**
 * Typing game leaderboard page
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, Trophy, Medal, Crown, Zap, Target } from 'lucide-react';
import { useAuth } from '../../../state/contexts/AuthContext';
import { typingGameApi } from '../services/typingGameApi';
import type { LeaderboardEntry, LeaderboardResponse } from '../types';

type LeaderboardType = 'wpm' | 'accuracy' | 'pvp';

export const TypingLeaderboardPage: React.FC = () => {
  const { user } = useAuth();
  const [leaderboardType, setLeaderboardType] = useState<LeaderboardType>('wpm');
  const [leaderboard, setLeaderboard] = useState<LeaderboardResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLeaderboard = async () => {
      setLoading(true);
      try {
        const data = await typingGameApi.getLeaderboard(leaderboardType, 100);
        setLeaderboard(data);
      } catch (error) {
        console.error('Failed to fetch leaderboard:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchLeaderboard();
  }, [leaderboardType]);

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

  const tabs = [
    { id: 'wpm' as LeaderboardType, label: 'Best WPM', icon: Zap },
    { id: 'accuracy' as LeaderboardType, label: 'Accuracy', icon: Target },
    { id: 'pvp' as LeaderboardType, label: 'PVP Rating', icon: Trophy }
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Back button */}
        <Link
          to="/games/typing"
          className="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Typing Games
        </Link>

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8"
        >
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-yellow-500 to-orange-600 rounded-2xl mb-4 shadow-lg">
            <Trophy className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Leaderboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Top typists ranked by performance
          </p>
        </motion.div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 bg-white dark:bg-gray-800 rounded-xl p-1 shadow">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setLeaderboardType(tab.id)}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all ${
                leaderboardType === tab.id
                  ? 'bg-blue-500 text-white shadow-md'
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* User's rank (if on leaderboard) */}
        {leaderboard?.user_rank && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded-xl p-4 mb-6"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                  #{leaderboard.user_rank}
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Your Rank</div>
                  <div className="text-sm text-gray-500">Keep playing to climb higher!</div>
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
            <div className="text-center py-12 text-gray-500">Loading leaderboard...</div>
          ) : leaderboard && leaderboard.entries.length > 0 ? (
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {leaderboard.entries.map((entry, idx) => (
                <motion.div
                  key={entry.user_id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.05 }}
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
                        {entry.display_name || entry.username}
                        {user?.id === entry.user_id && (
                          <span className="text-xs bg-blue-500 text-white px-2 py-0.5 rounded">You</span>
                        )}
                      </div>
                      <div className="text-sm text-gray-500">
                        {entry.games_played} games played
                      </div>
                    </div>
                  </div>

                  <div className="text-right">
                    {leaderboardType === 'wpm' && (
                      <>
                        <div className="text-xl font-bold text-blue-600 dark:text-blue-400">
                          {entry.best_wpm} WPM
                        </div>
                        <div className="text-sm text-gray-500">
                          Avg: {entry.avg_wpm.toFixed(1)} WPM
                        </div>
                      </>
                    )}
                    {leaderboardType === 'accuracy' && (
                      <>
                        <div className="text-xl font-bold text-green-600 dark:text-green-400">
                          {entry.avg_accuracy.toFixed(1)}%
                        </div>
                        <div className="text-sm text-gray-500">
                          Best: {entry.best_wpm} WPM
                        </div>
                      </>
                    )}
                    {leaderboardType === 'pvp' && (
                      <>
                        <div className="text-xl font-bold text-purple-600 dark:text-purple-400">
                          {entry.best_wpm} Rating
                        </div>
                        <div className="text-sm text-gray-500">
                          {entry.games_played} matches
                        </div>
                      </>
                    )}
                  </div>
                </motion.div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              No entries yet. Be the first to make the leaderboard!
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
};

export default TypingLeaderboardPage;
