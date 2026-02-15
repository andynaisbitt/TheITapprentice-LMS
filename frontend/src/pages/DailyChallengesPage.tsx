// src/pages/DailyChallengesPage.tsx
/**
 * Daily Challenges Page
 * Shows today's challenges, streak info, and challenge history link
 * Works for both authenticated users and guests
 */

import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Brain,
  Flame,
  Gift,
  ChevronRight,
  Trophy,
  Clock,
  Shield,
  Loader2,
  LogIn,
  Zap,
  CheckCircle,
  Target,
} from 'lucide-react';
import { useAuth } from '../state/contexts/AuthContext';
import { challengesApi } from '../plugins/shared/services/challengesApi';
import { StreakCounter } from '../plugins/shared/components/StreakCounter';
import type { DailyChallenge, ChallengeStreak } from '../plugins/shared/types';

const difficultyColors: Record<string, string> = {
  easy: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
  hard: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
};

const typeIcons: Record<string, string> = {
  quiz: '🧠',
  tutorial: '📖',
  course_section: '🎓',
  typing_game: '⌨️',
  typing_wpm: '⚡',
  xp_earn: '✨',
  login_streak: '🔥',
};

const DailyChallengesPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [challenges, setChallenges] = useState<DailyChallenge[]>([]);
  const [streakInfo, setStreakInfo] = useState<ChallengeStreak | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [claimingId, setClaimingId] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      if (!isAuthenticated) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const data = await challengesApi.getTodaysChallenges();
        setChallenges(data.challenges);
        setStreakInfo(data.streak_info);
      } catch (err: any) {
        console.error('Failed to load challenges:', err);
        setError('Failed to load challenges. Please try again.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [isAuthenticated]);

  const handleClaimReward = async (challengeId: string) => {
    try {
      setClaimingId(challengeId);
      const result = await challengesApi.claimReward(challengeId);
      // Update the challenge in state
      setChallenges(prev =>
        prev.map(c =>
          c.id === challengeId ? { ...c, is_claimed: true } : c
        )
      );
      // Update streak info if available
      if (streakInfo) {
        setStreakInfo(prev => prev ? { ...prev } : prev);
      }
    } catch (err: any) {
      console.error('Failed to claim reward:', err);
    } finally {
      setClaimingId(null);
    }
  };

  const completedCount = challenges.filter(c => c.is_completed).length;
  const totalCount = challenges.length;

  // Guest view
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
        <div className="max-w-4xl mx-auto px-4">
          {/* Header */}
          <div className="text-center mb-10">
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 rounded-full text-sm font-medium mb-4">
              <Brain className="w-4 h-4" />
              Daily Challenges
            </div>
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">
              Challenge Yourself Every Day
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
              Complete daily challenges to earn XP, build streaks, and unlock bonus rewards.
              The longer your streak, the bigger your XP multiplier!
            </p>
          </div>

          {/* How it works */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
            {[
              { icon: Target, title: 'Complete Tasks', desc: 'Take quizzes, finish tutorials, practice typing, and more.' },
              { icon: Flame, title: 'Build Streaks', desc: 'Complete at least one challenge daily to grow your streak.' },
              { icon: Zap, title: 'Earn Bonus XP', desc: 'Up to 100% bonus XP from consecutive day streaks!' },
            ].map((item, i) => (
              <motion.div
                key={item.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className="bg-white dark:bg-gray-800 rounded-xl p-6 text-center shadow-sm border border-gray-200 dark:border-gray-700"
              >
                <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                  <item.icon className="w-6 h-6 text-purple-600 dark:text-purple-400" />
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-2">{item.title}</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">{item.desc}</p>
              </motion.div>
            ))}
          </div>

          {/* CTA */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-gradient-to-br from-purple-600 to-indigo-700 rounded-2xl p-8 text-center"
          >
            <h2 className="text-2xl font-bold text-white mb-3">
              Sign up to start earning
            </h2>
            <p className="text-purple-200 mb-6">
              Create a free account to track your challenges, build streaks, and compete on the leaderboard.
            </p>
            <div className="flex items-center justify-center gap-4">
              <Link
                to="/register"
                className="inline-flex items-center gap-2 px-6 py-3 bg-white text-purple-700 rounded-xl font-semibold hover:bg-purple-50 transition-colors"
              >
                <LogIn className="w-5 h-5" />
                Create Account
              </Link>
              <Link
                to="/login"
                className="inline-flex items-center gap-2 px-6 py-3 bg-white/10 text-white rounded-xl font-semibold hover:bg-white/20 transition-colors"
              >
                Sign In
              </Link>
            </div>
          </motion.div>
        </div>
      </div>
    );
  }

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin text-purple-600 mx-auto mb-3" />
          <p className="text-gray-500 dark:text-gray-400">Loading challenges...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-600 dark:text-red-400 mb-4">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
              <Brain className="w-8 h-8 text-purple-600" />
              Daily Challenges
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Complete challenges to earn XP and build your streak
            </p>
          </div>
          <Link
            to="/challenges/history"
            className="inline-flex items-center gap-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors text-sm font-medium"
          >
            <Clock className="w-4 h-4" />
            Challenge History
            <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        {/* Streak Counter */}
        {streakInfo && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6"
          >
            <StreakCounter
              streak={streakInfo.current_streak}
              longestStreak={streakInfo.longest_streak}
              showLongest
            />

            {/* Streak bonus info */}
            {streakInfo.current_bonus_percent > 0 && (
              <div className="mt-3 flex items-center gap-2 text-sm text-amber-600 dark:text-amber-400">
                <Zap className="w-4 h-4" />
                <span>+{streakInfo.current_bonus_percent}% XP bonus from your streak!</span>
              </div>
            )}

            {/* Freeze token info */}
            {streakInfo.freeze_tokens > 0 && (
              <div className="mt-2 flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400">
                <Shield className="w-4 h-4" />
                <span>{streakInfo.freeze_tokens} freeze token{streakInfo.freeze_tokens !== 1 ? 's' : ''} available</span>
              </div>
            )}

            {/* Streak at risk warning */}
            {streakInfo.streak_at_risk && (
              <div className="mt-2 flex items-center gap-2 text-sm text-red-600 dark:text-red-400 font-medium">
                <Flame className="w-4 h-4" />
                <span>
                  Your streak is at risk! Complete a challenge or use a freeze token.
                  {streakInfo.hours_remaining != null && ` ${Math.round(streakInfo.hours_remaining)}h remaining.`}
                </span>
              </div>
            )}
          </motion.div>
        )}

        {/* Progress summary */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 mb-6 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Today's Progress
            </span>
            <span className="text-sm font-bold text-purple-600 dark:text-purple-400">
              {completedCount}/{totalCount} completed
            </span>
          </div>
          <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: totalCount > 0 ? `${(completedCount / totalCount) * 100}%` : '0%' }}
              className="h-full bg-gradient-to-r from-purple-500 to-indigo-600 rounded-full"
              transition={{ duration: 0.5 }}
            />
          </div>
        </div>

        {/* Challenges List */}
        {challenges.length === 0 ? (
          <div className="bg-white dark:bg-gray-800 rounded-xl p-8 text-center border border-gray-200 dark:border-gray-700">
            <Brain className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              No challenges today
            </h3>
            <p className="text-gray-500 dark:text-gray-400">
              Check back tomorrow for new challenges!
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {challenges.map((challenge, index) => (
              <motion.div
                key={challenge.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className={`bg-white dark:bg-gray-800 rounded-xl p-5 border transition-all ${
                  challenge.is_completed
                    ? 'border-green-200 dark:border-green-800'
                    : 'border-gray-200 dark:border-gray-700 hover:border-purple-300 dark:hover:border-purple-700'
                }`}
              >
                <div className="flex items-start gap-4">
                  {/* Icon */}
                  <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-xl flex-shrink-0 ${
                    challenge.is_completed
                      ? 'bg-green-100 dark:bg-green-900/30'
                      : 'bg-purple-100 dark:bg-purple-900/30'
                  }`}>
                    {challenge.is_completed ? (
                      <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
                    ) : (
                      <span>{typeIcons[challenge.challenge_type] || '🎯'}</span>
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className={`font-semibold ${
                        challenge.is_completed
                          ? 'text-green-700 dark:text-green-400'
                          : 'text-gray-900 dark:text-white'
                      }`}>
                        {challenge.title}
                      </h3>
                      <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${difficultyColors[challenge.difficulty]}`}>
                        {challenge.difficulty}
                      </span>
                    </div>

                    {challenge.description && (
                      <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                        {challenge.description}
                      </p>
                    )}

                    {/* Progress bar */}
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            challenge.is_completed
                              ? 'bg-green-500'
                              : 'bg-purple-500'
                          }`}
                          style={{ width: `${Math.min(challenge.progress_percent, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                        {challenge.current_progress}/{challenge.target_count}
                      </span>
                    </div>
                  </div>

                  {/* XP Reward / Claim */}
                  <div className="flex-shrink-0 text-right">
                    {challenge.is_completed && !challenge.is_claimed ? (
                      <button
                        onClick={() => handleClaimReward(challenge.id)}
                        disabled={claimingId === challenge.id}
                        className="inline-flex items-center gap-1.5 px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-500 text-white rounded-lg font-medium text-sm hover:from-amber-600 hover:to-orange-600 transition-all disabled:opacity-50"
                      >
                        <Gift className="w-4 h-4" />
                        {claimingId === challenge.id ? 'Claiming...' : 'Claim'}
                      </button>
                    ) : challenge.is_claimed ? (
                      <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400 text-sm font-medium">
                        <CheckCircle className="w-4 h-4" />
                        Claimed
                      </span>
                    ) : (
                      <div className="text-right">
                        <div className="text-sm font-bold text-purple-600 dark:text-purple-400">
                          +{challenge.potential_xp} XP
                        </div>
                        {challenge.streak_bonus_percent > 0 && (
                          <div className="text-xs text-amber-600 dark:text-amber-400">
                            incl. {challenge.streak_bonus_percent}% bonus
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}

        {/* Quick Links */}
        <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Link
            to="/leaderboard"
            className="flex items-center gap-3 p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-amber-300 dark:hover:border-amber-700 transition-colors"
          >
            <Trophy className="w-5 h-5 text-amber-500" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">Leaderboard</div>
              <div className="text-sm text-gray-500 dark:text-gray-400">See top performers</div>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400 ml-auto" />
          </Link>
          <Link
            to="/challenges/history"
            className="flex items-center gap-3 p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-purple-300 dark:hover:border-purple-700 transition-colors"
          >
            <Clock className="w-5 h-5 text-purple-500" />
            <div>
              <div className="font-medium text-gray-900 dark:text-white">Challenge History</div>
              <div className="text-sm text-gray-500 dark:text-gray-400">View past completions</div>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400 ml-auto" />
          </Link>
        </div>
      </div>
    </div>
  );
};

export default DailyChallengesPage;
