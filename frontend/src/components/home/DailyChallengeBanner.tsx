// src/components/home/DailyChallengeBanner.tsx
/**
 * Daily Challenges Banner - Homepage widget showing today's challenges
 * Shows progress for authenticated users, CTA for guests
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Flame,
  Target,
  Gift,
  ChevronRight,
  Sparkles,
  Trophy,
  Clock,
  Loader2,
} from 'lucide-react';
import { useAuth } from '../../state/contexts/AuthContext';
import { challengesApi } from '../../plugins/shared/services/challengesApi';
import type { DailyChallenge, ChallengeStreak } from '../../plugins/shared/types';
import { DIFFICULTY_COLORS } from '../../plugins/shared/types';

interface ChallengesState {
  challenges: DailyChallenge[];
  streak: ChallengeStreak | null;
  loading: boolean;
  error: string | null;
}

export const DailyChallengeBanner: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [state, setState] = useState<ChallengesState>({
    challenges: [],
    streak: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!isAuthenticated) {
      setState((prev) => ({ ...prev, loading: false }));
      return;
    }

    const fetchChallenges = async () => {
      try {
        const response = await challengesApi.getTodaysChallenges();
        setState({
          challenges: response.challenges,
          streak: response.streak_info,
          loading: false,
          error: null,
        });
      } catch {
        setState((prev) => ({
          ...prev,
          loading: false,
          error: 'Failed to load challenges',
        }));
      }
    };

    fetchChallenges();
  }, [isAuthenticated]);

  // Calculate hours remaining until reset (midnight UTC)
  const getHoursRemaining = () => {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCHours(24, 0, 0, 0);
    const diff = tomorrow.getTime() - now.getTime();
    return Math.floor(diff / (1000 * 60 * 60));
  };

  const completedCount = state.challenges.filter((c) => c.is_completed).length;
  const claimedCount = state.challenges.filter((c) => c.is_claimed).length;
  const totalXP = state.challenges.reduce((sum, c) => sum + c.potential_xp, 0);

  // Guest view - CTA to sign up
  if (!isAuthenticated) {
    return (
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-orange-500 via-red-500 to-pink-500 p-6 sm:p-8"
        >
          {/* Background pattern */}
          <div className="absolute inset-0 opacity-10">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_50%,white_0%,transparent_50%)]" />
          </div>

          <div className="relative flex flex-col sm:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-white/20 backdrop-blur-sm rounded-xl">
                <Flame className="w-8 h-8 text-white" />
              </div>
              <div>
                <h3 className="text-xl sm:text-2xl font-bold text-white mb-1">
                  Daily Challenges
                </h3>
                <p className="text-orange-100 text-sm sm:text-base">
                  Complete challenges daily to earn XP and build your streak!
                </p>
              </div>
            </div>

            <Link
              to="/register"
              className="group inline-flex items-center gap-2 px-6 py-3 bg-white text-orange-600 rounded-lg font-semibold hover:bg-orange-50 transition-all shadow-lg"
            >
              <span>Start Learning</span>
              <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </Link>
          </div>
        </motion.div>
      </section>
    );
  }

  // Loading state
  if (state.loading) {
    return (
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="rounded-2xl bg-gray-100 dark:bg-gray-800 p-8 flex items-center justify-center">
          <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
        </div>
      </section>
    );
  }

  // Error state
  if (state.error) {
    return null; // Silently hide on error
  }

  // Authenticated user view
  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="rounded-2xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shadow-lg overflow-hidden"
      >
        {/* Header */}
        <div className="bg-gradient-to-r from-orange-500 via-red-500 to-pink-500 px-6 py-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-white/20 backdrop-blur-sm rounded-lg">
                <Target className="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 className="text-lg sm:text-xl font-bold text-white">
                  Today's Challenges
                </h3>
                <div className="flex items-center gap-4 text-sm text-orange-100">
                  <span className="flex items-center gap-1">
                    <Clock className="w-4 h-4" />
                    {getHoursRemaining()}h remaining
                  </span>
                  {state.streak && state.streak.current_streak > 0 && (
                    <span className="flex items-center gap-1">
                      <Flame className="w-4 h-4 text-yellow-300" />
                      {state.streak.current_streak} day streak
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {/* Progress indicator */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-white/20 backdrop-blur-sm rounded-lg">
                <span className="text-sm font-medium text-white">
                  {completedCount}/{state.challenges.length} Done
                </span>
              </div>
              {/* XP available */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-white/20 backdrop-blur-sm rounded-lg">
                <Sparkles className="w-4 h-4 text-yellow-300" />
                <span className="text-sm font-medium text-white">
                  {totalXP} XP
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Challenges Grid */}
        <div className="p-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {state.challenges.map((challenge) => (
              <ChallengeCard key={challenge.id} challenge={challenge} />
            ))}
          </div>

          {/* Streak bonus info */}
          {state.streak && state.streak.current_bonus_percent > 0 && (
            <div className="mt-4 flex items-center justify-center gap-2 text-sm text-gray-600 dark:text-gray-400">
              <Trophy className="w-4 h-4 text-yellow-500" />
              <span>
                Your {state.streak.current_streak}-day streak gives you{' '}
                <strong className="text-green-600 dark:text-green-400">
                  +{state.streak.current_bonus_percent}% bonus XP
                </strong>
              </span>
            </div>
          )}

          {/* All completed message */}
          {completedCount === state.challenges.length && claimedCount === state.challenges.length && (
            <div className="mt-4 text-center py-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <p className="text-green-700 dark:text-green-400 font-medium flex items-center justify-center gap-2">
                <Gift className="w-5 h-5" />
                All challenges complete! Come back tomorrow for more.
              </p>
            </div>
          )}
        </div>
      </motion.div>
    </section>
  );
};

// Individual challenge card
interface ChallengeCardProps {
  challenge: DailyChallenge;
}

const ChallengeCard: React.FC<ChallengeCardProps> = ({ challenge }) => {
  const [claiming, setClaiming] = useState(false);
  const [claimed, setClaimed] = useState(challenge.is_claimed);
  const [xpEarned, setXpEarned] = useState<number | null>(null);

  const handleClaim = async () => {
    if (claiming || claimed || !challenge.is_completed) return;

    setClaiming(true);
    try {
      const result = await challengesApi.claimReward(challenge.id);
      setClaimed(true);
      setXpEarned(result.total_xp);
    } catch {
      // Handle error silently
    } finally {
      setClaiming(false);
    }
  };

  const difficultyClass = DIFFICULTY_COLORS[challenge.difficulty];

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`relative p-4 rounded-xl border-2 transition-all ${
        claimed
          ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700'
          : challenge.is_completed
          ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-300 dark:border-yellow-700'
          : 'bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600'
      }`}
    >
      {/* Difficulty badge */}
      <div className="flex items-start justify-between mb-3">
        <span
          className={`px-2 py-0.5 text-xs font-medium rounded-full border ${difficultyClass}`}
        >
          {challenge.difficulty}
        </span>
        {claimed && xpEarned && (
          <motion.span
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-xs font-bold text-green-600 dark:text-green-400"
          >
            +{xpEarned} XP!
          </motion.span>
        )}
      </div>

      {/* Title and description */}
      <h4 className="font-semibold text-gray-900 dark:text-white mb-1">
        {challenge.title}
      </h4>
      {challenge.description && (
        <p className="text-xs text-gray-600 dark:text-gray-400 mb-3">
          {challenge.description}
        </p>
      )}

      {/* Progress bar */}
      <div className="mb-3">
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="text-gray-600 dark:text-gray-400">Progress</span>
          <span className="font-medium text-gray-900 dark:text-white">
            {challenge.current_progress}/{challenge.target_count}
          </span>
        </div>
        <div className="h-2 bg-gray-200 dark:bg-gray-600 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${challenge.progress_percent}%` }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className={`h-full rounded-full ${
              challenge.is_completed
                ? 'bg-green-500'
                : 'bg-gradient-to-r from-orange-400 to-pink-500'
            }`}
          />
        </div>
      </div>

      {/* Reward and claim button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 text-sm">
          <Sparkles className="w-4 h-4 text-yellow-500" />
          <span className="font-medium text-gray-700 dark:text-gray-300">
            {challenge.potential_xp} XP
          </span>
          {challenge.streak_bonus_percent > 0 && (
            <span className="text-xs text-green-600 dark:text-green-400">
              (+{challenge.streak_bonus_percent}%)
            </span>
          )}
        </div>

        {challenge.is_completed && !claimed && (
          <button
            onClick={handleClaim}
            disabled={claiming}
            className="px-3 py-1.5 bg-gradient-to-r from-orange-500 to-pink-500 text-white text-sm font-medium rounded-lg hover:from-orange-600 hover:to-pink-600 disabled:opacity-50 transition-all flex items-center gap-1"
          >
            {claiming ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Gift className="w-4 h-4" />
            )}
            Claim
          </button>
        )}

        {claimed && (
          <span className="px-3 py-1.5 bg-green-100 dark:bg-green-800/30 text-green-700 dark:text-green-400 text-sm font-medium rounded-lg flex items-center gap-1">
            <Trophy className="w-4 h-4" />
            Claimed
          </span>
        )}
      </div>
    </motion.div>
  );
};

export default DailyChallengeBanner;
