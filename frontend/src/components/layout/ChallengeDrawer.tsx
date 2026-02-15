// src/components/layout/ChallengeDrawer.tsx
/**
 * Challenge Drawer - Slide-out panel showing daily challenges
 * Accessible from header on every page
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  X,
  Flame,
  Target,
  Gift,
  Sparkles,
  Trophy,
  Clock,
  Loader2,
  ChevronRight,
  Zap,
} from 'lucide-react';
import { useAuth } from '../../state/contexts/AuthContext';
import { challengesApi } from '../../plugins/shared/services/challengesApi';
import type { DailyChallenge, ChallengeStreak } from '../../plugins/shared/types';
import { DIFFICULTY_COLORS } from '../../plugins/shared/types';

interface ChallengeDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ChallengesState {
  challenges: DailyChallenge[];
  streak: ChallengeStreak | null;
  loading: boolean;
  error: string | null;
}

export const ChallengeDrawer: React.FC<ChallengeDrawerProps> = ({ isOpen, onClose }) => {
  const { isAuthenticated } = useAuth();
  const [state, setState] = useState<ChallengesState>({
    challenges: [],
    streak: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    if (!isOpen) return;

    if (!isAuthenticated) {
      setState((prev) => ({ ...prev, loading: false }));
      return;
    }

    const fetchChallenges = async () => {
      setState((prev) => ({ ...prev, loading: true }));
      try {
        const response = await challengesApi.getTodaysChallenges();
        setState({
          challenges: Array.isArray(response?.challenges) ? response.challenges : [],
          streak: response?.streak_info || null,
          loading: false,
          error: null,
        });
      } catch {
        setState((prev) => ({
          ...prev,
          challenges: [],
          loading: false,
          error: 'Failed to load challenges',
        }));
      }
    };

    fetchChallenges();
  }, [isOpen, isAuthenticated]);

  // Calculate hours remaining until reset (midnight UTC)
  const getHoursRemaining = () => {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCHours(24, 0, 0, 0);
    const diff = tomorrow.getTime() - now.getTime();
    return Math.floor(diff / (1000 * 60 * 60));
  };

  const completedCount = state.challenges.filter((c) => c.is_completed).length;
  const totalXP = state.challenges.reduce((sum, c) => sum + c.potential_xp, 0);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-[60]"
          />

          {/* Drawer */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            className="fixed right-0 top-0 h-full w-full max-w-md bg-white dark:bg-slate-900 shadow-2xl z-[61] flex flex-col"
          >
            {/* Header */}
            <div className="bg-gradient-to-r from-orange-500 via-red-500 to-pink-500 px-5 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-white/20 backdrop-blur-sm rounded-xl flex items-center justify-center">
                    <Target className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-white">Daily Challenges</h2>
                    <div className="flex items-center gap-3 text-sm text-orange-100">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" />
                        {getHoursRemaining()}h left
                      </span>
                      {state.streak && state.streak.current_streak > 0 && (
                        <span className="flex items-center gap-1">
                          <Flame className="w-3.5 h-3.5 text-yellow-300" />
                          {state.streak.current_streak} day streak
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-2 hover:bg-white/20 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-white" />
                </button>
              </div>

              {/* Progress bar */}
              {isAuthenticated && state.challenges.length > 0 && (
                <div className="mt-4">
                  <div className="flex items-center justify-between text-xs text-white/80 mb-1.5">
                    <span>{completedCount}/{state.challenges.length} completed</span>
                    <span className="flex items-center gap-1">
                      <Sparkles className="w-3 h-3" />
                      {totalXP} XP available
                    </span>
                  </div>
                  <div className="h-2 bg-white/20 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(completedCount / state.challenges.length) * 100}%` }}
                      transition={{ duration: 0.5 }}
                      className="h-full bg-white rounded-full"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-5">
              {!isAuthenticated ? (
                /* Guest View */
                <div className="text-center py-8">
                  <div className="w-16 h-16 bg-orange-100 dark:bg-orange-900/30 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Flame className="w-8 h-8 text-orange-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                    Start Your Journey
                  </h3>
                  <p className="text-slate-600 dark:text-slate-400 mb-6 text-sm">
                    Complete daily challenges to earn XP, build streaks, and unlock achievements!
                  </p>
                  <Link
                    to="/register"
                    onClick={onClose}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-orange-500 to-pink-500 text-white rounded-xl font-semibold hover:from-orange-600 hover:to-pink-600 transition-all"
                  >
                    <Zap className="w-4 h-4" />
                    Get Started Free
                  </Link>
                </div>
              ) : state.loading ? (
                /* Loading */
                <div className="flex items-center justify-center h-48">
                  <Loader2 className="w-8 h-8 animate-spin text-slate-400" />
                </div>
              ) : state.error ? (
                /* Error */
                <div className="text-center py-8">
                  <p className="text-slate-500 dark:text-slate-400">{state.error}</p>
                </div>
              ) : state.challenges.length === 0 ? (
                /* No challenges */
                <div className="text-center py-8">
                  <div className="w-16 h-16 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Target className="w-8 h-8 text-slate-400" />
                  </div>
                  <p className="text-slate-500 dark:text-slate-400">
                    No challenges available today. Check back soon!
                  </p>
                </div>
              ) : (
                /* Challenge Cards */
                <div className="space-y-3">
                  {state.challenges.map((challenge) => (
                    <ChallengeCard key={challenge.id} challenge={challenge} />
                  ))}

                  {/* Streak bonus info */}
                  {state.streak && state.streak.current_bonus_percent > 0 && (
                    <div className="mt-4 p-3 bg-gradient-to-r from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20 rounded-xl border border-amber-200 dark:border-amber-800">
                      <div className="flex items-center gap-2 text-sm">
                        <Trophy className="w-4 h-4 text-amber-500" />
                        <span className="text-amber-800 dark:text-amber-300">
                          <strong>+{state.streak.current_bonus_percent}% XP Bonus</strong> from your {state.streak.current_streak}-day streak!
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Footer */}
            {isAuthenticated && (
              <div className="p-4 border-t border-slate-200 dark:border-slate-800">
                <Link
                  to="/dashboard"
                  onClick={onClose}
                  className="flex items-center justify-center gap-2 w-full px-4 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-xl text-slate-700 dark:text-slate-300 font-medium transition-colors"
                >
                  View Full Dashboard
                  <ChevronRight className="w-4 h-4" />
                </Link>
              </div>
            )}
          </motion.div>
        </>
      )}
    </AnimatePresence>
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
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`p-4 rounded-xl border-2 transition-all ${
        claimed
          ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
          : challenge.is_completed
          ? 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800'
          : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-2">
        <span
          className={`px-2 py-0.5 text-xs font-medium rounded-full border ${difficultyClass}`}
        >
          {challenge.difficulty}
        </span>
        {claimed && xpEarned && (
          <motion.span
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-xs font-bold text-green-600 dark:text-green-400"
          >
            +{xpEarned} XP!
          </motion.span>
        )}
      </div>

      {/* Title */}
      <h4 className="font-semibold text-slate-900 dark:text-white mb-1">
        {challenge.title}
      </h4>
      {challenge.description && (
        <p className="text-xs text-slate-600 dark:text-slate-400 mb-3">
          {challenge.description}
        </p>
      )}

      {/* Progress bar */}
      <div className="mb-3">
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="text-slate-500 dark:text-slate-400">Progress</span>
          <span className="font-medium text-slate-700 dark:text-slate-300">
            {challenge.current_progress}/{challenge.target_count}
          </span>
        </div>
        <div className="h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${challenge.progress_percent}%` }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className={`h-full rounded-full ${
              challenge.is_completed
                ? 'bg-green-500'
                : 'bg-gradient-to-r from-orange-400 to-pink-500'
            }`}
          />
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 text-sm">
          <Sparkles className="w-4 h-4 text-amber-500" />
          <span className="font-medium text-slate-700 dark:text-slate-300">
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
            className="px-3 py-1.5 bg-gradient-to-r from-orange-500 to-pink-500 text-white text-sm font-medium rounded-lg hover:from-orange-600 hover:to-pink-600 disabled:opacity-50 transition-all flex items-center gap-1.5"
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
            Done
          </span>
        )}
      </div>
    </motion.div>
  );
};

export default ChallengeDrawer;
