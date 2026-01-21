// src/plugins/shared/components/StreakFreezeModal.tsx
/**
 * Streak Freeze Modal
 * Shows when user's streak is at risk and offers freeze token protection
 */

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Flame,
  Shield,
  X,
  AlertTriangle,
  Clock,
  Sparkles,
  Loader2,
  CheckCircle,
} from 'lucide-react';
import { challengesApi } from '../services/challengesApi';
import type { ChallengeStreak } from '../types';

interface StreakFreezeModalProps {
  isOpen: boolean;
  onClose: () => void;
  streakInfo: ChallengeStreak;
  onStreakProtected?: (newStreak: ChallengeStreak) => void;
}

export const StreakFreezeModal: React.FC<StreakFreezeModalProps> = ({
  isOpen,
  onClose,
  streakInfo,
  onStreakProtected,
}) => {
  const [using, setUsing] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleUseFreezeToken = async () => {
    if (streakInfo.freeze_tokens <= 0) return;

    setUsing(true);
    setError(null);

    try {
      const result = await challengesApi.useFreezeToken();

      if (result.success) {
        setSuccess(true);
        // Update parent with new streak info
        onStreakProtected?.({
          ...streakInfo,
          freeze_tokens: result.freeze_tokens_remaining,
          streak_protected_until: result.protected_until,
          streak_at_risk: false,
        });

        // Auto-close after 2 seconds
        setTimeout(() => {
          onClose();
        }, 2000);
      }
    } catch (err) {
      setError('Failed to use freeze token. Please try again.');
      console.error(err);
    } finally {
      setUsing(false);
    }
  };

  const formatTimeRemaining = () => {
    if (!streakInfo.hours_remaining) return 'soon';
    const hours = Math.floor(streakInfo.hours_remaining);
    const minutes = Math.floor((streakInfo.hours_remaining - hours) * 60);
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={(e) => e.target === e.currentTarget && onClose()}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-md overflow-hidden"
          >
            {/* Header */}
            <div className="relative bg-gradient-to-r from-orange-500 via-red-500 to-pink-500 px-6 py-8 text-center">
              <button
                onClick={onClose}
                className="absolute top-4 right-4 p-2 text-white/80 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>

              <div className="inline-flex items-center justify-center w-16 h-16 bg-white/20 backdrop-blur-sm rounded-full mb-4">
                {success ? (
                  <CheckCircle className="w-8 h-8 text-white" />
                ) : (
                  <AlertTriangle className="w-8 h-8 text-white" />
                )}
              </div>

              <h2 className="text-2xl font-bold text-white mb-2">
                {success ? 'Streak Protected!' : 'Streak At Risk!'}
              </h2>

              {!success && (
                <p className="text-white/90">
                  Your <strong>{streakInfo.current_streak}-day streak</strong> will end
                  {streakInfo.hours_remaining
                    ? ` in ${formatTimeRemaining()}`
                    : ' soon'}
                </p>
              )}
            </div>

            {/* Content */}
            <div className="p-6">
              {success ? (
                <div className="text-center py-4">
                  <div className="flex items-center justify-center gap-2 text-green-600 dark:text-green-400 mb-4">
                    <Shield className="w-6 h-6" />
                    <span className="text-lg font-semibold">
                      Streak protected for 24 hours!
                    </span>
                  </div>
                  <p className="text-gray-600 dark:text-gray-400">
                    Complete a challenge tomorrow to continue your streak.
                  </p>
                </div>
              ) : (
                <>
                  {/* Current streak info */}
                  <div className="flex items-center justify-center gap-4 mb-6 p-4 bg-orange-50 dark:bg-orange-900/20 rounded-xl">
                    <div className="flex items-center gap-2">
                      <Flame className="w-6 h-6 text-orange-500" />
                      <span className="text-2xl font-bold text-gray-900 dark:text-white">
                        {streakInfo.current_streak}
                      </span>
                      <span className="text-gray-600 dark:text-gray-400">days</span>
                    </div>
                    {streakInfo.current_bonus_percent > 0 && (
                      <div className="flex items-center gap-1 px-2 py-1 bg-green-100 dark:bg-green-900/30 rounded-full">
                        <Sparkles className="w-4 h-4 text-green-600 dark:text-green-400" />
                        <span className="text-sm font-medium text-green-700 dark:text-green-400">
                          +{streakInfo.current_bonus_percent}% XP
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Freeze token info */}
                  <div className="mb-6">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Freeze Tokens Available
                      </span>
                      <span className="text-lg font-bold text-gray-900 dark:text-white">
                        {streakInfo.freeze_tokens}
                      </span>
                    </div>
                    <div className="flex gap-1">
                      {[...Array(Math.max(streakInfo.freeze_tokens, 3))].map((_, i) => (
                        <div
                          key={i}
                          className={`w-8 h-8 rounded-full flex items-center justify-center ${
                            i < streakInfo.freeze_tokens
                              ? 'bg-blue-100 dark:bg-blue-900/30'
                              : 'bg-gray-100 dark:bg-gray-700'
                          }`}
                        >
                          <Shield
                            className={`w-4 h-4 ${
                              i < streakInfo.freeze_tokens
                                ? 'text-blue-600 dark:text-blue-400'
                                : 'text-gray-400'
                            }`}
                          />
                        </div>
                      ))}
                    </div>
                    <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                      Use a freeze token to protect your streak for 24 hours
                    </p>
                  </div>

                  {/* Error message */}
                  {error && (
                    <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-400 text-sm">
                      {error}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex flex-col gap-3">
                    <button
                      onClick={handleUseFreezeToken}
                      disabled={using || streakInfo.freeze_tokens <= 0}
                      className="flex items-center justify-center gap-2 w-full py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-xl font-semibold hover:from-blue-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    >
                      {using ? (
                        <Loader2 className="w-5 h-5 animate-spin" />
                      ) : (
                        <Shield className="w-5 h-5" />
                      )}
                      {streakInfo.freeze_tokens > 0
                        ? 'Use Freeze Token'
                        : 'No Freeze Tokens'}
                    </button>

                    <button
                      onClick={onClose}
                      className="py-3 text-gray-600 dark:text-gray-400 font-medium hover:text-gray-900 dark:hover:text-white transition-colors"
                    >
                      Complete a challenge instead
                    </button>
                  </div>

                  {/* Time remaining */}
                  {streakInfo.hours_remaining && (
                    <div className="mt-6 flex items-center justify-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                      <Clock className="w-4 h-4" />
                      <span>
                        Streak resets in <strong>{formatTimeRemaining()}</strong>
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default StreakFreezeModal;
