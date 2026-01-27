// frontend/src/plugins/typing-game/components/StreakDisplay.tsx
import { motion, AnimatePresence } from 'framer-motion';
import { Flame, Shield, AlertTriangle } from 'lucide-react';

interface StreakInfo {
  current_streak: number;
  longest_streak: number;
  games_today: number;
  freeze_available: boolean;
  streak_at_risk: boolean;
  played_today: boolean;
}

interface StreakDisplayProps {
  streak: StreakInfo;
  compact?: boolean;
  onUseFreeze?: () => void;
}

export function StreakDisplay({ streak, compact = false, onUseFreeze }: StreakDisplayProps) {
  const getFlameColor = () => {
    if (streak.current_streak >= 30) return 'text-purple-500';
    if (streak.current_streak >= 14) return 'text-orange-500';
    if (streak.current_streak >= 7) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getFlameSize = () => {
    if (compact) return 'w-5 h-5';
    if (streak.current_streak >= 30) return 'w-10 h-10';
    if (streak.current_streak >= 14) return 'w-8 h-8';
    return 'w-6 h-6';
  };

  if (compact) {
    return (
      <div className="flex items-center gap-1.5 px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded-full">
        <motion.div
          animate={streak.current_streak > 0 ? {
            scale: [1, 1.2, 1],
          } : {}}
          transition={{ duration: 0.5, repeat: Infinity, repeatDelay: 2 }}
        >
          <Flame className={`${getFlameSize()} ${getFlameColor()}`} />
        </motion.div>
        <span className="font-bold text-sm">{streak.current_streak}</span>
        {streak.freeze_available && (
          <span title="Freeze available">
            <Shield className="w-4 h-4 text-blue-500" />
          </span>
        )}
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-orange-50 to-red-50 dark:from-gray-800 dark:to-gray-900 rounded-xl p-3 sm:p-4 border border-orange-200 dark:border-orange-800">
      <div className="flex items-center justify-between mb-2 sm:mb-3">
        <h3 className="font-semibold text-sm sm:text-base text-gray-900 dark:text-white flex items-center gap-1.5 sm:gap-2">
          <motion.div
            animate={streak.current_streak > 0 ? {
              scale: [1, 1.15, 1],
              rotate: [0, 5, -5, 0],
            } : {}}
            transition={{ duration: 0.6, repeat: Infinity, repeatDelay: 1.5 }}
          >
            <Flame className={`${getFlameSize()} ${getFlameColor()}`} />
          </motion.div>
          Daily Streak
        </h3>
        {streak.streak_at_risk && !streak.played_today && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center gap-1 text-amber-600 text-xs sm:text-sm"
          >
            <AlertTriangle className="w-3 h-3 sm:w-4 sm:h-4" />
            At risk!
          </motion.div>
        )}
      </div>

      <div className="grid grid-cols-3 gap-2 sm:gap-4 mb-3 sm:mb-4">
        <div className="text-center">
          <div className="text-2xl sm:text-3xl font-bold text-orange-600 dark:text-orange-400">
            {streak.current_streak}
          </div>
          <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Current</div>
        </div>
        <div className="text-center">
          <div className="text-xl sm:text-2xl font-bold text-gray-700 dark:text-gray-300">
            {streak.longest_streak}
          </div>
          <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Best</div>
        </div>
        <div className="text-center">
          <div className="text-xl sm:text-2xl font-bold text-green-600 dark:text-green-400">
            {streak.games_today}
          </div>
          <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Today</div>
        </div>
      </div>

      {/* Streak milestones */}
      <div className="flex gap-1 mb-2 sm:mb-3">
        {[3, 7, 14, 30].map((milestone) => (
          <div
            key={milestone}
            className={`flex-1 h-1.5 sm:h-2 rounded-full transition-colors ${
              streak.current_streak >= milestone
                ? 'bg-orange-500'
                : 'bg-gray-200 dark:bg-gray-700'
            }`}
            title={`${milestone} days`}
          />
        ))}
      </div>

      {/* Freeze status */}
      <div className="flex items-center justify-between text-xs sm:text-sm">
        <div className="flex items-center gap-1.5 sm:gap-2">
          <Shield className={`w-3.5 h-3.5 sm:w-4 sm:h-4 ${streak.freeze_available ? 'text-blue-500' : 'text-gray-400'}`} />
          <span className={streak.freeze_available ? 'text-blue-600 dark:text-blue-400' : 'text-gray-500'}>
            {streak.freeze_available ? 'Freeze' : 'Used'}
          </span>
        </div>
        {streak.freeze_available && streak.streak_at_risk && onUseFreeze && (
          <button
            onClick={onUseFreeze}
            className="px-2 sm:px-3 py-0.5 sm:py-1 bg-blue-500 hover:bg-blue-600 text-white text-xs rounded-full transition-colors"
          >
            Use
          </button>
        )}
      </div>

      {/* Played today indicator */}
      <AnimatePresence>
        {streak.played_today && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mt-2 sm:mt-3 text-center text-xs sm:text-sm text-green-600 dark:text-green-400 font-medium"
          >
            Streak maintained!
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default StreakDisplay;
