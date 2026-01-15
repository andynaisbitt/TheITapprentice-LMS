// frontend/src/plugins/shared/components/StreakCounter.tsx
/**
 * Streak Counter Component
 * Displays daily streak with fire animation
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Flame, Calendar } from 'lucide-react';

interface StreakCounterProps {
  streak: number;
  longestStreak?: number;
  showLongest?: boolean;
  compact?: boolean;
  className?: string;
}

export const StreakCounter: React.FC<StreakCounterProps> = ({
  streak,
  longestStreak = 0,
  showLongest = false,
  compact = false,
  className = '',
}) => {
  const getStreakColor = () => {
    if (streak >= 30) return 'from-red-500 to-orange-500';
    if (streak >= 7) return 'from-orange-500 to-yellow-500';
    if (streak >= 3) return 'from-yellow-500 to-amber-500';
    return 'from-gray-400 to-gray-500';
  };

  const getStreakMessage = () => {
    if (streak >= 365) return "You're on fire! A whole year!";
    if (streak >= 100) return "Century streak! Amazing!";
    if (streak >= 30) return "Monthly master!";
    if (streak >= 7) return "Weekly warrior!";
    if (streak >= 3) return "Good start!";
    if (streak >= 1) return "Keep it going!";
    return "Start your streak today!";
  };

  if (compact) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className={`p-1.5 rounded-lg bg-gradient-to-br ${getStreakColor()}`}>
          <Flame className="w-4 h-4 text-white" />
        </div>
        <div className="flex items-baseline gap-1">
          <span className="text-lg font-bold text-gray-900 dark:text-white">{streak}</span>
          <span className="text-xs text-gray-500 dark:text-gray-400">day{streak !== 1 ? 's' : ''}</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl p-4 shadow ${className}`}>
      <div className="flex items-center gap-4">
        {/* Fire Icon with Animation */}
        <motion.div
          animate={streak > 0 ? {
            scale: [1, 1.1, 1],
            rotate: [0, -5, 5, 0],
          } : {}}
          transition={{
            duration: 1.5,
            repeat: Infinity,
            repeatType: 'reverse',
          }}
          className={`w-14 h-14 rounded-xl bg-gradient-to-br ${getStreakColor()} flex items-center justify-center shadow-lg`}
        >
          <Flame className="w-8 h-8 text-white" />
        </motion.div>

        {/* Streak Info */}
        <div className="flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-gray-900 dark:text-white">{streak}</span>
            <span className="text-gray-500 dark:text-gray-400">day streak</span>
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{getStreakMessage()}</div>
        </div>

        {/* Longest Streak */}
        {showLongest && longestStreak > 0 && (
          <div className="text-right border-l border-gray-200 dark:border-gray-700 pl-4">
            <div className="text-xs text-gray-500 dark:text-gray-400">Best</div>
            <div className="flex items-center gap-1">
              <Calendar className="w-4 h-4 text-gray-400" />
              <span className="text-lg font-bold text-gray-700 dark:text-gray-300">
                {longestStreak}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Streak Progress to Next Milestone */}
      {streak > 0 && streak < 365 && (
        <div className="mt-3">
          {renderMilestoneProgress(streak)}
        </div>
      )}
    </div>
  );
};

// Helper to render milestone progress
const renderMilestoneProgress = (streak: number) => {
  let nextMilestone = 3;
  let label = '3 Days';

  if (streak >= 100) {
    nextMilestone = 365;
    label = '1 Year';
  } else if (streak >= 30) {
    nextMilestone = 100;
    label = '100 Days';
  } else if (streak >= 7) {
    nextMilestone = 30;
    label = '30 Days';
  } else if (streak >= 3) {
    nextMilestone = 7;
    label = '1 Week';
  }

  const progress = (streak / nextMilestone) * 100;

  return (
    <div>
      <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
        <span>Progress to {label}</span>
        <span>{streak}/{nextMilestone}</span>
      </div>
      <div className="h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          className="h-full bg-gradient-to-r from-orange-500 to-red-500 rounded-full"
        />
      </div>
    </div>
  );
};

export default StreakCounter;
