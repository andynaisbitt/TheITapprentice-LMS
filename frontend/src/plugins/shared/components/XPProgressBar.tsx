// frontend/src/plugins/shared/components/XPProgressBar.tsx
/**
 * XP Progress Bar Component
 * Shows level progress with animated XP bar
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Sparkles, TrendingUp } from 'lucide-react';
import type { LevelProgress } from '../types';

interface XPProgressBarProps {
  progress: LevelProgress;
  showDetails?: boolean;
  compact?: boolean;
  className?: string;
}

export const XPProgressBar: React.FC<XPProgressBarProps> = ({
  progress,
  showDetails = true,
  compact = false,
  className = '',
}) => {
  const {
    level,
    total_xp,
    xp_in_current_level,
    xp_for_next_level,
    progress_percent,
    xp_to_next_level,
  } = progress;

  if (compact) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className="flex items-center gap-1">
          <Sparkles className="w-4 h-4 text-yellow-500" />
          <span className="font-bold text-gray-900 dark:text-white">Lv.{level}</span>
        </div>
        <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${progress_percent}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            className="h-full bg-gradient-to-r from-blue-500 to-purple-500 rounded-full"
          />
        </div>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          {progress_percent}%
        </span>
      </div>
    );
  }

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl p-4 shadow ${className}`}>
      {/* Level Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-xl flex items-center justify-center shadow-lg">
            <span className="text-xl font-bold text-white">{level}</span>
          </div>
          <div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Level</div>
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              {total_xp.toLocaleString()} XP
            </div>
          </div>
        </div>

        {showDetails && (
          <div className="text-right">
            <div className="text-sm text-gray-500 dark:text-gray-400">Next Level</div>
            <div className="flex items-center gap-1 text-blue-600 dark:text-blue-400 font-medium">
              <TrendingUp className="w-4 h-4" />
              {xp_to_next_level.toLocaleString()} XP
            </div>
          </div>
        )}
      </div>

      {/* Progress Bar */}
      <div className="relative">
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${progress_percent}%` }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
            className="h-full bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 rounded-full relative"
          >
            {/* Shimmer effect */}
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer" />
          </motion.div>
        </div>

        {/* Progress Labels */}
        {showDetails && (
          <div className="flex justify-between mt-1 text-xs text-gray-500 dark:text-gray-400">
            <span>{xp_in_current_level.toLocaleString()} XP</span>
            <span className="font-medium">{progress_percent}%</span>
            <span>{xp_for_next_level.toLocaleString()} XP</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default XPProgressBar;
