// frontend/src/plugins/shared/components/AchievementsGrid.tsx
/**
 * Achievements Grid Component
 * Displays a grid of achievements with filtering
 */

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Trophy, Filter } from 'lucide-react';
import { AchievementBadge } from './AchievementBadge';
import type { AchievementProgress, AchievementCategory } from '../types';

interface AchievementsGridProps {
  achievements: AchievementProgress[];
  title?: string;
  showFilters?: boolean;
  showUnlockedFirst?: boolean;
  maxDisplay?: number;
  onAchievementClick?: (achievement: AchievementProgress) => void;
  className?: string;
}

const CATEGORY_LABELS: Record<AchievementCategory, string> = {
  tutorials: 'Tutorials',
  courses: 'Courses',
  typing: 'Typing',
  social: 'Social',
  streak: 'Streaks',
  special: 'Special',
};

export const AchievementsGrid: React.FC<AchievementsGridProps> = ({
  achievements,
  title = 'Achievements',
  showFilters = true,
  showUnlockedFirst = true,
  maxDisplay,
  onAchievementClick,
  className = '',
}) => {
  const [selectedCategory, setSelectedCategory] = useState<AchievementCategory | 'all'>('all');
  const [showOnlyUnlocked, setShowOnlyUnlocked] = useState(false);

  // Get unique categories from achievements
  const categories = [...new Set(achievements.map((a) => a.category))];

  // Filter achievements
  let filteredAchievements = achievements;

  if (selectedCategory !== 'all') {
    filteredAchievements = filteredAchievements.filter((a) => a.category === selectedCategory);
  }

  if (showOnlyUnlocked) {
    filteredAchievements = filteredAchievements.filter((a) => a.is_unlocked);
  }

  // Sort achievements (unlocked first if enabled)
  if (showUnlockedFirst) {
    filteredAchievements = [...filteredAchievements].sort((a, b) => {
      if (a.is_unlocked && !b.is_unlocked) return -1;
      if (!a.is_unlocked && b.is_unlocked) return 1;
      return 0;
    });
  }

  // Limit display if needed
  if (maxDisplay && maxDisplay > 0) {
    filteredAchievements = filteredAchievements.slice(0, maxDisplay);
  }

  // Count unlocked
  const unlockedCount = achievements.filter((a) => a.is_unlocked).length;
  const totalCount = achievements.length;

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl shadow ${className}`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-100 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-xl flex items-center justify-center">
              <Trophy className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-gray-900 dark:text-white">{title}</h2>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {unlockedCount} / {totalCount} unlocked
              </div>
            </div>
          </div>

          {/* Progress indicator */}
          <div className="flex items-center gap-2">
            <div className="w-24 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${(unlockedCount / totalCount) * 100}%` }}
                className="h-full bg-gradient-to-r from-yellow-400 to-orange-500 rounded-full"
              />
            </div>
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {Math.round((unlockedCount / totalCount) * 100)}%
            </span>
          </div>
        </div>

        {/* Filters */}
        {showFilters && categories.length > 1 && (
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                selectedCategory === 'all'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              All
            </button>
            {categories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                  selectedCategory === category
                    ? 'bg-blue-500 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                {CATEGORY_LABELS[category]}
              </button>
            ))}

            {/* Toggle unlocked only */}
            <button
              onClick={() => setShowOnlyUnlocked(!showOnlyUnlocked)}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors flex items-center gap-1 ${
                showOnlyUnlocked
                  ? 'bg-green-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              <Filter className="w-3 h-3" />
              Unlocked
            </button>
          </div>
        )}
      </div>

      {/* Grid */}
      <div className="p-4">
        {filteredAchievements.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
            {filteredAchievements.map((achievement, idx) => (
              <motion.div
                key={achievement.achievement_id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.05 }}
              >
                <AchievementBadge
                  achievement={achievement}
                  size="md"
                  onClick={onAchievementClick ? () => onAchievementClick(achievement) : undefined}
                />
              </motion.div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400">
            {showOnlyUnlocked
              ? 'No achievements unlocked yet. Keep learning!'
              : 'No achievements found in this category.'}
          </div>
        )}
      </div>
    </div>
  );
};

export default AchievementsGrid;
