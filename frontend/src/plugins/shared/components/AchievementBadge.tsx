// frontend/src/plugins/shared/components/AchievementBadge.tsx
/**
 * Achievement Badge Component
 * Displays a single achievement with progress
 */

import React from 'react';
import { motion } from 'framer-motion';
import {
  Trophy, BookOpen, GraduationCap, Keyboard, Users, Flame, Star,
  Lock, Check
} from 'lucide-react';
import type { AchievementProgress, AchievementRarity, AchievementCategory } from '../types';
import { RARITY_COLORS, RARITY_COLORS_DARK } from '../types';

interface AchievementBadgeProps {
  achievement: AchievementProgress;
  size?: 'sm' | 'md' | 'lg';
  showProgress?: boolean;
  onClick?: () => void;
  className?: string;
}

const CATEGORY_ICON_MAP: Record<AchievementCategory, React.ElementType> = {
  tutorials: BookOpen,
  courses: GraduationCap,
  typing: Keyboard,
  social: Users,
  streak: Flame,
  special: Star,
};

const RARITY_GLOW: Record<AchievementRarity, string> = {
  common: '',
  uncommon: 'shadow-green-500/20',
  rare: 'shadow-blue-500/30',
  epic: 'shadow-purple-500/40',
  legendary: 'shadow-yellow-500/50 animate-pulse',
};

export const AchievementBadge: React.FC<AchievementBadgeProps> = ({
  achievement,
  size = 'md',
  showProgress = true,
  onClick,
  className = '',
}) => {
  const {
    name,
    description,
    icon,
    category,
    rarity,
    is_unlocked,
    progress,
    progress_max,
    progress_percent,
  } = achievement;

  // Get icon component (fall back to category icon, then trophy)
  const IconComponent = CATEGORY_ICON_MAP[category] || Trophy;

  const sizeClasses = {
    sm: 'w-12 h-12',
    md: 'w-16 h-16',
    lg: 'w-24 h-24',
  };

  const iconSizes = {
    sm: 'w-5 h-5',
    md: 'w-7 h-7',
    lg: 'w-10 h-10',
  };

  const textSizes = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-base',
  };

  const rarityColor = RARITY_COLORS[rarity];
  const rarityColorDark = RARITY_COLORS_DARK[rarity];
  const glowEffect = is_unlocked ? RARITY_GLOW[rarity] : '';

  return (
    <motion.div
      whileHover={{ scale: onClick ? 1.05 : 1 }}
      whileTap={{ scale: onClick ? 0.95 : 1 }}
      className={`relative flex flex-col items-center ${onClick ? 'cursor-pointer' : ''} ${className}`}
      onClick={onClick}
    >
      {/* Badge Icon */}
      <div
        className={`
          ${sizeClasses[size]}
          rounded-xl border-2 flex items-center justify-center
          ${is_unlocked ? rarityColor : 'bg-gray-100 border-gray-300 dark:bg-gray-800 dark:border-gray-600'}
          ${is_unlocked ? rarityColorDark : ''}
          ${glowEffect ? `shadow-lg ${glowEffect}` : ''}
          transition-all duration-300
        `}
      >
        {is_unlocked ? (
          <IconComponent className={`${iconSizes[size]} ${is_unlocked ? '' : 'opacity-50'}`} />
        ) : (
          <Lock className={`${iconSizes[size]} text-gray-400`} />
        )}
      </div>

      {/* Achievement Name */}
      <div className={`mt-2 text-center ${textSizes[size]}`}>
        <div className={`font-medium ${is_unlocked ? 'text-gray-900 dark:text-white' : 'text-gray-400'}`}>
          {name}
        </div>
        {size !== 'sm' && (
          <div className={`text-xs ${is_unlocked ? 'text-gray-500 dark:text-gray-400' : 'text-gray-400'} line-clamp-2`}>
            {description}
          </div>
        )}
      </div>

      {/* Progress Bar (for locked achievements) */}
      {showProgress && !is_unlocked && progress_max > 1 && (
        <div className="w-full mt-2">
          <div className="h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progress_percent}%` }}
              className="h-full bg-blue-500 rounded-full"
            />
          </div>
          <div className="flex justify-between mt-0.5 text-[10px] text-gray-400">
            <span>{progress}/{progress_max}</span>
            <span>{progress_percent}%</span>
          </div>
        </div>
      )}

      {/* Unlocked Checkmark */}
      {is_unlocked && (
        <div className="absolute -top-1 -right-1 w-5 h-5 bg-green-500 rounded-full flex items-center justify-center">
          <Check className="w-3 h-3 text-white" />
        </div>
      )}
    </motion.div>
  );
};

export default AchievementBadge;
