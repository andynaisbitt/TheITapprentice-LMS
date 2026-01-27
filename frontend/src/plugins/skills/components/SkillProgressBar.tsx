// frontend/src/plugins/skills/components/SkillProgressBar.tsx
/**
 * SkillProgressBar - Animated XP progress bar with level display
 */

import React from 'react';

interface SkillProgressBarProps {
  currentXp: number;
  xpToNextLevel: number;
  xpProgressPercentage: number;
  currentLevel: number;
  tierColor: string;
  showXpText?: boolean;
  height?: 'sm' | 'md' | 'lg';
  animated?: boolean;
}

export const SkillProgressBar: React.FC<SkillProgressBarProps> = ({
  currentXp,
  xpToNextLevel,
  xpProgressPercentage,
  currentLevel,
  tierColor,
  showXpText = true,
  height = 'md',
  animated = true,
}) => {
  const heightClasses = {
    sm: 'h-1.5',
    md: 'h-2.5',
    lg: 'h-4',
  };

  const progressPercent = Math.min(100, Math.max(0, xpProgressPercentage));

  return (
    <div className="w-full">
      {showXpText && (
        <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
          <span>{(currentXp ?? 0).toLocaleString()} XP</span>
          <span>
            {(currentLevel ?? 0) < 99
              ? `${(xpToNextLevel ?? 0).toLocaleString()} to Lv.${(currentLevel ?? 0) + 1}`
              : 'MAX LEVEL'
            }
          </span>
        </div>
      )}
      <div className={`${heightClasses[height]} bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden`}>
        <div
          className={`h-full rounded-full ${animated ? 'transition-all duration-700 ease-out' : ''}`}
          style={{
            width: `${progressPercent}%`,
            backgroundColor: tierColor,
          }}
        />
      </div>
    </div>
  );
};

export default SkillProgressBar;
