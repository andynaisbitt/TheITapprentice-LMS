// frontend/src/plugins/skills/components/SkillBadge.tsx
/**
 * SkillBadge - Compact skill level display
 * Use in profiles, leaderboards, and anywhere you need to show a skill level
 */

import React from 'react';
import { Link } from 'react-router-dom';
import type { SkillTier } from '../types';

interface SkillBadgeProps {
  skillSlug: string;
  skillName: string;
  skillIcon: string;
  level: number;
  tier: SkillTier;
  tierColor: string;
  size?: 'sm' | 'md' | 'lg';
  showName?: boolean;
  linkable?: boolean;
}

export const SkillBadge: React.FC<SkillBadgeProps> = ({
  skillSlug,
  skillName,
  skillIcon,
  level,
  tier,
  tierColor,
  size = 'md',
  showName = false,
  linkable = true,
}) => {
  const sizeClasses = {
    sm: 'w-8 h-8 text-xs',
    md: 'w-10 h-10 text-sm',
    lg: 'w-14 h-14 text-base',
  };

  const iconSizes = {
    sm: 'text-sm',
    md: 'text-lg',
    lg: 'text-2xl',
  };

  const content = (
    <div className="flex items-center gap-2 group">
      <div className="relative">
        {/* Skill icon background */}
        <div
          className={`${sizeClasses[size]} rounded-full flex items-center justify-center transition-transform group-hover:scale-110`}
          style={{ backgroundColor: `${tierColor}20` }}
        >
          <span className={iconSizes[size]}>{skillIcon}</span>
        </div>
        {/* Level badge */}
        <div
          className={`absolute -bottom-1 -right-1 ${
            size === 'sm' ? 'w-4 h-4 text-[10px]' : size === 'md' ? 'w-5 h-5 text-xs' : 'w-6 h-6 text-sm'
          } rounded-full flex items-center justify-center text-white font-bold shadow-md`}
          style={{ backgroundColor: tierColor }}
        >
          {level}
        </div>
      </div>
      {showName && (
        <div className="flex flex-col">
          <span className="text-sm font-medium text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
            {skillName}
          </span>
          <span
            className="text-xs"
            style={{ color: tierColor }}
          >
            {tier}
          </span>
        </div>
      )}
    </div>
  );

  if (linkable) {
    return (
      <Link to={`/skills/${skillSlug}`} className="inline-block" title={`${skillName} - Level ${level} ${tier}`}>
        {content}
      </Link>
    );
  }

  return <div title={`${skillName} - Level ${level} ${tier}`}>{content}</div>;
};

export default SkillBadge;
