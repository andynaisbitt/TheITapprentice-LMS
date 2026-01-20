// src/components/admin/dashboard/QuickStatsCard.tsx
/**
 * Stats card with icon, value, trend indicator
 */

import { type LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface QuickStatsCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    label: string;
  };
  color?: 'blue' | 'green' | 'purple' | 'orange' | 'pink' | 'cyan';
  onClick?: () => void;
}

const colorClasses = {
  blue: {
    bg: 'bg-blue-500',
    light: 'bg-blue-50 dark:bg-blue-900/20',
    text: 'text-blue-600 dark:text-blue-400',
    border: 'border-blue-500',
  },
  green: {
    bg: 'bg-green-500',
    light: 'bg-green-50 dark:bg-green-900/20',
    text: 'text-green-600 dark:text-green-400',
    border: 'border-green-500',
  },
  purple: {
    bg: 'bg-purple-500',
    light: 'bg-purple-50 dark:bg-purple-900/20',
    text: 'text-purple-600 dark:text-purple-400',
    border: 'border-purple-500',
  },
  orange: {
    bg: 'bg-orange-500',
    light: 'bg-orange-50 dark:bg-orange-900/20',
    text: 'text-orange-600 dark:text-orange-400',
    border: 'border-orange-500',
  },
  pink: {
    bg: 'bg-pink-500',
    light: 'bg-pink-50 dark:bg-pink-900/20',
    text: 'text-pink-600 dark:text-pink-400',
    border: 'border-pink-500',
  },
  cyan: {
    bg: 'bg-cyan-500',
    light: 'bg-cyan-50 dark:bg-cyan-900/20',
    text: 'text-cyan-600 dark:text-cyan-400',
    border: 'border-cyan-500',
  },
};

export const QuickStatsCard: React.FC<QuickStatsCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  color = 'blue',
  onClick,
}) => {
  const colors = colorClasses[color];

  const TrendIcon = trend
    ? trend.value > 0
      ? TrendingUp
      : trend.value < 0
      ? TrendingDown
      : Minus
    : null;

  const trendColor = trend
    ? trend.value > 0
      ? 'text-green-600 dark:text-green-400'
      : trend.value < 0
      ? 'text-red-600 dark:text-red-400'
      : 'text-gray-500'
    : '';

  return (
    <div
      onClick={onClick}
      className={`
        bg-white dark:bg-gray-800 rounded-xl shadow-sm
        border-l-4 ${colors.border}
        p-5 transition-all duration-200
        ${onClick ? 'cursor-pointer hover:shadow-md hover:scale-[1.02]' : ''}
      `}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
            {title}
          </p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
          {trend && (
            <div className={`flex items-center gap-1 mt-2 text-sm ${trendColor}`}>
              {TrendIcon && <TrendIcon className="w-4 h-4" />}
              <span className="font-medium">
                {trend.value > 0 ? '+' : ''}
                {trend.value}%
              </span>
              <span className="text-gray-500 dark:text-gray-400">{trend.label}</span>
            </div>
          )}
        </div>
        <div className={`p-3 rounded-xl ${colors.light}`}>
          <Icon className={`w-6 h-6 ${colors.text}`} />
        </div>
      </div>
    </div>
  );
};

export default QuickStatsCard;
