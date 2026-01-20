// src/components/admin/dashboard/AttentionItems.tsx
/**
 * Items needing admin attention (drafts, pending users, etc.)
 */

import { Link } from 'react-router-dom';
import {
  FileText,
  User,
  AlertTriangle,
  TrendingDown,
  ChevronRight,
  type LucideIcon,
} from 'lucide-react';

export interface AttentionItem {
  id: string;
  type: 'draft_posts' | 'pending_users' | 'tutorial_dropoff' | 'system_warning';
  title: string;
  count?: number;
  description: string;
  link: string;
  priority: 'low' | 'medium' | 'high';
}

interface AttentionItemsProps {
  items: AttentionItem[];
  loading?: boolean;
}

const typeConfig: Record<
  AttentionItem['type'],
  { icon: LucideIcon; bgColor: string; iconColor: string }
> = {
  draft_posts: {
    icon: FileText,
    bgColor: 'bg-yellow-50 dark:bg-yellow-900/20',
    iconColor: 'text-yellow-600 dark:text-yellow-400',
  },
  pending_users: {
    icon: User,
    bgColor: 'bg-blue-50 dark:bg-blue-900/20',
    iconColor: 'text-blue-600 dark:text-blue-400',
  },
  tutorial_dropoff: {
    icon: TrendingDown,
    bgColor: 'bg-orange-50 dark:bg-orange-900/20',
    iconColor: 'text-orange-600 dark:text-orange-400',
  },
  system_warning: {
    icon: AlertTriangle,
    bgColor: 'bg-red-50 dark:bg-red-900/20',
    iconColor: 'text-red-600 dark:text-red-400',
  },
};

const priorityStyles = {
  low: 'border-gray-200 dark:border-gray-700',
  medium: 'border-yellow-300 dark:border-yellow-700',
  high: 'border-red-300 dark:border-red-700',
};

export const AttentionItems: React.FC<AttentionItemsProps> = ({
  items,
  loading = false,
}) => {
  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div
            key={i}
            className="flex items-center gap-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg animate-pulse"
          >
            <div className="w-10 h-10 bg-gray-200 dark:bg-gray-700 rounded-lg" />
            <div className="flex-1 space-y-2">
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2" />
              <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="text-center py-8">
        <div className="w-16 h-16 mx-auto mb-4 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center">
          <svg
            className="w-8 h-8 text-green-600 dark:text-green-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M5 13l4 4L19 7"
            />
          </svg>
        </div>
        <p className="text-gray-600 dark:text-gray-400 font-medium">All caught up!</p>
        <p className="text-sm text-gray-500 dark:text-gray-500">
          No items need your attention right now
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((item) => {
        const config = typeConfig[item.type];
        const Icon = config.icon;

        return (
          <Link
            key={item.id}
            to={item.link}
            className={`
              flex items-center gap-4 p-4
              bg-white dark:bg-gray-800
              border ${priorityStyles[item.priority]}
              rounded-lg
              hover:shadow-md transition-all duration-200
              group
            `}
          >
            {/* Icon */}
            <div className={`p-2.5 rounded-lg ${config.bgColor}`}>
              <Icon className={`w-5 h-5 ${config.iconColor}`} />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <p className="text-sm font-semibold text-gray-900 dark:text-white">
                  {item.title}
                </p>
                {item.count !== undefined && item.count > 0 && (
                  <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-primary/10 text-primary">
                    {item.count}
                  </span>
                )}
              </div>
              <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                {item.description}
              </p>
            </div>

            {/* Arrow */}
            <ChevronRight className="w-5 h-5 text-gray-400 group-hover:text-primary transition-colors" />
          </Link>
        );
      })}
    </div>
  );
};

export default AttentionItems;
