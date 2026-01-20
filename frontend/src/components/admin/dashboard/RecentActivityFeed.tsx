// src/components/admin/dashboard/RecentActivityFeed.tsx
/**
 * Recent activity timeline for admin dashboard
 */

import {
  FileText,
  User,
  BookOpen,
  Trophy,
  Keyboard,
  CheckCircle,
  UserPlus,
  Edit,
  type LucideIcon,
} from 'lucide-react';

export interface ActivityItem {
  id: string;
  type: string;
  title: string;
  description?: string;
  timestamp: string;
  user?: {
    name: string;
    avatar?: string;
  };
}

interface RecentActivityFeedProps {
  activities: ActivityItem[];
  loading?: boolean;
  maxItems?: number;
}

const activityConfig: Record<string, { icon: LucideIcon; color: string }> = {
  post_published: { icon: FileText, color: 'bg-blue-500' },
  post_edited: { icon: Edit, color: 'bg-blue-400' },
  user_registered: { icon: UserPlus, color: 'bg-green-500' },
  user_verified: { icon: CheckCircle, color: 'bg-green-600' },
  tutorial_completed: { icon: BookOpen, color: 'bg-purple-500' },
  achievement_unlocked: { icon: Trophy, color: 'bg-yellow-500' },
  game_played: { icon: Keyboard, color: 'bg-pink-500' },
  login: { icon: User, color: 'bg-gray-500' },
  course_enrolled: { icon: BookOpen, color: 'bg-indigo-500' },
  unknown: { icon: User, color: 'bg-gray-400' },
};

const formatTimeAgo = (timestamp: string): string => {
  const date = new Date(timestamp);
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 60) return 'Just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)}d ago`;

  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

export const RecentActivityFeed: React.FC<RecentActivityFeedProps> = ({
  activities,
  loading = false,
  maxItems = 8,
}) => {
  const displayedActivities = activities.slice(0, maxItems);

  if (loading) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="flex items-start gap-3 animate-pulse">
            <div className="w-8 h-8 bg-gray-200 dark:bg-gray-700 rounded-full" />
            <div className="flex-1 space-y-2">
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
              <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (displayedActivities.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
        <User className="w-12 h-12 mx-auto mb-3 opacity-50" />
        <p>No recent activity</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {displayedActivities.map((activity, index) => {
        const config = activityConfig[activity.type] || activityConfig.unknown;
        const Icon = config.icon;

        return (
          <div
            key={activity.id}
            className={`
              flex items-start gap-3 p-3 rounded-lg
              hover:bg-gray-50 dark:hover:bg-gray-800/50
              transition-colors duration-200
              ${index !== displayedActivities.length - 1 ? 'border-b border-gray-100 dark:border-gray-800' : ''}
            `}
          >
            {/* Icon */}
            <div className={`p-2 rounded-full ${config.color} flex-shrink-0`}>
              <Icon className="w-4 h-4 text-white" />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {activity.title}
              </p>
              {activity.description && (
                <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                  {activity.description}
                </p>
              )}
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                {formatTimeAgo(activity.timestamp)}
              </p>
            </div>

            {/* User avatar */}
            {activity.user && (
              <div className="flex-shrink-0">
                {activity.user.avatar ? (
                  <img
                    src={activity.user.avatar}
                    alt={activity.user.name}
                    className="w-8 h-8 rounded-full"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white text-xs font-semibold">
                    {activity.user.name[0].toUpperCase()}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default RecentActivityFeed;
