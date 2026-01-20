// src/pages/admin/ActivityLogPage.tsx
/**
 * Site-wide Activity Log
 * View all user activities across the platform
 */

import { useState, useEffect } from 'react';
import {
  Activity,
  FileText,
  User,
  BookOpen,
  Trophy,
  Keyboard,
  LogIn,
  Filter,
  Search,
  Loader2,
} from 'lucide-react';

interface ActivityLogItem {
  id: string;
  type: string;
  title: string;
  description?: string;
  user: {
    id: number;
    username: string;
    avatar?: string;
  };
  timestamp: string;
  xp_earned?: number;
}

export const ActivityLogPage: React.FC = () => {
  const [activities, setActivities] = useState<ActivityLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadActivities();
  }, [filter]);

  const loadActivities = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch(`/api/v1/admin/activities?type=${filter}`);
      // const data = await response.json();
      // setActivities(data);

      // Mock data
      setActivities([
        {
          id: '1',
          type: 'tutorial_complete',
          title: 'Completed tutorial: Python Basics',
          user: { id: 1, username: 'john_doe' },
          timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          xp_earned: 100,
        },
        {
          id: '2',
          type: 'achievement_unlock',
          title: 'Unlocked achievement: Speed Demon',
          description: 'Reached 80+ WPM in typing game',
          user: { id: 2, username: 'jane_smith' },
          timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
          xp_earned: 150,
        },
        {
          id: '3',
          type: 'login',
          title: 'User logged in',
          user: { id: 3, username: 'bob_wilson' },
          timestamp: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
          xp_earned: 10,
        },
        {
          id: '4',
          type: 'typing_game',
          title: 'Completed typing game',
          description: '65 WPM, 95% accuracy',
          user: { id: 1, username: 'john_doe' },
          timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
          xp_earned: 50,
        },
        {
          id: '5',
          type: 'post_view',
          title: 'Viewed blog post',
          description: 'Docker Guide for Beginners',
          user: { id: 4, username: 'alice_chen' },
          timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
        },
      ]);
    } catch (error) {
      console.error('Failed to load activities:', error);
    } finally {
      setLoading(false);
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'tutorial_complete':
        return BookOpen;
      case 'achievement_unlock':
        return Trophy;
      case 'typing_game':
        return Keyboard;
      case 'login':
        return LogIn;
      case 'post_view':
        return FileText;
      default:
        return Activity;
    }
  };

  const getActivityColor = (type: string) => {
    switch (type) {
      case 'tutorial_complete':
        return 'bg-purple-500';
      case 'achievement_unlock':
        return 'bg-yellow-500';
      case 'typing_game':
        return 'bg-pink-500';
      case 'login':
        return 'bg-green-500';
      case 'post_view':
        return 'bg-blue-500';
      default:
        return 'bg-gray-500';
    }
  };

  const formatTimeAgo = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    return date.toLocaleDateString();
  };

  const filterOptions = [
    { value: 'all', label: 'All Activities' },
    { value: 'tutorial_complete', label: 'Tutorials' },
    { value: 'achievement_unlock', label: 'Achievements' },
    { value: 'typing_game', label: 'Typing Games' },
    { value: 'login', label: 'Logins' },
  ];

  const filteredActivities = activities.filter(a => {
    if (filter !== 'all' && a.type !== filter) return false;
    if (searchTerm && !a.title.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !a.user.username.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Activity Log
        </h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">
          View all user activities across the platform
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search activities..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Filter dropdown */}
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="pl-10 pr-8 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 appearance-none"
          >
            {filterOptions.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Activity List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : filteredActivities.length === 0 ? (
          <div className="text-center py-12">
            <Activity className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">No activities found</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {filteredActivities.map((activity) => {
              const Icon = getActivityIcon(activity.type);

              return (
                <div key={activity.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                  <div className="flex items-start gap-4">
                    {/* Icon */}
                    <div className={`p-2 rounded-full ${getActivityColor(activity.type)} flex-shrink-0`}>
                      <Icon className="w-4 h-4 text-white" />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {activity.title}
                      </p>
                      {activity.description && (
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {activity.description}
                        </p>
                      )}
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-400">
                        <span>@{activity.user.username}</span>
                        <span>{formatTimeAgo(activity.timestamp)}</span>
                        {activity.xp_earned && (
                          <span className="text-primary font-medium">+{activity.xp_earned} XP</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default ActivityLogPage;
