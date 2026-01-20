// src/pages/admin/AnalyticsPage.tsx
/**
 * Site Analytics Dashboard
 * Overview of traffic, engagement, and content performance
 */

import { useState } from 'react';
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Eye,
  Users,
  FileText,
  BookOpen,
  Clock,
  ArrowUpRight,
  ArrowDownRight,
} from 'lucide-react';

interface StatCard {
  label: string;
  value: string;
  change: number;
  icon: React.ElementType;
  color: string;
}

interface TopContent {
  id: number;
  title: string;
  type: 'post' | 'tutorial' | 'course';
  views: number;
  change: number;
}

export const AnalyticsPage: React.FC = () => {
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');

  const stats: StatCard[] = [
    { label: 'Page Views', value: '12,847', change: 12.5, icon: Eye, color: 'blue' },
    { label: 'Unique Visitors', value: '3,421', change: 8.2, icon: Users, color: 'green' },
    { label: 'Avg. Session', value: '4m 32s', change: -2.1, icon: Clock, color: 'purple' },
    { label: 'Bounce Rate', value: '42.3%', change: -5.4, icon: TrendingDown, color: 'orange' },
  ];

  const topContent: TopContent[] = [
    { id: 1, title: 'Getting Started with Docker', type: 'post', views: 2341, change: 15.2 },
    { id: 2, title: 'Python Basics Tutorial', type: 'tutorial', views: 1892, change: 8.7 },
    { id: 3, title: 'Linux Commands Cheat Sheet', type: 'post', views: 1456, change: -3.2 },
    { id: 4, title: 'Git for Beginners', type: 'tutorial', views: 1234, change: 22.1 },
    { id: 5, title: 'Web Development Fundamentals', type: 'course', views: 987, change: 5.6 },
  ];

  const getTypeIcon = (type: TopContent['type']) => {
    switch (type) {
      case 'post': return FileText;
      case 'tutorial': return BookOpen;
      case 'course': return BarChart3;
    }
  };

  const getTypeColor = (type: TopContent['type']) => {
    switch (type) {
      case 'post': return 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400';
      case 'tutorial': return 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400';
      case 'course': return 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Analytics
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Track your site's performance and engagement
          </p>
        </div>
        <div className="flex items-center gap-2 bg-white dark:bg-gray-800 rounded-lg p-1">
          {(['7d', '30d', '90d'] as const).map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                timeRange === range
                  ? 'bg-primary text-white'
                  : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
            >
              {range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : '90 Days'}
            </button>
          ))}
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          const isPositive = stat.change > 0;
          const colorClasses: Record<string, string> = {
            blue: 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400',
            green: 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400',
            purple: 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400',
            orange: 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400',
          };

          return (
            <div
              key={stat.label}
              className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6"
            >
              <div className="flex items-center justify-between">
                <div className={`p-3 rounded-lg ${colorClasses[stat.color]}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div className={`flex items-center gap-1 text-sm font-medium ${
                  isPositive ? 'text-green-600' : 'text-red-600'
                }`}>
                  {isPositive ? (
                    <ArrowUpRight className="w-4 h-4" />
                  ) : (
                    <ArrowDownRight className="w-4 h-4" />
                  )}
                  {Math.abs(stat.change)}%
                </div>
              </div>
              <div className="mt-4">
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {stat.value}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {stat.label}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Placeholder */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Traffic Overview
          </h2>
          <div className="h-64 flex items-center justify-center border-2 border-dashed border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="text-center">
              <BarChart3 className="w-12 h-12 mx-auto mb-2 text-gray-400" />
              <p className="text-gray-500 dark:text-gray-400">
                Chart visualization coming soon
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Will integrate with analytics API
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            User Engagement
          </h2>
          <div className="h-64 flex items-center justify-center border-2 border-dashed border-gray-200 dark:border-gray-700 rounded-lg">
            <div className="text-center">
              <TrendingUp className="w-12 h-12 mx-auto mb-2 text-gray-400" />
              <p className="text-gray-500 dark:text-gray-400">
                Engagement metrics coming soon
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Tutorial completions, game plays, etc.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Top Content */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Top Content
        </h2>
        <div className="space-y-4">
          {topContent.map((content, index) => {
            const TypeIcon = getTypeIcon(content.type);

            return (
              <div
                key={content.id}
                className="flex items-center gap-4 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
              >
                <span className="w-6 text-center font-bold text-gray-400">
                  {index + 1}
                </span>
                <div className={`p-2 rounded-lg ${getTypeColor(content.type)}`}>
                  <TypeIcon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-gray-900 dark:text-white truncate">
                    {content.title}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                    {content.type}
                  </p>
                </div>
                <div className="text-right">
                  <p className="font-medium text-gray-900 dark:text-white">
                    {content.views.toLocaleString()} views
                  </p>
                  <p className={`text-sm flex items-center justify-end gap-1 ${
                    content.change > 0 ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {content.change > 0 ? (
                      <ArrowUpRight className="w-3 h-3" />
                    ) : (
                      <ArrowDownRight className="w-3 h-3" />
                    )}
                    {Math.abs(content.change)}%
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default AnalyticsPage;
