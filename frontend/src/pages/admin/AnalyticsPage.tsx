// src/pages/admin/AnalyticsPage.tsx
/**
 * Site Analytics Dashboard
 * Real-time overview of content, users, and engagement stats
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Eye,
  Users,
  FileText,
  BookOpen,
  Library,
  Keyboard,
  ClipboardList,
  Clock,
  ArrowUpRight,
  ArrowDownRight,
  Loader2,
  AlertCircle,
  RefreshCw,
  Trophy,
  Zap,
  GraduationCap,
} from 'lucide-react';
import { adminStatsApi, DashboardResponse, ContentStats } from '../../services/api/admin-stats.api';

interface StatCard {
  label: string;
  value: string | number;
  change?: number;
  icon: React.ElementType;
  color: string;
  link?: string;
}

export const AnalyticsPage: React.FC = () => {
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [dashboardData, setDashboardData] = useState<DashboardResponse | null>(null);
  const [contentStats, setContentStats] = useState<ContentStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [dashboard, content] = await Promise.all([
        adminStatsApi.getDashboard(),
        adminStatsApi.getContentStats(),
      ]);
      setDashboardData(dashboard);
      setContentStats(content);
    } catch (err: any) {
      console.error('Failed to load analytics:', err);
      setError(err.response?.data?.detail || 'Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-red-600" />
            <p className="text-red-800 dark:text-red-200">{error}</p>
          </div>
          <button
            onClick={loadData}
            className="mt-3 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const stats = dashboardData?.stats;

  // Build stat cards from real data
  const overviewStats: StatCard[] = [
    {
      label: 'Total Views',
      value: stats?.total_views?.toLocaleString() || '0',
      icon: Eye,
      color: 'blue',
      link: '/admin/posts',
    },
    {
      label: 'Total Users',
      value: stats?.total_users?.toLocaleString() || '0',
      icon: Users,
      color: 'green',
      link: '/admin/users',
    },
    {
      label: 'Active Users',
      value: stats?.active_users?.toLocaleString() || '0',
      icon: Users,
      color: 'emerald',
      link: '/admin/users',
    },
    {
      label: 'New Users (30d)',
      value: stats?.new_users_this_month?.toLocaleString() || '0',
      change: dashboardData?.trends?.find(t => t.label === 'New Users')?.change,
      icon: TrendingUp,
      color: 'purple',
    },
  ];

  const contentStatCards: StatCard[] = [
    {
      label: 'Total Posts',
      value: stats?.total_posts || 0,
      icon: FileText,
      color: 'blue',
      link: '/admin/posts',
    },
    {
      label: 'Draft Posts',
      value: stats?.draft_posts || 0,
      icon: FileText,
      color: 'orange',
      link: '/admin/posts?status=draft',
    },
    {
      label: 'Categories',
      value: stats?.total_categories || 0,
      icon: BarChart3,
      color: 'indigo',
      link: '/admin/categories',
    },
    {
      label: 'Tags',
      value: stats?.total_tags || 0,
      icon: BarChart3,
      color: 'pink',
      link: '/admin/tags',
    },
  ];

  const lmsStats: StatCard[] = [
    {
      label: 'Tutorials',
      value: `${stats?.tutorials_published || 0} / ${stats?.total_tutorials || 0}`,
      icon: BookOpen,
      color: 'purple',
      link: '/admin/tutorials',
    },
    {
      label: 'Courses',
      value: `${stats?.courses_published || 0} / ${stats?.total_courses || 0}`,
      icon: Library,
      color: 'green',
      link: '/admin/courses',
    },
    {
      label: 'Enrollments',
      value: stats?.total_enrollments?.toLocaleString() || '0',
      icon: GraduationCap,
      color: 'blue',
      link: '/admin/courses/enrollments',
    },
    {
      label: 'Games Played',
      value: stats?.typing_games_played?.toLocaleString() || '0',
      icon: Keyboard,
      color: 'orange',
      link: '/admin/games/leaderboard',
    },
  ];

  const gamificationStats: StatCard[] = [
    {
      label: 'Total XP Awarded',
      value: stats?.total_xp_awarded?.toLocaleString() || '0',
      icon: Zap,
      color: 'yellow',
      link: '/admin/xp-config',
    },
  ];

  const getColorClasses = (color: string): string => {
    const colorMap: Record<string, string> = {
      blue: 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400',
      green: 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400',
      emerald: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400',
      purple: 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400',
      orange: 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400',
      indigo: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400',
      pink: 'bg-pink-100 dark:bg-pink-900/30 text-pink-600 dark:text-pink-400',
      yellow: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400',
    };
    return colorMap[color] || colorMap.blue;
  };

  const renderStatCard = (stat: StatCard, index: number) => {
    const Icon = stat.icon;
    const content = (
      <div
        key={`${stat.label}-${index}`}
        className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 hover:shadow-md transition-shadow"
      >
        <div className="flex items-center justify-between">
          <div className={`p-3 rounded-lg ${getColorClasses(stat.color)}`}>
            <Icon className="w-5 h-5" />
          </div>
          {stat.change !== undefined && stat.change !== null && (
            <div
              className={`flex items-center gap-1 text-sm font-medium ${
                stat.change >= 0 ? 'text-green-600' : 'text-red-600'
              }`}
            >
              {stat.change >= 0 ? (
                <ArrowUpRight className="w-4 h-4" />
              ) : (
                <ArrowDownRight className="w-4 h-4" />
              )}
              {Math.abs(stat.change)}%
            </div>
          )}
        </div>
        <div className="mt-4">
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{stat.value}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">{stat.label}</p>
        </div>
      </div>
    );

    if (stat.link) {
      return (
        <Link key={`${stat.label}-${index}`} to={stat.link} className="block">
          {content}
        </Link>
      );
    }

    return content;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Analytics</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Real-time overview of your site's performance
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
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
      </div>

      {/* Overview Stats */}
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Overview</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {overviewStats.map((stat, i) => renderStatCard(stat, i))}
        </div>
      </div>

      {/* Content Stats */}
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Content</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {contentStatCards.map((stat, i) => renderStatCard(stat, i))}
        </div>
      </div>

      {/* LMS Stats */}
      {(stats?.total_tutorials || stats?.total_courses || stats?.typing_games_played) ? (
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Learning Management (LMS)
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {lmsStats.map((stat, i) => renderStatCard(stat, i))}
          </div>
        </div>
      ) : null}

      {/* Gamification Stats */}
      {stats?.total_xp_awarded ? (
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Gamification</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {gamificationStats.map((stat, i) => renderStatCard(stat, i))}
          </div>
        </div>
      ) : null}

      {/* Trends */}
      {dashboardData?.trends && dashboardData.trends.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Trends</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {dashboardData.trends.map((trend, index) => (
              <div key={index} className="flex items-center gap-4 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <div className="p-3 bg-primary/10 rounded-lg">
                  <TrendingUp className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{trend.value}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{trend.label}</p>
                  {trend.change !== undefined && (
                    <p
                      className={`text-xs flex items-center gap-1 mt-1 ${
                        trend.change >= 0 ? 'text-green-600' : 'text-red-600'
                      }`}
                    >
                      {trend.change >= 0 ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                      {Math.abs(trend.change)}% {trend.change_label}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* System Status */}
      {dashboardData?.system_status && dashboardData.system_status.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">System Status</h2>
          <div className="space-y-3">
            {dashboardData.system_status.map((status) => (
              <div
                key={status.id}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-3 h-3 rounded-full ${
                      status.status === 'healthy'
                        ? 'bg-green-500'
                        : status.status === 'warning'
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    }`}
                  />
                  <span className="font-medium text-gray-900 dark:text-white">{status.name}</span>
                </div>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {status.message || status.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attention Items */}
      {dashboardData?.attention_items && dashboardData.attention_items.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Needs Attention</h2>
          <div className="space-y-3">
            {dashboardData.attention_items.map((item) => (
              <Link
                key={item.id}
                to={item.link}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`px-3 py-1 rounded-full text-sm font-medium ${
                      item.priority === 'high'
                        ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                        : item.priority === 'medium'
                        ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                        : 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                    }`}
                  >
                    {item.count}
                  </div>
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">{item.title}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{item.description}</p>
                  </div>
                </div>
                <ArrowUpRight className="w-5 h-5 text-gray-400" />
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Last Updated */}
      {dashboardData?.last_updated && (
        <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
          Last updated: {new Date(dashboardData.last_updated).toLocaleString()}
        </p>
      )}
    </div>
  );
};

export default AnalyticsPage;
