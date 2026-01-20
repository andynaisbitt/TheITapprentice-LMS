// src/pages/admin/AdminDashboard.tsx
/**
 * Admin Dashboard - Central hub for blog administration
 * Features: Quick stats, recent activity, attention items, system status
 */

import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  FileText,
  Users,
  BookOpen,
  GraduationCap,
  Keyboard,
  Eye,
  Plus,
  ArrowRight,
} from 'lucide-react';
import { blogApi } from '../../services/api';
import { useAuth } from '../../state/contexts/AuthContext';
import {
  QuickStatsCard,
  RecentActivityFeed,
  AttentionItems,
  SystemStatus,
  type ActivityItem,
  type AttentionItem,
  type SystemStatusItem,
} from '../../components/admin/dashboard';

interface DashboardStats {
  total_posts: number;
  total_categories: number;
  total_views: number;
  total_tags: number;
  draft_posts?: number;
  total_users?: number;
  total_tutorials?: number;
  total_courses?: number;
}

// Helper to get greeting based on time
const getGreeting = () => {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
};

// Format date
const formatDate = () => {
  return new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
};

export const AdminDashboard: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [stats, setStats] = useState<DashboardStats>({
    total_posts: 0,
    total_categories: 0,
    total_views: 0,
    total_tags: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Mock data for features not yet connected to API
  const [activities] = useState<ActivityItem[]>([
    {
      id: '1',
      type: 'post_published',
      title: 'New post published',
      description: 'Docker Guide for Beginners',
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      user: { name: 'Admin' },
    },
    {
      id: '2',
      type: 'user_registered',
      title: 'New user registered',
      description: 'sarah@example.com',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    },
    {
      id: '3',
      type: 'tutorial_completed',
      title: 'Tutorial completed',
      description: 'Python Basics by john_doe',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
      user: { name: 'John' },
    },
    {
      id: '4',
      type: 'achievement_unlocked',
      title: 'Achievement unlocked',
      description: 'Speed Demon (80+ WPM)',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
      user: { name: 'Mike' },
    },
  ]);

  const [attentionItems] = useState<AttentionItem[]>([
    {
      id: '1',
      type: 'draft_posts',
      title: 'Draft Posts',
      count: 3,
      description: 'Posts awaiting publication',
      link: '/admin/posts?status=draft',
      priority: 'medium',
    },
    {
      id: '2',
      type: 'pending_users',
      title: 'Unverified Users',
      count: 2,
      description: 'Users pending email verification',
      link: '/admin/users?verified=false',
      priority: 'low',
    },
  ]);

  const [systemStatus] = useState<SystemStatusItem[]>([
    { id: 'api', name: 'API Server', status: 'healthy' },
    { id: 'database', name: 'Database', status: 'healthy' },
    { id: 'plugins', name: 'Plugins', status: 'healthy', message: '3/4 active' },
  ]);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      const statsData = await blogApi.getStats();
      setStats(statsData);
    } catch (err: any) {
      console.error('Error loading dashboard data:', err);
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <p className="text-red-600 dark:text-red-400">{error}</p>
          <button
            onClick={loadDashboardData}
            className="mt-2 text-sm text-red-700 dark:text-red-300 hover:underline"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            {getGreeting()}, {user?.first_name || user?.username || 'Admin'}!
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">{formatDate()}</p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/admin/blog"
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors font-medium"
          >
            <Plus className="w-4 h-4" />
            New Post
          </Link>
        </div>
      </div>

      {/* Quick Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <QuickStatsCard
          title="Total Posts"
          value={stats.total_posts}
          icon={FileText}
          color="blue"
          trend={{ value: 12, label: 'this month' }}
          onClick={() => navigate('/admin/posts')}
        />
        <QuickStatsCard
          title="Total Views"
          value={stats.total_views >= 1000 ? `${(stats.total_views / 1000).toFixed(1)}K` : stats.total_views}
          icon={Eye}
          color="green"
          trend={{ value: 8, label: 'this week' }}
        />
        <QuickStatsCard
          title="Users"
          value={stats.total_users || 0}
          icon={Users}
          color="purple"
          trend={{ value: 5, label: 'this month' }}
          onClick={() => navigate('/admin/users')}
        />
        <QuickStatsCard
          title="Tutorials"
          value={stats.total_tutorials || 0}
          icon={BookOpen}
          color="orange"
          onClick={() => navigate('/admin/tutorials')}
        />
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div
          onClick={() => navigate('/admin/categories')}
          className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-sm cursor-pointer hover:shadow-md transition-shadow"
        >
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total_categories}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">Categories</p>
        </div>
        <div
          onClick={() => navigate('/admin/tags')}
          className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-sm cursor-pointer hover:shadow-md transition-shadow"
        >
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total_tags}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">Tags</p>
        </div>
        <div
          onClick={() => navigate('/admin/courses')}
          className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-sm cursor-pointer hover:shadow-md transition-shadow"
        >
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total_courses || 0}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">Courses</p>
        </div>
        <div
          onClick={() => navigate('/games/typing/leaderboard')}
          className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-sm cursor-pointer hover:shadow-md transition-shadow"
        >
          <div className="flex items-center gap-2">
            <Keyboard className="w-5 h-5 text-pink-500" />
            <p className="text-sm text-gray-500 dark:text-gray-400">Typing Games</p>
          </div>
          <p className="text-sm text-primary mt-1">View Leaderboard</p>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity */}
        <div className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent Activity
            </h2>
            <Link
              to="/admin/activity"
              className="text-sm text-primary hover:underline flex items-center gap-1"
            >
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <RecentActivityFeed activities={activities} loading={loading} />
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Attention Items */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Needs Attention
            </h2>
            <AttentionItems items={attentionItems} loading={loading} />
          </div>

          {/* System Status */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              System Status
            </h2>
            <SystemStatus items={systemStatus} loading={loading} />
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Quick Actions
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <Link
            to="/admin/blog"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors"
          >
            <FileText className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">New Post</span>
          </Link>
          <Link
            to="/admin/tutorials/new"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-purple-50 dark:bg-purple-900/20 hover:bg-purple-100 dark:hover:bg-purple-900/30 transition-colors"
          >
            <BookOpen className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">New Tutorial</span>
          </Link>
          <Link
            to="/admin/courses/new"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-green-50 dark:bg-green-900/20 hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors"
          >
            <GraduationCap className="w-6 h-6 text-green-600 dark:text-green-400" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">New Course</span>
          </Link>
          <Link
            to="/admin/pages/new"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-orange-50 dark:bg-orange-900/20 hover:bg-orange-100 dark:hover:bg-orange-900/30 transition-colors"
          >
            <FileText className="w-6 h-6 text-orange-600 dark:text-orange-400" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">New Page</span>
          </Link>
          <Link
            to="/admin/users"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-pink-50 dark:bg-pink-900/20 hover:bg-pink-100 dark:hover:bg-pink-900/30 transition-colors"
          >
            <Users className="w-6 h-6 text-pink-600 dark:text-pink-400" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Users</span>
          </Link>
          <a
            href="/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          >
            <Eye className="w-6 h-6 text-gray-600 dark:text-gray-400" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">View Site</span>
          </a>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
