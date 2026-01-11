// src/pages/user/UserDashboard.tsx
/**
 * User Dashboard - For non-admin users
 * Shows personalized content based on user role
 */

import { useAuth } from '../../state/contexts/AuthContext';
import { Link } from 'react-router-dom';
import {
  User,
  Mail,
  Calendar,
  Award,
  TrendingUp,
  BookOpen,
  Settings,
  LogOut,
  Shield,
  Edit,
  Heart,
} from 'lucide-react';

export const UserDashboard = () => {
  const { user, logout } = useAuth();

  if (!user) {
    return null;
  }

  // Role-specific quick actions
  const getQuickActions = () => {
    const actions = [];

    // Everyone gets profile
    actions.push({
      icon: User,
      label: 'Edit Profile',
      href: '/profile',
      color: 'blue',
    });

    // Authors and above can write blog posts
    if (user.role === 'author' || user.can_write_blog || user.is_admin) {
      actions.push({
        icon: Edit,
        label: 'Write Blog Post',
        href: '/admin/blog',
        color: 'green',
      });
    }

    // Tutors can create courses (future feature)
    if (user.role === 'tutor' || user.role === 'mentor') {
      actions.push({
        icon: BookOpen,
        label: 'My Courses',
        href: '/courses',
        color: 'purple',
      });
    }

    // Contributors and mentors
    if (user.role === 'contributor' || user.role === 'mentor') {
      actions.push({
        icon: Heart,
        label: 'Contribute',
        href: '/contribute',
        color: 'pink',
      });
    }

    return actions;
  };

  const quickActions = getQuickActions();

  const getRoleBadgeColor = (role: string) => {
    const colors: Record<string, string> = {
      admin: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
      author: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
      tutor: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
      mentor: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400',
      contributor: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
      supporter: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
      apprentice: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    };
    return colors[role] || colors.apprentice;
  };

  const getActionButtonColor = (color: string) => {
    const colors: Record<string, string> = {
      blue: 'bg-blue-600 hover:bg-blue-700',
      green: 'bg-green-600 hover:bg-green-700',
      purple: 'bg-purple-600 hover:bg-purple-700',
      pink: 'bg-pink-600 hover:bg-pink-700',
    };
    return colors[color] || colors.blue;
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-8 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Welcome Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
            Welcome back, {user.first_name}! 👋
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Here's what's happening with your account
          </p>
        </div>

        {/* Profile Summary Card */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-lg border border-gray-200 dark:border-slate-700 p-6 mb-8">
          <div className="flex items-start gap-6">
            {/* Avatar */}
            <div className="w-24 h-24 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-white font-bold text-3xl flex-shrink-0">
              {user.first_name[0]}
              {user.last_name[0]}
            </div>

            {/* User Info */}
            <div className="flex-1">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 flex items-center gap-3">
                    {user.first_name} {user.last_name}
                    {user.is_admin && (
                      <Shield className="w-5 h-5 text-purple-600" />
                    )}
                  </h2>
                  <p className="text-gray-600 dark:text-gray-400">@{user.username}</p>
                </div>

                <span className={`px-3 py-1 rounded-full text-sm font-medium ${getRoleBadgeColor(user.role)}`}>
                  {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                </span>
              </div>

              {/* User Details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Mail size={16} />
                  <span>{user.email}</span>
                </div>
                {user.last_login && (
                  <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                    <Calendar size={16} />
                    <span>Last login: {new Date(user.last_login).toLocaleDateString()}</span>
                  </div>
                )}
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Award size={16} />
                  <span>Level {user.level} • {user.total_points} points</span>
                </div>
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <TrendingUp size={16} />
                  <span>{user.login_count} total logins</span>
                </div>
              </div>

              {/* Status Badges */}
              <div className="flex gap-2 mt-4">
                {user.is_verified && (
                  <span className="px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                    Verified
                  </span>
                )}
                {user.google_id && (
                  <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                    Google Account
                  </span>
                )}
                {user.can_write_blog && (
                  <span className="px-2 py-1 rounded text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                    Can Write Blog
                  </span>
                )}
                {user.can_moderate && (
                  <span className="px-2 py-1 rounded text-xs font-medium bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400">
                    Can Moderate
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        {quickActions.length > 0 && (
          <div className="mb-8">
            <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">Quick Actions</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {quickActions.map((action, index) => (
                <Link
                  key={index}
                  to={action.href}
                  className={`flex items-center gap-3 p-4 ${getActionButtonColor(action.color)} text-white rounded-lg shadow hover:shadow-lg transition`}
                >
                  <action.icon size={24} />
                  <span className="font-medium">{action.label}</span>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-6">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Points</h4>
              <Award className="w-5 h-5 text-yellow-500" />
            </div>
            <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">{user.total_points}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Keep learning to earn more!</p>
          </div>

          <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-6">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400">Current Level</h4>
              <TrendingUp className="w-5 h-5 text-green-500" />
            </div>
            <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">{user.level}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Level up by completing tasks</p>
          </div>

          <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-6">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400">Subscription</h4>
              <Heart className="w-5 h-5 text-pink-500" />
            </div>
            <p className="text-3xl font-bold text-gray-900 dark:text-gray-100 capitalize">
              {user.subscription_status}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              {user.subscription_status === 'free' ? 'Upgrade to unlock more' : 'Active subscription'}
            </p>
          </div>
        </div>

        {/* Account Actions */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-6">
          <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 mb-4">Account Settings</h3>
          <div className="flex flex-wrap gap-3">
            <Link
              to="/profile"
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 transition"
            >
              <Settings size={18} />
              Edit Profile
            </Link>
            <button
              onClick={logout}
              className="flex items-center gap-2 px-4 py-2 border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition"
            >
              <LogOut size={18} />
              Logout
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserDashboard;
