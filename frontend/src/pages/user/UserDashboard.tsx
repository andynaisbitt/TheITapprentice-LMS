// src/pages/user/UserDashboard.tsx
/**
 * User Dashboard - Enhanced with XP, Achievements, and Activity
 * Shows personalized learning progress and stats
 */

import { useAuth } from '../../state/contexts/AuthContext';
import { Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
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
  Keyboard,
  Trophy,
  Target,
  Zap,
  Clock,
  ChevronRight,
  Play,
} from 'lucide-react';
import * as tutorialApi from '../../plugins/tutorials/services/tutorialApi';
import type { TutorialProgress } from '../../plugins/tutorials/types';
import { progressApi } from '../../plugins/shared/services/progressApi';
import type { DashboardData, AchievementProgress } from '../../plugins/shared/types';
import { XPProgressBar } from '../../plugins/shared/components/XPProgressBar';
import { StreakCounter } from '../../plugins/shared/components/StreakCounter';
import { AchievementBadge } from '../../plugins/shared/components/AchievementBadge';

export const UserDashboard = () => {
  const { user, logout } = useAuth();
  const [tutorialProgress, setTutorialProgress] = useState<TutorialProgress[]>([]);
  const [loadingTutorials, setLoadingTutorials] = useState(true);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [achievements, setAchievements] = useState<AchievementProgress[]>([]);
  const [loadingDashboard, setLoadingDashboard] = useState(true);

  useEffect(() => {
    if (user) {
      loadAllData();
    }
  }, [user]);

  const loadAllData = async () => {
    try {
      setLoadingTutorials(true);
      setLoadingDashboard(true);

      const [progress, dashboard, achievementList] = await Promise.all([
        tutorialApi.getMyTutorialProgress(),
        progressApi.getMyDashboard().catch(() => null),
        progressApi.getMyAchievements().catch(() => []),
      ]);

      setTutorialProgress(progress);
      setDashboardData(dashboard);
      setAchievements(achievementList);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoadingTutorials(false);
      setLoadingDashboard(false);
    }
  };

  if (!user) {
    return null;
  }

  // Role-specific quick actions
  const getQuickActions = () => {
    const actions = [];

    actions.push({
      icon: Play,
      label: 'Typing Game',
      href: '/games/typing',
      color: 'from-blue-500 to-purple-600',
      description: 'Practice typing',
    });

    actions.push({
      icon: BookOpen,
      label: 'Tutorials',
      href: '/tutorials',
      color: 'from-green-500 to-teal-600',
      description: 'Learn new skills',
    });

    actions.push({
      icon: Trophy,
      label: 'Leaderboard',
      href: '/leaderboard',
      color: 'from-yellow-500 to-orange-600',
      description: 'See top learners',
    });

    // Authors and above can write blog posts
    if (user.role === 'author' || user.can_write_blog || user.is_admin) {
      actions.push({
        icon: Edit,
        label: 'Write Post',
        href: '/admin/blog',
        color: 'from-pink-500 to-rose-600',
        description: 'Create blog content',
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

  // Get recent unlocked achievements
  const recentAchievements = achievements
    .filter((a) => a.is_unlocked)
    .slice(0, 4);

  // Get in-progress achievements
  const inProgressAchievements = achievements
    .filter((a) => !a.is_unlocked && a.progress > 0)
    .sort((a, b) => b.progress_percent - a.progress_percent)
    .slice(0, 3);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-8 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Welcome Header with XP */}
        <div className="mb-8">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
                Welcome back, {user.first_name}! 👋
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Keep up the great work on your learning journey
              </p>
            </div>

            {/* Streak Counter (Compact) */}
            <StreakCounter
              streak={dashboardData?.stats.current_streak || user.current_streak || 0}
              compact
            />
          </div>
        </div>

        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Profile & Progress */}
          <div className="lg:col-span-2 space-y-6">
            {/* XP Progress Card */}
            {dashboardData?.stats.level_progress && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <XPProgressBar
                  progress={dashboardData.stats.level_progress}
                  showDetails
                />
              </motion.div>
            )}

            {/* Quick Actions */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 mb-4">
                Quick Actions
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {quickActions.map((action, index) => (
                  <Link
                    key={index}
                    to={action.href}
                    className="group relative overflow-hidden bg-white dark:bg-gray-800 rounded-xl shadow hover:shadow-lg transition-all"
                  >
                    <div className={`absolute inset-0 bg-gradient-to-br ${action.color} opacity-0 group-hover:opacity-10 transition-opacity`} />
                    <div className="p-4 text-center">
                      <div className={`w-12 h-12 mx-auto mb-2 rounded-xl bg-gradient-to-br ${action.color} flex items-center justify-center`}>
                        <action.icon className="w-6 h-6 text-white" />
                      </div>
                      <div className="font-medium text-gray-900 dark:text-white text-sm">
                        {action.label}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {action.description}
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            </motion.div>

            {/* Stats Grid */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="grid grid-cols-2 sm:grid-cols-4 gap-4"
            >
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-4">
                <div className="flex items-center gap-2 mb-2">
                  <BookOpen className="w-5 h-5 text-blue-500" />
                  <span className="text-sm text-gray-500 dark:text-gray-400">Tutorials</span>
                </div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dashboardData?.stats.tutorials_completed || tutorialProgress.filter(p => p.status === 'completed').length}
                </div>
                <div className="text-xs text-gray-500">completed</div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Keyboard className="w-5 h-5 text-purple-500" />
                  <span className="text-sm text-gray-500 dark:text-gray-400">Games</span>
                </div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dashboardData?.stats.typing_games_played || 0}
                </div>
                <div className="text-xs text-gray-500">played</div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  <span className="text-sm text-gray-500 dark:text-gray-400">Best WPM</span>
                </div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dashboardData?.stats.best_wpm?.toFixed(0) || '-'}
                </div>
                <div className="text-xs text-gray-500">words/min</div>
              </div>

              <div className="bg-white dark:bg-gray-800 rounded-xl shadow p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Target className="w-5 h-5 text-green-500" />
                  <span className="text-sm text-gray-500 dark:text-gray-400">Accuracy</span>
                </div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {dashboardData?.stats.avg_accuracy?.toFixed(1) || '-'}%
                </div>
                <div className="text-xs text-gray-500">average</div>
              </div>
            </motion.div>

            {/* Tutorial Progress Section */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="bg-white dark:bg-gray-800 rounded-xl shadow"
            >
              <div className="p-4 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
                <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                  <BookOpen className="w-5 h-5 text-blue-500" />
                  Continue Learning
                </h3>
                <Link
                  to="/tutorials"
                  className="text-blue-500 hover:text-blue-600 text-sm font-medium flex items-center gap-1"
                >
                  View All <ChevronRight className="w-4 h-4" />
                </Link>
              </div>

              <div className="p-4">
                {loadingTutorials ? (
                  <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                  </div>
                ) : tutorialProgress.filter(p => p.status === 'in_progress').length > 0 ? (
                  <div className="space-y-3">
                    {tutorialProgress
                      .filter(p => p.status === 'in_progress')
                      .slice(0, 3)
                      .map((progress) => (
                        <Link
                          key={progress.id}
                          to={`/tutorials/${progress.tutorial_id}`}
                          className="block p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <p className="font-medium text-gray-900 dark:text-gray-100">
                              Tutorial #{progress.tutorial_id}
                            </p>
                            <span className="text-sm text-gray-500 flex items-center gap-1">
                              <Clock className="w-4 h-4" />
                              {progress.time_spent_minutes} mins
                            </span>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="flex-1 bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                              <div
                                className="bg-blue-600 h-2 rounded-full transition-all"
                                style={{ width: `${progress.progress_percentage || 0}%` }}
                              ></div>
                            </div>
                            <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                              {progress.progress_percentage || 0}%
                            </span>
                          </div>
                        </Link>
                      ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <BookOpen className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                    <p className="text-gray-600 dark:text-gray-400 mb-3">
                      Start a tutorial to begin learning!
                    </p>
                    <Link
                      to="/tutorials"
                      className="inline-flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition"
                    >
                      <BookOpen className="w-4 h-4" />
                      Browse Tutorials
                    </Link>
                  </div>
                )}
              </div>
            </motion.div>
          </div>

          {/* Right Column - Achievements & Profile */}
          <div className="space-y-6">
            {/* Profile Card */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white dark:bg-gray-800 rounded-xl shadow p-6"
            >
              <div className="flex items-center gap-4 mb-4">
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-white font-bold text-xl">
                  {user.first_name[0]}{user.last_name[0]}
                </div>
                <div>
                  <h3 className="font-bold text-gray-900 dark:text-white flex items-center gap-2">
                    {user.first_name} {user.last_name}
                    {user.is_admin && <Shield className="w-4 h-4 text-purple-500" />}
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">@{user.username}</p>
                  <span className={`inline-block mt-1 px-2 py-0.5 rounded-full text-xs font-medium ${getRoleBadgeColor(user.role)}`}>
                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                  </span>
                </div>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Mail className="w-4 h-4" />
                  <span className="truncate">{user.email}</span>
                </div>
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Calendar className="w-4 h-4" />
                  <span>Joined {new Date(user.created_at || '').toLocaleDateString()}</span>
                </div>
              </div>

              <div className="flex gap-2 mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
                <Link
                  to="/profile"
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition text-sm"
                >
                  <Settings className="w-4 h-4" />
                  Profile
                </Link>
                <button
                  onClick={logout}
                  className="flex items-center justify-center gap-2 px-3 py-2 text-red-600 dark:text-red-400 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition text-sm"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            </motion.div>

            {/* Recent Achievements */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="bg-white dark:bg-gray-800 rounded-xl shadow"
            >
              <div className="p-4 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
                <h3 className="font-bold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                  <Trophy className="w-5 h-5 text-yellow-500" />
                  Achievements
                </h3>
                <span className="text-sm text-gray-500">
                  {achievements.filter(a => a.is_unlocked).length}/{achievements.length}
                </span>
              </div>

              <div className="p-4">
                {recentAchievements.length > 0 ? (
                  <div className="grid grid-cols-4 gap-2">
                    {recentAchievements.map((achievement) => (
                      <AchievementBadge
                        key={achievement.achievement_id}
                        achievement={achievement}
                        size="sm"
                        showProgress={false}
                      />
                    ))}
                  </div>
                ) : (
                  <p className="text-center text-gray-500 dark:text-gray-400 text-sm py-4">
                    Complete activities to unlock achievements!
                  </p>
                )}

                {/* In Progress Achievements */}
                {inProgressAchievements.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
                    <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">In Progress</p>
                    {inProgressAchievements.map((achievement) => (
                      <div
                        key={achievement.achievement_id}
                        className="flex items-center gap-2 mb-2"
                      >
                        <div className="flex-1">
                          <div className="text-xs font-medium text-gray-700 dark:text-gray-300 truncate">
                            {achievement.name}
                          </div>
                          <div className="h-1 bg-gray-200 dark:bg-gray-700 rounded-full mt-1">
                            <div
                              className="h-1 bg-blue-500 rounded-full"
                              style={{ width: `${achievement.progress_percent}%` }}
                            />
                          </div>
                        </div>
                        <span className="text-xs text-gray-500">
                          {achievement.progress}/{achievement.progress_max}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>

            {/* Recent Activity */}
            {dashboardData?.recent_activities && dashboardData.recent_activities.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="bg-white dark:bg-gray-800 rounded-xl shadow"
              >
                <div className="p-4 border-b border-gray-100 dark:border-gray-700">
                  <h3 className="font-bold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                    <TrendingUp className="w-5 h-5 text-green-500" />
                    Recent Activity
                  </h3>
                </div>

                <div className="p-4 space-y-3">
                  {dashboardData.recent_activities.slice(0, 5).map((activity) => (
                    <div
                      key={activity.id}
                      className="flex items-start gap-3 text-sm"
                    >
                      <div className="w-2 h-2 mt-2 rounded-full bg-blue-500" />
                      <div className="flex-1">
                        <p className="text-gray-700 dark:text-gray-300">{activity.title}</p>
                        <p className="text-xs text-gray-500">
                          {new Date(activity.created_at).toLocaleString()}
                          {activity.xp_earned > 0 && (
                            <span className="ml-2 text-green-500">+{activity.xp_earned} XP</span>
                          )}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserDashboard;
