// src/pages/user/Profile.tsx
/**
 * Enhanced User Profile Page
 * Shows learning stats, achievements, tutorials, game stats, and activity
 */

import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../../state/contexts/AuthContext';
import { authApi } from '../../services/api';
import { progressApi } from '../../plugins/shared/services/progressApi';
import { typingGameApi } from '../../plugins/typing-game/services/typingGameApi';
import * as tutorialApi from '../../plugins/tutorials/services/tutorialApi';
import { XPProgressBar } from '../../plugins/shared/components/XPProgressBar';
import { AchievementBadge } from '../../plugins/shared/components/AchievementBadge';
import { StreakCounter } from '../../plugins/shared/components/StreakCounter';
import { SkillsWidget } from '../../plugins/skills/components/SkillsWidget';
import type { LevelProgress, AchievementProgress, Activity, AchievementCategory } from '../../plugins/shared/types';
import type { UserTypingStats, UserPVPStats } from '../../plugins/typing-game/types';
import type { TutorialProgress } from '../../plugins/tutorials/types';
import {
  User,
  Mail,
  Lock,
  Save,
  Loader2,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  Trophy,
  BookOpen,
  Keyboard,
  TrendingUp,
  Calendar,
  Target,
  Zap,
  Award,
  Flame,
  Star,
  Edit,
  ChevronRight,
  Clock,
  Gamepad2,
} from 'lucide-react';

type ProfileTab = 'overview' | 'achievements' | 'tutorials' | 'games' | 'activity' | 'settings';

export const Profile = () => {
  const { username } = useParams<{ username?: string }>();
  const { user, updateUserProfile } = useAuth();

  // Determine if viewing own profile or another user's
  const isOwnProfile = !username || username === user?.username;
  const [activeTab, setActiveTab] = useState<ProfileTab>('overview');

  // Profile edit state
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  // Profile form state
  const [profileForm, setProfileForm] = useState({
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    bio: user?.bio || '',
  });

  // Password form state
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });

  // Learning data state
  const [levelProgress, setLevelProgress] = useState<LevelProgress | null>(null);
  const [achievements, setAchievements] = useState<AchievementProgress[]>([]);
  const [activities, setActivities] = useState<Activity[]>([]);
  const [typingStats, setTypingStats] = useState<UserTypingStats | null>(null);
  const [pvpStats, setPvpStats] = useState<UserPVPStats | null>(null);
  const [tutorialProgress, setTutorialProgress] = useState<TutorialProgress[]>([]);
  const [loadingData, setLoadingData] = useState(true);
  const [achievementFilter, setAchievementFilter] = useState<AchievementCategory | 'all'>('all');

  useEffect(() => {
    if (user) {
      setProfileForm({
        first_name: user.first_name,
        last_name: user.last_name,
        bio: user.bio || '',
      });
      loadLearningData();
    }
  }, [user]);

  const loadLearningData = async () => {
    if (!user) return;
    setLoadingData(true);

    try {
      const [xpProgress, achievementList, activityData, stats, pvp, tutorials] = await Promise.all([
        progressApi.getMyXPProgress().catch(() => null),
        progressApi.getMyAchievements().catch(() => []),
        progressApi.getMyActivities(50).catch(() => ({ activities: [], total: 0, has_more: false })),
        typingGameApi.getMyStats().catch(() => null),
        typingGameApi.getMyPVPStats().catch(() => null),
        tutorialApi.getMyTutorialProgress().catch(() => []),
      ]);

      setLevelProgress(xpProgress);
      setAchievements(achievementList);
      setActivities(activityData.activities);
      setTypingStats(stats);
      setPvpStats(pvp);
      setTutorialProgress(tutorials);
    } catch (err) {
      console.error('Failed to load learning data:', err);
    } finally {
      setLoadingData(false);
    }
  };

  if (!user) {
    return null;
  }

  const handleProfileUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      await authApi.updateProfile(profileForm);
      updateUserProfile(profileForm);
      setSuccess('Profile updated successfully!');
      setIsEditing(false);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setError('New passwords do not match');
      return;
    }

    if (passwordForm.new_password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      await authApi.changePassword({
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
      });

      setSuccess('Password changed successfully!');
      setShowPasswordForm(false);
      setPasswordForm({ current_password: '', new_password: '', confirm_password: '' });
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

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

  // Filter achievements
  const filteredAchievements = achievementFilter === 'all'
    ? achievements
    : achievements.filter(a => a.category === achievementFilter);

  const unlockedAchievements = filteredAchievements.filter(a => a.is_unlocked);
  const lockedAchievements = filteredAchievements.filter(a => !a.is_unlocked);
  const completedTutorials = tutorialProgress.filter(t => t.status === 'completed');
  const inProgressTutorials = tutorialProgress.filter(t => t.status === 'in_progress');

  const tabs: { id: ProfileTab; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <User className="w-4 h-4" /> },
    { id: 'achievements', label: 'Achievements', icon: <Trophy className="w-4 h-4" /> },
    { id: 'tutorials', label: 'Tutorials', icon: <BookOpen className="w-4 h-4" /> },
    { id: 'games', label: 'Game Stats', icon: <Keyboard className="w-4 h-4" /> },
    { id: 'activity', label: 'Activity', icon: <TrendingUp className="w-4 h-4" /> },
    ...(isOwnProfile ? [{ id: 'settings' as ProfileTab, label: 'Settings', icon: <Edit className="w-4 h-4" /> }] : []),
  ];

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'tutorial_complete': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'tutorial_start': return <BookOpen className="w-4 h-4 text-blue-500" />;
      case 'typing_game': return <Keyboard className="w-4 h-4 text-purple-500" />;
      case 'achievement_unlock': return <Trophy className="w-4 h-4 text-yellow-500" />;
      case 'level_up': return <Star className="w-4 h-4 text-orange-500" />;
      case 'streak_milestone': return <Flame className="w-4 h-4 text-red-500" />;
      default: return <Zap className="w-4 h-4 text-gray-500" />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-8 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Success/Error Messages */}
        {success && (
          <div className="mb-6 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
            <p className="text-green-600 dark:text-green-400">{success}</p>
          </div>
        )}
        {error && (
          <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
            <p className="text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        {/* Profile Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-slate-800 rounded-xl shadow-lg p-6 mb-6"
        >
          <div className="flex flex-col md:flex-row md:items-center gap-6">
            {/* Avatar & Basic Info */}
            <div className="flex items-center gap-4">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold text-2xl shadow-lg">
                {user.first_name[0]}{user.last_name[0]}
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                  {user.first_name} {user.last_name}
                </h1>
                <p className="text-gray-500 dark:text-gray-400">@{user.username}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getRoleBadgeColor(user.role)}`}>
                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                  </span>
                  <StreakCounter streak={user.current_streak || 0} compact />
                </div>
              </div>
            </div>

            {/* XP Progress */}
            <div className="flex-1">
              {levelProgress ? (
                <XPProgressBar progress={levelProgress} showDetails />
              ) : (
                <div className="animate-pulse bg-gray-200 dark:bg-gray-700 rounded-lg h-16" />
              )}
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                  {completedTutorials.length}
                </div>
                <div className="text-xs text-gray-500">Tutorials</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                  {typingStats?.total_games_completed || 0}
                </div>
                <div className="text-xs text-gray-500">Games</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                  {achievements.filter(a => a.is_unlocked).length}
                </div>
                <div className="text-xs text-gray-500">Achievements</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                  {typingStats?.best_wpm?.toFixed(0) || '-'}
                </div>
                <div className="text-xs text-gray-500">Best WPM</div>
              </div>
            </div>
          </div>

          {user.bio && (
            <p className="mt-4 text-gray-600 dark:text-gray-400 border-t border-gray-100 dark:border-gray-700 pt-4">
              {user.bio}
            </p>
          )}
        </motion.div>

        {/* Tab Navigation */}
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-lg mb-6 overflow-hidden">
          <div className="flex overflow-x-auto border-b border-gray-100 dark:border-gray-700">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-6 py-4 text-sm font-medium whitespace-nowrap transition ${
                  activeTab === tab.id
                    ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400 bg-blue-50/50 dark:bg-blue-900/10'
                    : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-50 dark:hover:bg-slate-700/50'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {loadingData && activeTab !== 'settings' ? (
              <div className="flex justify-center py-12">
                <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
              </div>
            ) : (
              <>
                {/* Overview Tab */}
                {activeTab === 'overview' && (
                  <div className="space-y-6">
                    {/* Stats Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl p-4 text-white">
                        <BookOpen className="w-6 h-6 mb-2 opacity-80" />
                        <div className="text-3xl font-bold">{completedTutorials.length}</div>
                        <div className="text-sm opacity-80">Tutorials Completed</div>
                      </div>
                      <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl p-4 text-white">
                        <Keyboard className="w-6 h-6 mb-2 opacity-80" />
                        <div className="text-3xl font-bold">{typingStats?.total_games_completed || 0}</div>
                        <div className="text-sm opacity-80">Games Played</div>
                      </div>
                      <div className="bg-gradient-to-br from-yellow-500 to-orange-500 rounded-xl p-4 text-white">
                        <Trophy className="w-6 h-6 mb-2 opacity-80" />
                        <div className="text-3xl font-bold">{achievements.filter(a => a.is_unlocked).length}</div>
                        <div className="text-sm opacity-80">Achievements</div>
                      </div>
                      <div className="bg-gradient-to-br from-green-500 to-teal-500 rounded-xl p-4 text-white">
                        <Zap className="w-6 h-6 mb-2 opacity-80" />
                        <div className="text-3xl font-bold">{user.total_points || 0}</div>
                        <div className="text-sm opacity-80">Total XP</div>
                      </div>
                    </div>

                    {/* IT Skills Widget */}
                    <SkillsWidget maxSkills={6} showLeaderboardLink />

                    {/* Recent Achievements */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                          <Trophy className="w-5 h-5 text-yellow-500" />
                          Recent Achievements
                        </h3>
                        <button
                          onClick={() => setActiveTab('achievements')}
                          className="text-blue-600 dark:text-blue-400 text-sm flex items-center gap-1 hover:underline"
                        >
                          View All <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                      <div className="grid grid-cols-4 md:grid-cols-8 gap-3">
                        {unlockedAchievements.slice(0, 8).map((achievement) => (
                          <AchievementBadge
                            key={achievement.achievement_id}
                            achievement={achievement}
                            size="md"
                            showProgress={false}
                          />
                        ))}
                        {unlockedAchievements.length === 0 && (
                          <p className="col-span-full text-gray-500 dark:text-gray-400 text-center py-4">
                            No achievements unlocked yet. Start learning to earn achievements!
                          </p>
                        )}
                      </div>
                    </div>

                    {/* Recent Activity */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                          <TrendingUp className="w-5 h-5 text-green-500" />
                          Recent Activity
                        </h3>
                        <button
                          onClick={() => setActiveTab('activity')}
                          className="text-blue-600 dark:text-blue-400 text-sm flex items-center gap-1 hover:underline"
                        >
                          View All <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                      <div className="space-y-3">
                        {activities.slice(0, 5).map((activity) => (
                          <div
                            key={activity.id}
                            className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-slate-700/50 rounded-lg"
                          >
                            {getActivityIcon(activity.activity_type)}
                            <div className="flex-1">
                              <p className="text-sm text-gray-900 dark:text-white">{activity.title}</p>
                              <p className="text-xs text-gray-500">
                                {new Date(activity.created_at).toLocaleDateString()}
                              </p>
                            </div>
                            {activity.xp_earned > 0 && (
                              <span className="text-sm text-green-600 dark:text-green-400 font-medium">
                                +{activity.xp_earned} XP
                              </span>
                            )}
                          </div>
                        ))}
                        {activities.length === 0 && (
                          <p className="text-gray-500 dark:text-gray-400 text-center py-4">
                            No recent activity
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Achievements Tab */}
                {activeTab === 'achievements' && (
                  <div className="space-y-6">
                    {/* Filter */}
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm text-gray-500">Filter:</span>
                      {(['all', 'tutorials', 'typing', 'streak', 'special'] as const).map((cat) => (
                        <button
                          key={cat}
                          onClick={() => setAchievementFilter(cat)}
                          className={`px-3 py-1 rounded-full text-sm transition ${
                            achievementFilter === cat
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                          }`}
                        >
                          {cat.charAt(0).toUpperCase() + cat.slice(1)}
                        </button>
                      ))}
                    </div>

                    {/* Stats */}
                    <div className="flex items-center gap-6 p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
                      <div>
                        <div className="text-2xl font-bold text-gray-900 dark:text-white">
                          {unlockedAchievements.length}
                        </div>
                        <div className="text-sm text-gray-500">Unlocked</div>
                      </div>
                      <div className="h-8 w-px bg-gray-300 dark:bg-gray-600" />
                      <div>
                        <div className="text-2xl font-bold text-gray-900 dark:text-white">
                          {filteredAchievements.length}
                        </div>
                        <div className="text-sm text-gray-500">Total</div>
                      </div>
                      <div className="h-8 w-px bg-gray-300 dark:bg-gray-600" />
                      <div>
                        <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                          {filteredAchievements.length > 0
                            ? Math.round((unlockedAchievements.length / filteredAchievements.length) * 100)
                            : 0}%
                        </div>
                        <div className="text-sm text-gray-500">Complete</div>
                      </div>
                    </div>

                    {/* Unlocked */}
                    {unlockedAchievements.length > 0 && (
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-3">
                          Unlocked ({unlockedAchievements.length})
                        </h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          {unlockedAchievements.map((achievement) => (
                            <div
                              key={achievement.achievement_id}
                              className="flex items-center gap-3 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg"
                            >
                              <AchievementBadge achievement={achievement} size="md" showProgress={false} />
                              <div className="flex-1 min-w-0">
                                <p className="font-medium text-gray-900 dark:text-white text-sm truncate">
                                  {achievement.name}
                                </p>
                                <p className="text-xs text-gray-500 truncate">{achievement.description}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Locked */}
                    {lockedAchievements.length > 0 && (
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-3">
                          In Progress ({lockedAchievements.length})
                        </h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          {lockedAchievements.map((achievement) => (
                            <div
                              key={achievement.achievement_id}
                              className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600 rounded-lg opacity-75"
                            >
                              <AchievementBadge achievement={achievement} size="md" showProgress />
                              <div className="flex-1 min-w-0">
                                <p className="font-medium text-gray-700 dark:text-gray-300 text-sm truncate">
                                  {achievement.name}
                                </p>
                                <p className="text-xs text-gray-500 truncate">{achievement.description}</p>
                                <div className="mt-1 h-1 bg-gray-200 dark:bg-gray-600 rounded-full">
                                  <div
                                    className="h-1 bg-blue-500 rounded-full"
                                    style={{ width: `${achievement.progress_percent}%` }}
                                  />
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Tutorials Tab */}
                {activeTab === 'tutorials' && (
                  <div className="space-y-6">
                    {/* Stats */}
                    <div className="grid grid-cols-3 gap-4">
                      <div className="bg-green-50 dark:bg-green-900/20 rounded-xl p-4 text-center">
                        <CheckCircle className="w-8 h-8 text-green-500 mx-auto mb-2" />
                        <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                          {completedTutorials.length}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">Completed</div>
                      </div>
                      <div className="bg-blue-50 dark:bg-blue-900/20 rounded-xl p-4 text-center">
                        <Clock className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                        <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                          {inProgressTutorials.length}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">In Progress</div>
                      </div>
                      <div className="bg-purple-50 dark:bg-purple-900/20 rounded-xl p-4 text-center">
                        <Zap className="w-8 h-8 text-purple-500 mx-auto mb-2" />
                        <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                          {completedTutorials.length * 100}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400">XP Earned</div>
                      </div>
                    </div>

                    {/* In Progress */}
                    {inProgressTutorials.length > 0 && (
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <Clock className="w-5 h-5 text-blue-500" />
                          In Progress
                        </h4>
                        <div className="space-y-3">
                          {inProgressTutorials.map((tutorial) => (
                            <Link
                              key={tutorial.id}
                              to={`/tutorials/${tutorial.tutorial_id}`}
                              className="flex items-center gap-4 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/30 transition"
                            >
                              <div className="flex-1">
                                <p className="font-medium text-gray-900 dark:text-white">
                                  Tutorial #{tutorial.tutorial_id}
                                </p>
                                <p className="text-sm text-gray-500">
                                  {tutorial.completed_step_ids?.length || 0} steps done • {tutorial.time_spent_minutes} mins spent
                                </p>
                              </div>
                              <div className="flex items-center gap-3">
                                <div className="w-24">
                                  <div className="h-2 bg-gray-200 dark:bg-gray-600 rounded-full">
                                    <div
                                      className="h-2 bg-blue-500 rounded-full"
                                      style={{ width: `${tutorial.progress_percentage || 0}%` }}
                                    />
                                  </div>
                                  <p className="text-xs text-gray-500 mt-1 text-right">
                                    {tutorial.progress_percentage || 0}%
                                  </p>
                                </div>
                                <ChevronRight className="w-5 h-5 text-gray-400" />
                              </div>
                            </Link>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Completed */}
                    {completedTutorials.length > 0 && (
                      <div>
                        <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                          <CheckCircle className="w-5 h-5 text-green-500" />
                          Completed ({completedTutorials.length})
                        </h4>
                        <div className="space-y-3">
                          {completedTutorials.map((tutorial) => (
                            <div
                              key={tutorial.id}
                              className="flex items-center gap-4 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg"
                            >
                              <CheckCircle className="w-6 h-6 text-green-500" />
                              <div className="flex-1">
                                <p className="font-medium text-gray-900 dark:text-white">
                                  Tutorial #{tutorial.tutorial_id}
                                </p>
                                <p className="text-sm text-gray-500">
                                  Completed on {new Date(tutorial.completed_at || '').toLocaleDateString()}
                                  {tutorial.time_spent_minutes && ` • ${tutorial.time_spent_minutes} mins`}
                                </p>
                              </div>
                              <span className="text-green-600 dark:text-green-400 font-medium">+100 XP</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {tutorialProgress.length === 0 && (
                      <div className="text-center py-12">
                        <BookOpen className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                          No tutorials yet
                        </h3>
                        <p className="text-gray-500 dark:text-gray-400 mb-4">
                          Start learning to track your progress here
                        </p>
                        <Link
                          to="/tutorials"
                          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
                        >
                          <BookOpen className="w-4 h-4" />
                          Browse Tutorials
                        </Link>
                      </div>
                    )}
                  </div>
                )}

                {/* Games Tab */}
                {activeTab === 'games' && (
                  <div className="space-y-6">
                    {/* Typing Stats */}
                    {typingStats ? (
                      <>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl p-4 text-white">
                            <Zap className="w-6 h-6 mb-2 opacity-80" />
                            <div className="text-3xl font-bold">{typingStats.best_wpm?.toFixed(0) || '-'}</div>
                            <div className="text-sm opacity-80">Best WPM</div>
                          </div>
                          <div className="bg-gradient-to-br from-green-500 to-teal-500 rounded-xl p-4 text-white">
                            <Target className="w-6 h-6 mb-2 opacity-80" />
                            <div className="text-3xl font-bold">{typingStats.avg_accuracy?.toFixed(1) || '-'}%</div>
                            <div className="text-sm opacity-80">Avg Accuracy</div>
                          </div>
                          <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl p-4 text-white">
                            <Gamepad2 className="w-6 h-6 mb-2 opacity-80" />
                            <div className="text-3xl font-bold">{typingStats.total_games_completed}</div>
                            <div className="text-sm opacity-80">Games Played</div>
                          </div>
                          <div className="bg-gradient-to-br from-orange-500 to-red-500 rounded-xl p-4 text-white">
                            <Clock className="w-6 h-6 mb-2 opacity-80" />
                            <div className="text-3xl font-bold">{typingStats.avg_wpm?.toFixed(0) || '-'}</div>
                            <div className="text-sm opacity-80">Avg WPM</div>
                          </div>
                        </div>

                        {/* PVP Stats */}
                        {pvpStats && (pvpStats.wins > 0 || pvpStats.losses > 0) && (
                          <div className="bg-gray-50 dark:bg-slate-700/50 rounded-xl p-6">
                            <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                              <Award className="w-5 h-5 text-yellow-500" />
                              PVP Statistics
                            </h4>
                            <div className="grid grid-cols-4 gap-4 text-center">
                              <div>
                                <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                                  {pvpStats.wins}
                                </div>
                                <div className="text-sm text-gray-500">Wins</div>
                              </div>
                              <div>
                                <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                                  {pvpStats.losses}
                                </div>
                                <div className="text-sm text-gray-500">Losses</div>
                              </div>
                              <div>
                                <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                                  {pvpStats.total_matches > 0
                                    ? ((pvpStats.wins / pvpStats.total_matches) * 100).toFixed(1)
                                    : 0}%
                                </div>
                                <div className="text-sm text-gray-500">Win Rate</div>
                              </div>
                              <div>
                                <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                                  {pvpStats.total_matches}
                                </div>
                                <div className="text-sm text-gray-500">Total Matches</div>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Detailed Stats */}
                        <div className="bg-gray-50 dark:bg-slate-700/50 rounded-xl p-6">
                          <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-4">
                            Detailed Statistics
                          </h4>
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                            <div className="p-4 bg-white dark:bg-slate-800 rounded-lg">
                              <p className="text-sm text-gray-500 mb-1">Best Accuracy</p>
                              <p className="text-xl font-bold text-gray-900 dark:text-white">
                                {typingStats.best_accuracy?.toFixed(1) || 0}%
                              </p>
                            </div>
                            <div className="p-4 bg-white dark:bg-slate-800 rounded-lg">
                              <p className="text-sm text-gray-500 mb-1">Total Words</p>
                              <p className="text-xl font-bold text-gray-900 dark:text-white">
                                {typingStats.total_words_typed?.toLocaleString() || 0}
                              </p>
                            </div>
                            <div className="p-4 bg-white dark:bg-slate-800 rounded-lg">
                              <p className="text-sm text-gray-500 mb-1">Time Played</p>
                              <p className="text-xl font-bold text-gray-900 dark:text-white">
                                {Math.round((typingStats.total_time_seconds || 0) / 60)} mins
                              </p>
                            </div>
                          </div>
                        </div>
                      </>
                    ) : (
                      <div className="text-center py-12">
                        <Keyboard className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                          No game stats yet
                        </h3>
                        <p className="text-gray-500 dark:text-gray-400 mb-4">
                          Play the typing game to see your stats here
                        </p>
                        <Link
                          to="/games/typing"
                          className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition"
                        >
                          <Keyboard className="w-4 h-4" />
                          Play Typing Game
                        </Link>
                      </div>
                    )}
                  </div>
                )}

                {/* Activity Tab */}
                {activeTab === 'activity' && (
                  <div className="space-y-4">
                    {activities.length > 0 ? (
                      activities.map((activity, index) => (
                        <motion.div
                          key={activity.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.05 }}
                          className="flex items-start gap-4 p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg"
                        >
                          <div className="w-10 h-10 rounded-full bg-white dark:bg-slate-800 flex items-center justify-center">
                            {getActivityIcon(activity.activity_type)}
                          </div>
                          <div className="flex-1">
                            <p className="text-gray-900 dark:text-white font-medium">
                              {activity.title}
                            </p>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                              {new Date(activity.created_at).toLocaleString()}
                            </p>
                          </div>
                          {activity.xp_earned > 0 && (
                            <span className="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 text-sm font-medium rounded">
                              +{activity.xp_earned} XP
                            </span>
                          )}
                        </motion.div>
                      ))
                    ) : (
                      <div className="text-center py-12">
                        <TrendingUp className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                          No activity yet
                        </h3>
                        <p className="text-gray-500 dark:text-gray-400">
                          Your learning activity will appear here
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* Settings Tab */}
                {activeTab === 'settings' && isOwnProfile && (
                  <div className="space-y-8">
                    {/* Profile Information */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                          Profile Information
                        </h3>
                        {!isEditing && (
                          <button
                            onClick={() => setIsEditing(true)}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition"
                          >
                            <Edit className="w-4 h-4" />
                            Edit
                          </button>
                        )}
                      </div>

                      {isEditing ? (
                        <form onSubmit={handleProfileUpdate} className="space-y-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                First Name
                              </label>
                              <input
                                type="text"
                                value={profileForm.first_name}
                                onChange={(e) => setProfileForm({ ...profileForm, first_name: e.target.value })}
                                className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                                required
                              />
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Last Name
                              </label>
                              <input
                                type="text"
                                value={profileForm.last_name}
                                onChange={(e) => setProfileForm({ ...profileForm, last_name: e.target.value })}
                                className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                                required
                              />
                            </div>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                              Bio (optional)
                            </label>
                            <textarea
                              value={profileForm.bio}
                              onChange={(e) => setProfileForm({ ...profileForm, bio: e.target.value })}
                              rows={4}
                              className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                              placeholder="Tell us about yourself..."
                            />
                          </div>
                          <div className="flex gap-3">
                            <button
                              type="submit"
                              disabled={loading}
                              className="flex items-center gap-2 px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition disabled:opacity-50"
                            >
                              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                              Save Changes
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setIsEditing(false);
                                setProfileForm({
                                  first_name: user.first_name,
                                  last_name: user.last_name,
                                  bio: user.bio || '',
                                });
                              }}
                              className="px-6 py-2 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 transition"
                            >
                              Cancel
                            </button>
                          </div>
                        </form>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
                            <p className="text-sm text-gray-500 mb-1">First Name</p>
                            <p className="text-gray-900 dark:text-white font-medium">{user.first_name}</p>
                          </div>
                          <div className="p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
                            <p className="text-sm text-gray-500 mb-1">Last Name</p>
                            <p className="text-gray-900 dark:text-white font-medium">{user.last_name}</p>
                          </div>
                          <div className="p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
                            <p className="text-sm text-gray-500 mb-1">Email</p>
                            <div className="flex items-center gap-2">
                              <Mail className="w-4 h-4 text-gray-400" />
                              <p className="text-gray-900 dark:text-white font-medium">{user.email}</p>
                            </div>
                          </div>
                          <div className="p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
                            <p className="text-sm text-gray-500 mb-1">Username</p>
                            <p className="text-gray-900 dark:text-white font-medium">@{user.username}</p>
                          </div>
                          {user.bio && (
                            <div className="md:col-span-2 p-4 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
                              <p className="text-sm text-gray-500 mb-1">Bio</p>
                              <p className="text-gray-900 dark:text-white">{user.bio}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Change Password */}
                    {!user.google_id && (
                      <div>
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h3 className="text-lg font-bold text-gray-900 dark:text-white">Password</h3>
                            <p className="text-sm text-gray-500">Update your password to keep your account secure</p>
                          </div>
                          {!showPasswordForm && (
                            <button
                              onClick={() => setShowPasswordForm(true)}
                              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 transition"
                            >
                              <Lock className="w-4 h-4" />
                              Change
                            </button>
                          )}
                        </div>

                        {showPasswordForm && (
                          <form onSubmit={handlePasswordChange} className="space-y-4 bg-gray-50 dark:bg-slate-700/50 p-4 rounded-lg">
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Current Password
                              </label>
                              <div className="relative">
                                <input
                                  type={showPasswords.current ? 'text' : 'password'}
                                  value={passwordForm.current_password}
                                  onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                                  className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100 pr-10"
                                  required
                                />
                                <button
                                  type="button"
                                  onClick={() => setShowPasswords({ ...showPasswords, current: !showPasswords.current })}
                                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                                >
                                  {showPasswords.current ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                              </div>
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                New Password
                              </label>
                              <div className="relative">
                                <input
                                  type={showPasswords.new ? 'text' : 'password'}
                                  value={passwordForm.new_password}
                                  onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                                  className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100 pr-10"
                                  required
                                  minLength={8}
                                />
                                <button
                                  type="button"
                                  onClick={() => setShowPasswords({ ...showPasswords, new: !showPasswords.new })}
                                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                                >
                                  {showPasswords.new ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                              </div>
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Confirm New Password
                              </label>
                              <div className="relative">
                                <input
                                  type={showPasswords.confirm ? 'text' : 'password'}
                                  value={passwordForm.confirm_password}
                                  onChange={(e) => setPasswordForm({ ...passwordForm, confirm_password: e.target.value })}
                                  className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100 pr-10"
                                  required
                                />
                                <button
                                  type="button"
                                  onClick={() => setShowPasswords({ ...showPasswords, confirm: !showPasswords.confirm })}
                                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                                >
                                  {showPasswords.confirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                              </div>
                            </div>
                            <div className="flex gap-3">
                              <button
                                type="submit"
                                disabled={loading}
                                className="flex items-center gap-2 px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition disabled:opacity-50"
                              >
                                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
                                Update Password
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setShowPasswordForm(false);
                                  setPasswordForm({ current_password: '', new_password: '', confirm_password: '' });
                                }}
                                className="px-6 py-2 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 transition"
                              >
                                Cancel
                              </button>
                            </div>
                          </form>
                        )}
                      </div>
                    )}

                    {/* OAuth Notice */}
                    {user.google_id && (
                      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                        <p className="text-blue-700 dark:text-blue-400 text-sm">
                          You're signed in with Google. Password management is handled through your Google account.
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
