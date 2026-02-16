// src/pages/user/UserSettingsPage.tsx
/**
 * User Settings Page
 * Provides preferences for theme, notifications, privacy, and profile management
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Settings,
  Sun,
  Moon,
  Monitor,
  Bell,
  BellOff,
  Shield,
  User,
  Eye,
  EyeOff,
  ChevronRight,
  Palette,
  Save,
  Loader2,
  CheckCircle,
  Trophy,
  Keyboard,
  BookOpen,
} from 'lucide-react';
import { useAuth } from '../../state/contexts/AuthContext';
import { apiClient } from '../../services/api/client';

type ThemePreference = 'light' | 'dark' | 'system';

interface UserPreferences {
  theme: ThemePreference;
  notifications: {
    challengeReminders: boolean;
    streakReminders: boolean;
    achievementAlerts: boolean;
    weeklyDigest: boolean;
  };
  privacy: {
    showOnLeaderboard: boolean;
    showProfile: boolean;
    showActivity: boolean;
  };
  learning: {
    defaultDifficulty: 'easy' | 'medium' | 'hard';
    autoPlayNext: boolean;
  };
}

const DEFAULT_PREFERENCES: UserPreferences = {
  theme: 'dark',
  notifications: {
    challengeReminders: true,
    streakReminders: true,
    achievementAlerts: true,
    weeklyDigest: false,
  },
  privacy: {
    showOnLeaderboard: true,
    showProfile: true,
    showActivity: true,
  },
  learning: {
    defaultDifficulty: 'medium',
    autoPlayNext: true,
  },
};

const UserSettingsPage: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const [preferences, setPreferences] = useState<UserPreferences>(DEFAULT_PREFERENCES);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  // Load preferences from backend user data + localStorage for theme
  useEffect(() => {
    // Theme from localStorage (client-side only)
    const currentTheme = localStorage.getItem('theme');
    if (currentTheme === 'dark' || currentTheme === 'light') {
      setPreferences(prev => ({ ...prev, theme: currentTheme as ThemePreference }));
    }

    // Load backend preferences from user object
    if (user) {
      const u = user as any;
      setPreferences(prev => ({
        ...prev,
        notifications: {
          challengeReminders: u.notify_challenge_reminders ?? prev.notifications.challengeReminders,
          streakReminders: u.notify_streak_reminders ?? prev.notifications.streakReminders,
          achievementAlerts: u.notify_achievement_alerts ?? prev.notifications.achievementAlerts,
          weeklyDigest: u.notify_weekly_digest ?? prev.notifications.weeklyDigest,
        },
        privacy: {
          showOnLeaderboard: u.show_on_leaderboard ?? prev.privacy.showOnLeaderboard,
          showProfile: u.show_profile_public ?? prev.privacy.showProfile,
          showActivity: u.show_activity_public ?? prev.privacy.showActivity,
        },
        learning: {
          ...prev.learning,
          defaultDifficulty: u.default_difficulty ?? prev.learning.defaultDifficulty,
        },
      }));
    }
  }, [user]);

  const handleThemeChange = (theme: ThemePreference) => {
    setPreferences(prev => ({ ...prev, theme }));

    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.classList.toggle('dark', prefersDark);
      localStorage.setItem('theme', 'system');
    } else {
      document.documentElement.classList.toggle('dark', theme === 'dark');
      localStorage.setItem('theme', theme);
    }
  };

  const handleNotificationChange = (key: keyof UserPreferences['notifications']) => {
    setPreferences(prev => ({
      ...prev,
      notifications: { ...prev.notifications, [key]: !prev.notifications[key] },
    }));
  };

  const handlePrivacyChange = (key: keyof UserPreferences['privacy']) => {
    setPreferences(prev => ({
      ...prev,
      privacy: { ...prev.privacy, [key]: !prev.privacy[key] },
    }));
  };

  const handleLearningChange = (key: string, value: string | boolean) => {
    setPreferences(prev => ({
      ...prev,
      learning: { ...prev.learning, [key]: value },
    }));
  };

  const savePreferences = async () => {
    setSaving(true);
    try {
      // Save to backend (privacy, notifications, learning difficulty)
      await apiClient.put('/api/v1/auth/me/preferences', {
        show_on_leaderboard: preferences.privacy.showOnLeaderboard,
        show_profile_public: preferences.privacy.showProfile,
        show_activity_public: preferences.privacy.showActivity,
        default_difficulty: preferences.learning.defaultDifficulty,
        notify_challenge_reminders: preferences.notifications.challengeReminders,
        notify_streak_reminders: preferences.notifications.streakReminders,
        notify_achievement_alerts: preferences.notifications.achievementAlerts,
        notify_weekly_digest: preferences.notifications.weeklyDigest,
      });

      // Theme stays in localStorage (client-side only)
      localStorage.setItem('userPreferences', JSON.stringify(preferences));
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      console.error('Failed to save preferences:', err);
    } finally {
      setSaving(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4">
        <div className="text-center">
          <Settings className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Sign in Required</h2>
          <p className="text-gray-500 dark:text-gray-400 mb-6">Sign in to access your settings.</p>
          <Link
            to="/login"
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition"
          >
            Sign In
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-6 sm:py-10">
      <div className="max-w-2xl mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center">
              <Settings className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">Manage your preferences</p>
            </div>
          </div>
        </motion.div>

        <div className="space-y-6">
          {/* Profile Link */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
          >
            <Link
              to="/profile"
              className="flex items-center justify-between p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-blue-300 dark:hover:border-blue-600 transition group"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                  <User className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <div className="font-semibold text-gray-900 dark:text-white">
                    {user?.first_name} {user?.last_name}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    Edit profile, change password
                  </div>
                </div>
              </div>
              <ChevronRight className="w-5 h-5 text-gray-400 group-hover:text-blue-500 transition" />
            </Link>
          </motion.div>

          {/* Theme Settings */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-center gap-2 mb-4">
              <Palette className="w-5 h-5 text-purple-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Appearance</h2>
            </div>

            <div className="grid grid-cols-3 gap-3">
              {([
                { id: 'light' as ThemePreference, label: 'Light', icon: Sun },
                { id: 'dark' as ThemePreference, label: 'Dark', icon: Moon },
                { id: 'system' as ThemePreference, label: 'System', icon: Monitor },
              ]).map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => handleThemeChange(id)}
                  className={`flex flex-col items-center gap-2 p-3 rounded-lg border-2 transition ${
                    preferences.theme === id
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                      : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${preferences.theme === id ? 'text-blue-500' : 'text-gray-500 dark:text-gray-400'}`} />
                  <span className={`text-sm font-medium ${preferences.theme === id ? 'text-blue-600 dark:text-blue-400' : 'text-gray-600 dark:text-gray-400'}`}>
                    {label}
                  </span>
                </button>
              ))}
            </div>
          </motion.div>

          {/* Notification Settings */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-center gap-2 mb-4">
              <Bell className="w-5 h-5 text-orange-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Notifications</h2>
            </div>

            <div className="space-y-3">
              {([
                { key: 'challengeReminders' as const, label: 'Daily challenge reminders', desc: 'Get reminded about uncompleted daily challenges' },
                { key: 'streakReminders' as const, label: 'Streak reminders', desc: 'Get notified if your streak is about to expire' },
                { key: 'achievementAlerts' as const, label: 'Achievement alerts', desc: 'Celebrate when you unlock new achievements' },
                { key: 'weeklyDigest' as const, label: 'Weekly digest', desc: 'Summary of your weekly learning progress' },
              ]).map(({ key, label, desc }) => (
                <div key={key} className="flex items-center justify-between py-2">
                  <div>
                    <div className="font-medium text-gray-900 dark:text-white text-sm">{label}</div>
                    <div className="text-xs text-gray-500 dark:text-gray-400">{desc}</div>
                  </div>
                  <button
                    onClick={() => handleNotificationChange(key)}
                    className={`relative w-11 h-6 rounded-full transition ${
                      preferences.notifications[key]
                        ? 'bg-blue-500'
                        : 'bg-gray-300 dark:bg-gray-600'
                    }`}
                  >
                    <div
                      className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
                        preferences.notifications[key] ? 'translate-x-5.5 left-0.5' : 'left-0.5'
                      }`}
                      style={{ transform: preferences.notifications[key] ? 'translateX(22px)' : 'translateX(0)' }}
                    />
                  </button>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Privacy Settings */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-green-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Privacy</h2>
            </div>

            <div className="space-y-3">
              {([
                { key: 'showOnLeaderboard' as const, label: 'Show on leaderboards', desc: 'Display your scores on public leaderboards', icon: Trophy },
                { key: 'showProfile' as const, label: 'Public profile', desc: 'Let other users see your profile', icon: Eye },
                { key: 'showActivity' as const, label: 'Show activity', desc: 'Display your recent activity on your profile', icon: BookOpen },
              ]).map(({ key, label, desc }) => (
                <div key={key} className="flex items-center justify-between py-2">
                  <div>
                    <div className="font-medium text-gray-900 dark:text-white text-sm">{label}</div>
                    <div className="text-xs text-gray-500 dark:text-gray-400">{desc}</div>
                  </div>
                  <button
                    onClick={() => handlePrivacyChange(key)}
                    className={`relative w-11 h-6 rounded-full transition ${
                      preferences.privacy[key]
                        ? 'bg-blue-500'
                        : 'bg-gray-300 dark:bg-gray-600'
                    }`}
                  >
                    <div
                      className="absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform left-0.5"
                      style={{ transform: preferences.privacy[key] ? 'translateX(22px)' : 'translateX(0)' }}
                    />
                  </button>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Learning Preferences */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25 }}
            className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-center gap-2 mb-4">
              <BookOpen className="w-5 h-5 text-blue-500" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Learning</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">
                  Default difficulty
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {(['easy', 'medium', 'hard'] as const).map((diff) => (
                    <button
                      key={diff}
                      onClick={() => handleLearningChange('defaultDifficulty', diff)}
                      className={`px-3 py-2 rounded-lg text-sm font-medium capitalize transition ${
                        preferences.learning.defaultDifficulty === diff
                          ? diff === 'easy' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 ring-2 ring-green-500'
                            : diff === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 ring-2 ring-yellow-500'
                            : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 ring-2 ring-red-500'
                          : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                      }`}
                    >
                      {diff}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between py-2">
                <div>
                  <div className="font-medium text-gray-900 dark:text-white text-sm">Auto-play next lesson</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">Automatically start the next lesson when you finish one</div>
                </div>
                <button
                  onClick={() => handleLearningChange('autoPlayNext', !preferences.learning.autoPlayNext)}
                  className={`relative w-11 h-6 rounded-full transition ${
                    preferences.learning.autoPlayNext
                      ? 'bg-blue-500'
                      : 'bg-gray-300 dark:bg-gray-600'
                  }`}
                >
                  <div
                    className="absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform left-0.5"
                    style={{ transform: preferences.learning.autoPlayNext ? 'translateX(22px)' : 'translateX(0)' }}
                  />
                </button>
              </div>
            </div>
          </motion.div>

          {/* Save Button */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex justify-end"
          >
            <button
              onClick={savePreferences}
              disabled={saving}
              className={`flex items-center gap-2 px-6 py-2.5 rounded-lg font-medium transition ${
                saved
                  ? 'bg-green-500 text-white'
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
              } disabled:opacity-50`}
            >
              {saving ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : saved ? (
                <CheckCircle className="w-4 h-4" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              {saved ? 'Saved!' : 'Save Preferences'}
            </button>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default UserSettingsPage;
