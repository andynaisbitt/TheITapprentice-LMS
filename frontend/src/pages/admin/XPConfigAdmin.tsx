// src/pages/admin/XPConfigAdmin.tsx
/**
 * XP & Levels Configuration
 * Configure level thresholds, XP rewards, and level titles
 */

import { useState, useEffect } from 'react';
import {
  Zap,
  Plus,
  Edit2,
  Trash2,
  Save,
  Loader2,
  Trophy,
  Star,
  Info,
} from 'lucide-react';

interface LevelConfig {
  level: number;
  xp_required: number;
  title: string;
  badge_color: string;
}

interface XPReward {
  id: string;
  action: string;
  description: string;
  base_xp: number;
  multiplier: number;
  category: string;
}

const DEFAULT_LEVELS: LevelConfig[] = [
  { level: 1, xp_required: 0, title: 'Novice', badge_color: '#9CA3AF' },
  { level: 2, xp_required: 100, title: 'Beginner', badge_color: '#6B7280' },
  { level: 3, xp_required: 250, title: 'Apprentice', badge_color: '#10B981' },
  { level: 4, xp_required: 500, title: 'Student', badge_color: '#22C55E' },
  { level: 5, xp_required: 1000, title: 'Practitioner', badge_color: '#3B82F6' },
  { level: 6, xp_required: 2000, title: 'Adept', badge_color: '#6366F1' },
  { level: 7, xp_required: 3500, title: 'Expert', badge_color: '#8B5CF6' },
  { level: 8, xp_required: 5500, title: 'Master', badge_color: '#A855F7' },
  { level: 9, xp_required: 8000, title: 'Grandmaster', badge_color: '#EC4899' },
  { level: 10, xp_required: 12000, title: 'Legend', badge_color: '#F59E0B' },
];

const DEFAULT_REWARDS: XPReward[] = [
  { id: 'login_daily', action: 'Daily Login', description: 'First login of the day', base_xp: 10, multiplier: 1, category: 'Activity' },
  { id: 'tutorial_start', action: 'Start Tutorial', description: 'Begin a new tutorial', base_xp: 5, multiplier: 1, category: 'Tutorials' },
  { id: 'tutorial_step', action: 'Complete Step', description: 'Complete a tutorial step', base_xp: 10, multiplier: 1, category: 'Tutorials' },
  { id: 'tutorial_complete', action: 'Complete Tutorial', description: 'Finish an entire tutorial', base_xp: 50, multiplier: 1, category: 'Tutorials' },
  { id: 'course_enroll', action: 'Enroll in Course', description: 'Start a new course', base_xp: 10, multiplier: 1, category: 'Courses' },
  { id: 'lesson_complete', action: 'Complete Lesson', description: 'Finish a course lesson', base_xp: 25, multiplier: 1, category: 'Courses' },
  { id: 'course_complete', action: 'Complete Course', description: 'Finish an entire course', base_xp: 200, multiplier: 1, category: 'Courses' },
  { id: 'typing_game', action: 'Typing Game', description: 'Complete a typing game', base_xp: 15, multiplier: 1, category: 'Games' },
  { id: 'typing_wpm_bonus', action: 'Speed Bonus', description: 'Per WPM above 60', base_xp: 1, multiplier: 1, category: 'Games' },
  { id: 'pvp_win', action: 'PVP Victory', description: 'Win a PVP typing match', base_xp: 50, multiplier: 1, category: 'Games' },
  { id: 'streak_bonus', action: 'Streak Bonus', description: 'Per day of streak', base_xp: 5, multiplier: 1, category: 'Streaks' },
];

export const XPConfigAdmin: React.FC = () => {
  const [levels, setLevels] = useState<LevelConfig[]>([]);
  const [rewards, setRewards] = useState<XPReward[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'levels' | 'rewards'>('levels');
  const [editingLevel, setEditingLevel] = useState<LevelConfig | null>(null);
  const [editingReward, setEditingReward] = useState<XPReward | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      setLevels(DEFAULT_LEVELS);
      setRewards(DEFAULT_REWARDS);
    } catch (error) {
      console.error('Failed to load XP config:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveAll = async () => {
    setSaving(true);
    try {
      // TODO: Implement save API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      alert('Configuration saved successfully!');
    } catch (error) {
      console.error('Failed to save config:', error);
    } finally {
      setSaving(false);
    }
  };

  const updateLevel = (level: number, field: keyof LevelConfig, value: any) => {
    setLevels(levels.map(l =>
      l.level === level ? { ...l, [field]: value } : l
    ));
  };

  const updateReward = (id: string, field: keyof XPReward, value: any) => {
    setRewards(rewards.map(r =>
      r.id === id ? { ...r, [field]: value } : r
    ));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            XP & Levels
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Configure level thresholds and XP reward values
          </p>
        </div>
        <button
          onClick={handleSaveAll}
          disabled={saving}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
        >
          {saving ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          Save Changes
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-gray-200 dark:border-gray-700">
        <button
          onClick={() => setActiveTab('levels')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'levels'
              ? 'border-primary text-primary'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
          }`}
        >
          <Trophy className="w-4 h-4 inline mr-2" />
          Level Thresholds
        </button>
        <button
          onClick={() => setActiveTab('rewards')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'rewards'
              ? 'border-primary text-primary'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
          }`}
        >
          <Zap className="w-4 h-4 inline mr-2" />
          XP Rewards
        </button>
      </div>

      {/* Level Thresholds Tab */}
      {activeTab === 'levels' && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
          <div className="p-4 bg-gray-50 dark:bg-gray-700/50 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
              <Info className="w-4 h-4" />
              Define how much XP is required for each level and what titles users earn.
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Level
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    XP Required
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Title
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Badge Color
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Preview
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {levels.map((level) => (
                  <tr key={level.level} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Star className="w-4 h-4 text-yellow-500" />
                        <span className="font-semibold text-gray-900 dark:text-white">
                          {level.level}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <input
                        type="number"
                        value={level.xp_required}
                        onChange={(e) => updateLevel(level.level, 'xp_required', parseInt(e.target.value) || 0)}
                        className="w-24 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <input
                        type="text"
                        value={level.title}
                        onChange={(e) => updateLevel(level.level, 'title', e.target.value)}
                        className="w-32 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <input
                        type="color"
                        value={level.badge_color}
                        onChange={(e) => updateLevel(level.level, 'badge_color', e.target.value)}
                        className="w-10 h-8 rounded cursor-pointer"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium text-white"
                        style={{ backgroundColor: level.badge_color }}
                      >
                        <Star className="w-3 h-3" />
                        Lv.{level.level} {level.title}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* XP Rewards Tab */}
      {activeTab === 'rewards' && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
          <div className="p-4 bg-gray-50 dark:bg-gray-700/50 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
              <Info className="w-4 h-4" />
              Configure how much XP users earn for different actions.
            </div>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {Object.entries(
              rewards.reduce((acc, r) => {
                if (!acc[r.category]) acc[r.category] = [];
                acc[r.category].push(r);
                return acc;
              }, {} as Record<string, XPReward[]>)
            ).map(([category, categoryRewards]) => (
              <div key={category} className="p-4">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                  {category}
                </h3>
                <div className="space-y-3">
                  {categoryRewards.map((reward) => (
                    <div
                      key={reward.id}
                      className="flex items-center gap-4 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                    >
                      <div className="flex-1">
                        <p className="font-medium text-gray-900 dark:text-white">
                          {reward.action}
                        </p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {reward.description}
                        </p>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="flex items-center gap-1">
                          <Zap className="w-4 h-4 text-yellow-500" />
                          <input
                            type="number"
                            value={reward.base_xp}
                            onChange={(e) => updateReward(reward.id, 'base_xp', parseInt(e.target.value) || 0)}
                            className="w-16 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-center"
                          />
                          <span className="text-sm text-gray-500 dark:text-gray-400">XP</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="text-sm text-gray-500 dark:text-gray-400">×</span>
                          <input
                            type="number"
                            step="0.1"
                            value={reward.multiplier}
                            onChange={(e) => updateReward(reward.id, 'multiplier', parseFloat(e.target.value) || 1)}
                            className="w-16 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-center"
                          />
                        </div>
                        <span className="text-sm font-medium text-primary min-w-[60px] text-right">
                          = {Math.round(reward.base_xp * reward.multiplier)} XP
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default XPConfigAdmin;
