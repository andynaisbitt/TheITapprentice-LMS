// src/pages/admin/AchievementsAdmin.tsx
/**
 * Achievements Management
 * CRUD interface for achievement definitions
 */

import { useState, useEffect } from 'react';
import {
  Trophy,
  Plus,
  Edit2,
  Trash2,
  Search,
  Filter,
  Loader2,
  Star,
  Zap,
  Users,
  X,
  BookOpen,
  Compass,
  GraduationCap,
  Flame,
  Calendar,
  Target,
  Award,
  Crown,
  Medal,
  Gift,
  Heart,
  Sparkles,
} from 'lucide-react';

type AchievementRarity = 'common' | 'uncommon' | 'rare' | 'epic' | 'legendary';
type AchievementCategory = 'tutorials' | 'courses' | 'typing' | 'social' | 'streak' | 'special';
type ConditionType = 'count' | 'value' | 'streak' | 'special';

// Icon map for achievement icons
const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  Trophy, BookOpen, Compass, GraduationCap, Flame, Calendar, Target, Award,
  Crown, Medal, Gift, Heart, Star, Zap, Sparkles,
};

const availableIcons = Object.keys(iconMap);

interface Achievement {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: AchievementCategory;
  rarity: AchievementRarity;
  xp_reward: number;
  unlock_condition: Record<string, any>;
  is_hidden: boolean;
  is_active: boolean;
  unlock_count?: number;
}

const rarityColors: Record<AchievementRarity, { bg: string; text: string; border: string }> = {
  common: { bg: 'bg-gray-100 dark:bg-gray-700', text: 'text-gray-600 dark:text-gray-300', border: 'border-gray-300' },
  uncommon: { bg: 'bg-green-100 dark:bg-green-900/30', text: 'text-green-600 dark:text-green-400', border: 'border-green-400' },
  rare: { bg: 'bg-blue-100 dark:bg-blue-900/30', text: 'text-blue-600 dark:text-blue-400', border: 'border-blue-400' },
  epic: { bg: 'bg-purple-100 dark:bg-purple-900/30', text: 'text-purple-600 dark:text-purple-400', border: 'border-purple-400' },
  legendary: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-600 dark:text-yellow-400', border: 'border-yellow-400' },
};

const categoryLabels: Record<AchievementCategory, string> = {
  tutorials: 'Tutorials',
  courses: 'Courses',
  typing: 'Typing Games',
  social: 'Social',
  streak: 'Streaks',
  special: 'Special',
};

export const AchievementsAdmin: React.FC = () => {
  const [achievements, setAchievements] = useState<Achievement[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<AchievementCategory | 'all'>('all');
  const [showForm, setShowForm] = useState(false);
  const [editingAchievement, setEditingAchievement] = useState<Achievement | null>(null);

  useEffect(() => {
    loadAchievements();
  }, []);

  const loadAchievements = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/progress/admin/achievements', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch achievements');
      }

      const data = await response.json();

      // Map API response to our Achievement type
      const mappedAchievements: Achievement[] = data.map((a: any) => ({
        id: a.id,
        name: a.name,
        description: a.description,
        icon: a.icon || 'Trophy',
        category: a.category || 'special',
        rarity: a.rarity || 'common',
        xp_reward: a.xp_reward || 0,
        unlock_condition: a.unlock_condition || {},
        is_hidden: a.is_hidden || false,
        is_active: a.is_active ?? true,
        unlock_count: a.unlock_count || 0,
      }));

      setAchievements(mappedAchievements);
    } catch (error) {
      console.error('Failed to load achievements:', error);
      // Fallback to empty array if API fails
      setAchievements([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this achievement?')) return;

    try {
      const response = await fetch(`/api/v1/progress/admin/achievements/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to delete achievement');
      }

      setAchievements(achievements.filter(a => a.id !== id));
    } catch (error) {
      console.error('Failed to delete achievement:', error);
      alert('Failed to delete achievement');
    }
  };

  const filteredAchievements = achievements.filter(a => {
    if (filterCategory !== 'all' && a.category !== filterCategory) return false;
    if (searchTerm && !a.name.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !a.description.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const stats = {
    total: achievements.length,
    active: achievements.filter(a => a.is_active).length,
    totalUnlocks: achievements.reduce((sum, a) => sum + (a.unlock_count || 0), 0),
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
            Achievements
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Manage achievement definitions and rewards
          </p>
        </div>
        <button
          onClick={() => {
            setEditingAchievement(null);
            setShowForm(true);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Achievement
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
            <Trophy className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Achievements</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
            <Star className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.active}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Active</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Users className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.totalUnlocks}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Unlocks</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search achievements..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value as AchievementCategory | 'all')}
            className="pl-10 pr-8 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 appearance-none"
          >
            <option value="all">All Categories</option>
            {Object.entries(categoryLabels).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Achievement List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        {filteredAchievements.length === 0 ? (
          <div className="text-center py-12">
            <Trophy className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">No achievements found</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {filteredAchievements.map((achievement) => {
              const rarity = rarityColors[achievement.rarity];

              return (
                <div
                  key={achievement.id}
                  className={`p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors ${!achievement.is_active ? 'opacity-50' : ''}`}
                >
                  <div className="flex items-center gap-4">
                    {/* Icon */}
                    <div className={`p-3 rounded-xl border-2 ${rarity.bg} ${rarity.border}`}>
                      <Trophy className={`w-6 h-6 ${rarity.text}`} />
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium text-gray-900 dark:text-white">
                          {achievement.name}
                        </h3>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${rarity.bg} ${rarity.text}`}>
                          {achievement.rarity}
                        </span>
                        {achievement.is_hidden && (
                          <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                            Hidden
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {achievement.description}
                      </p>
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-400">
                        <span>{categoryLabels[achievement.category]}</span>
                        <span className="flex items-center gap-1">
                          <Zap className="w-3 h-3" />
                          {achievement.xp_reward} XP
                        </span>
                        <span>{achievement.unlock_count || 0} unlocks</span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setEditingAchievement(achievement);
                          setShowForm(true);
                        }}
                        className="p-2 text-gray-400 hover:text-primary transition-colors"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(achievement.id)}
                        className="p-2 text-gray-400 hover:text-red-500 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Achievement Form Modal */}
      {showForm && (
        <AchievementFormModal
          achievement={editingAchievement}
          onClose={() => setShowForm(false)}
          onSave={(data) => {
            if (editingAchievement) {
              setAchievements(achievements.map(a =>
                a.id === editingAchievement.id ? { ...a, ...data } : a
              ));
            } else {
              const newAchievement: Achievement = {
                ...data,
                id: `achievement_${Date.now()}`,
                unlock_count: 0,
              };
              setAchievements([...achievements, newAchievement]);
            }
            setShowForm(false);
          }}
        />
      )}
    </div>
  );
};

// Achievement Form Modal Component
interface AchievementFormData {
  name: string;
  description: string;
  icon: string;
  category: AchievementCategory;
  rarity: AchievementRarity;
  xp_reward: number;
  unlock_condition: Record<string, any>;
  is_hidden: boolean;
  is_active: boolean;
}

interface AchievementFormModalProps {
  achievement: Achievement | null;
  onClose: () => void;
  onSave: (data: AchievementFormData) => void;
}

const AchievementFormModal: React.FC<AchievementFormModalProps> = ({
  achievement,
  onClose,
  onSave,
}) => {
  const [formData, setFormData] = useState<AchievementFormData>({
    name: achievement?.name || '',
    description: achievement?.description || '',
    icon: achievement?.icon || 'Trophy',
    category: achievement?.category || 'tutorials',
    rarity: achievement?.rarity || 'common',
    xp_reward: achievement?.xp_reward || 50,
    unlock_condition: achievement?.unlock_condition || { type: 'count', action: '', count: 1 },
    is_hidden: achievement?.is_hidden || false,
    is_active: achievement?.is_active ?? true,
  });

  const [conditionType, setConditionType] = useState<ConditionType>(
    (achievement?.unlock_condition?.type as ConditionType) || 'count'
  );

  const handleConditionTypeChange = (type: ConditionType) => {
    setConditionType(type);
    switch (type) {
      case 'count':
        setFormData(prev => ({
          ...prev,
          unlock_condition: { type: 'count', action: '', count: 1 },
        }));
        break;
      case 'value':
        setFormData(prev => ({
          ...prev,
          unlock_condition: { type: 'value', metric: '', operator: '>=', value: 0 },
        }));
        break;
      case 'streak':
        setFormData(prev => ({
          ...prev,
          unlock_condition: { type: 'streak', days: 7 },
        }));
        break;
      case 'special':
        setFormData(prev => ({
          ...prev,
          unlock_condition: { type: 'special', trigger: 'manual' },
        }));
        break;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  const IconComponent = iconMap[formData.icon] || Trophy;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            {achievement ? 'Edit Achievement' : 'New Achievement'}
          </h2>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Name & Description */}
          <div className="grid grid-cols-1 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Name *
              </label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
                placeholder="First Steps"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description *
              </label>
              <textarea
                required
                rows={2}
                value={formData.description}
                onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
                placeholder="Complete your first tutorial"
              />
            </div>
          </div>

          {/* Icon, Category, Rarity */}
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Icon
              </label>
              <div className="relative">
                <select
                  value={formData.icon}
                  onChange={(e) => setFormData(prev => ({ ...prev, icon: e.target.value }))}
                  className="w-full pl-10 pr-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 appearance-none"
                >
                  {availableIcons.map((icon) => (
                    <option key={icon} value={icon}>{icon}</option>
                  ))}
                </select>
                <div className="absolute left-3 top-1/2 -translate-y-1/2">
                  <IconComponent className="w-4 h-4 text-gray-500" />
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Category
              </label>
              <select
                value={formData.category}
                onChange={(e) => setFormData(prev => ({ ...prev, category: e.target.value as AchievementCategory }))}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                {Object.entries(categoryLabels).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Rarity
              </label>
              <select
                value={formData.rarity}
                onChange={(e) => setFormData(prev => ({ ...prev, rarity: e.target.value as AchievementRarity }))}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                <option value="common">Common</option>
                <option value="uncommon">Uncommon</option>
                <option value="rare">Rare</option>
                <option value="epic">Epic</option>
                <option value="legendary">Legendary</option>
              </select>
            </div>
          </div>

          {/* XP Reward */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              XP Reward
            </label>
            <div className="relative">
              <Zap className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-yellow-500" />
              <input
                type="number"
                min={0}
                step={25}
                value={formData.xp_reward}
                onChange={(e) => setFormData(prev => ({ ...prev, xp_reward: parseInt(e.target.value) || 0 }))}
                className="w-full pl-10 pr-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
          </div>

          {/* Unlock Condition Builder */}
          <div className="space-y-3 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Unlock Condition
            </label>

            <div className="flex gap-2">
              {(['count', 'value', 'streak', 'special'] as ConditionType[]).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => handleConditionTypeChange(type)}
                  className={`px-3 py-1 text-sm rounded-lg transition-colors ${
                    conditionType === type
                      ? 'bg-primary text-white'
                      : 'bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-500'
                  }`}
                >
                  {type.charAt(0).toUpperCase() + type.slice(1)}
                </button>
              ))}
            </div>

            {/* Count Condition */}
            {conditionType === 'count' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Action</label>
                  <select
                    value={formData.unlock_condition.action || ''}
                    onChange={(e) => setFormData(prev => ({
                      ...prev,
                      unlock_condition: { ...prev.unlock_condition, action: e.target.value },
                    }))}
                    className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                  >
                    <option value="">Select action...</option>
                    <option value="tutorial_complete">Complete Tutorial</option>
                    <option value="course_complete">Complete Course</option>
                    <option value="typing_game_play">Play Typing Game</option>
                    <option value="typing_game_win">Win Typing Game</option>
                    <option value="comment_post">Post Comment</option>
                    <option value="profile_update">Update Profile</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Count Required</label>
                  <input
                    type="number"
                    min={1}
                    value={formData.unlock_condition.count || 1}
                    onChange={(e) => setFormData(prev => ({
                      ...prev,
                      unlock_condition: { ...prev.unlock_condition, count: parseInt(e.target.value) || 1 },
                    }))}
                    className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                  />
                </div>
              </div>
            )}

            {/* Value Condition */}
            {conditionType === 'value' && (
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Metric</label>
                  <select
                    value={formData.unlock_condition.metric || ''}
                    onChange={(e) => setFormData(prev => ({
                      ...prev,
                      unlock_condition: { ...prev.unlock_condition, metric: e.target.value },
                    }))}
                    className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                  >
                    <option value="">Select metric...</option>
                    <option value="wpm">WPM (Typing Speed)</option>
                    <option value="accuracy">Accuracy (%)</option>
                    <option value="xp_total">Total XP</option>
                    <option value="level">User Level</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Operator</label>
                  <select
                    value={formData.unlock_condition.operator || '>='}
                    onChange={(e) => setFormData(prev => ({
                      ...prev,
                      unlock_condition: { ...prev.unlock_condition, operator: e.target.value },
                    }))}
                    className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                  >
                    <option value=">=">≥ (at least)</option>
                    <option value=">"> (more than)</option>
                    <option value="=">=  (exactly)</option>
                    <option value="<=">≤ (at most)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Value</label>
                  <input
                    type="number"
                    min={0}
                    value={formData.unlock_condition.value || 0}
                    onChange={(e) => setFormData(prev => ({
                      ...prev,
                      unlock_condition: { ...prev.unlock_condition, value: parseInt(e.target.value) || 0 },
                    }))}
                    className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                  />
                </div>
              </div>
            )}

            {/* Streak Condition */}
            {conditionType === 'streak' && (
              <div>
                <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Days Required</label>
                <input
                  type="number"
                  min={1}
                  value={formData.unlock_condition.days || 7}
                  onChange={(e) => setFormData(prev => ({
                    ...prev,
                    unlock_condition: { type: 'streak', days: parseInt(e.target.value) || 7 },
                  }))}
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                />
              </div>
            )}

            {/* Special Condition */}
            {conditionType === 'special' && (
              <div>
                <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Trigger Type</label>
                <select
                  value={formData.unlock_condition.trigger || 'manual'}
                  onChange={(e) => setFormData(prev => ({
                    ...prev,
                    unlock_condition: { type: 'special', trigger: e.target.value },
                  }))}
                  className="w-full px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg"
                >
                  <option value="manual">Manual Award</option>
                  <option value="registration_date">Registration Date</option>
                  <option value="event">Special Event</option>
                  <option value="referral">Referral Program</option>
                </select>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Special achievements are awarded manually or through specific events.
                </p>
              </div>
            )}
          </div>

          {/* Toggles */}
          <div className="flex gap-6">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.is_active}
                onChange={(e) => setFormData(prev => ({ ...prev, is_active: e.target.checked }))}
                className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
              />
              <span className="text-sm text-gray-700 dark:text-gray-300">Active</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.is_hidden}
                onChange={(e) => setFormData(prev => ({ ...prev, is_hidden: e.target.checked }))}
                className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
              />
              <span className="text-sm text-gray-700 dark:text-gray-300">Hidden (Secret Achievement)</span>
            </label>
          </div>
        </form>

        {/* Footer */}
        <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-700">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
          >
            {achievement ? 'Save Changes' : 'Create Achievement'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AchievementsAdmin;
