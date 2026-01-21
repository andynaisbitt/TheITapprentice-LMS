// src/pages/admin/DailyChallengesAdmin.tsx
/**
 * Daily Challenges Admin Page
 * CRUD interface for challenge templates and system management
 */

import { useState, useEffect } from 'react';
import {
  Target,
  Plus,
  Edit2,
  Trash2,
  Search,
  Loader2,
  RefreshCw,
  Zap,
  Clock,
  Users,
  Flame,
  Trophy,
  Calendar,
  X,
  CheckCircle,
  AlertTriangle,
  Play,
} from 'lucide-react';
import { challengesApi } from '../../plugins/shared/services/challengesApi';
import type {
  ChallengeTemplate,
  ChallengeStats,
  ChallengeDifficulty,
  ChallengeType,
} from '../../plugins/shared/types';
import { DIFFICULTY_COLORS } from '../../plugins/shared/types';

const challengeTypes: { value: ChallengeType; label: string; description: string }[] = [
  { value: 'quiz', label: 'Complete Quizzes', description: 'User must complete N quizzes' },
  { value: 'tutorial', label: 'Complete Tutorials', description: 'User must complete N tutorials' },
  { value: 'course_section', label: 'Course Sections', description: 'User must complete N course sections' },
  { value: 'typing_game', label: 'Typing Games', description: 'User must play N typing games' },
  { value: 'typing_wpm', label: 'Typing WPM', description: 'User must achieve N WPM in a game' },
  { value: 'xp_earn', label: 'Earn XP', description: 'User must earn N XP' },
];

const difficultyOptions: { value: ChallengeDifficulty; label: string; xpRange: string }[] = [
  { value: 'easy', label: 'Easy', xpRange: '25-50 XP' },
  { value: 'medium', label: 'Medium', xpRange: '50-100 XP' },
  { value: 'hard', label: 'Hard', xpRange: '100-200 XP' },
];

const iconOptions = ['target', 'zap', 'flame', 'trophy', 'star', 'book', 'keyboard', 'graduation'];

interface FormData {
  title: string;
  description: string;
  challenge_type: ChallengeType;
  difficulty: ChallengeDifficulty;
  target_count: number;
  base_xp_reward: number;
  icon: string;
  is_active: boolean;
}

const defaultFormData: FormData = {
  title: '',
  description: '',
  challenge_type: 'quiz',
  difficulty: 'easy',
  target_count: 1,
  base_xp_reward: 50,
  icon: 'target',
  is_active: true,
};

export const DailyChallengesAdmin: React.FC = () => {
  const [templates, setTemplates] = useState<ChallengeTemplate[]>([]);
  const [stats, setStats] = useState<ChallengeStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterDifficulty, setFilterDifficulty] = useState<ChallengeDifficulty | 'all'>('all');
  const [showForm, setShowForm] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<ChallengeTemplate | null>(null);
  const [formData, setFormData] = useState<FormData>(defaultFormData);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [templatesData, statsData] = await Promise.all([
        challengesApi.adminGetTemplates(true),
        challengesApi.adminGetStats(),
      ]);
      setTemplates(templatesData);
      setStats(statsData);
    } catch (err) {
      setError('Failed to load challenge data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateChallenges = async () => {
    setGenerating(true);
    try {
      await challengesApi.adminGenerateChallenges();
      const newStats = await challengesApi.adminGetStats();
      setStats(newStats);
      alert('Daily challenges generated successfully!');
    } catch (err) {
      alert('Failed to generate challenges');
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  const handleEdit = (template: ChallengeTemplate) => {
    setEditingTemplate(template);
    setFormData({
      title: template.title,
      description: template.description || '',
      challenge_type: template.challenge_type as ChallengeType,
      difficulty: template.difficulty as ChallengeDifficulty,
      target_count: template.target_count,
      base_xp_reward: template.base_xp_reward,
      icon: template.icon,
      is_active: template.is_active,
    });
    setShowForm(true);
  };

  const handleCreate = () => {
    setEditingTemplate(null);
    setFormData(defaultFormData);
    setShowForm(true);
  };

  const handleDelete = async (template: ChallengeTemplate) => {
    if (!confirm(`Delete challenge template "${template.title}"? This cannot be undone.`)) {
      return;
    }

    try {
      await challengesApi.adminDeleteTemplate(template.id);
      setTemplates(templates.filter((t) => t.id !== template.id));
    } catch (err) {
      alert('Failed to delete template');
      console.error(err);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    try {
      if (editingTemplate) {
        const updated = await challengesApi.adminUpdateTemplate(editingTemplate.id, formData);
        setTemplates(templates.map((t) => (t.id === editingTemplate.id ? updated : t)));
      } else {
        const created = await challengesApi.adminCreateTemplate(formData);
        setTemplates([...templates, created]);
      }
      setShowForm(false);
      setEditingTemplate(null);
      setFormData(defaultFormData);
    } catch (err) {
      alert('Failed to save template');
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const filteredTemplates = templates.filter((t) => {
    const matchesSearch =
      t.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (t.description?.toLowerCase().includes(searchTerm.toLowerCase()) ?? false);
    const matchesDifficulty = filterDifficulty === 'all' || t.difficulty === filterDifficulty;
    return matchesSearch && matchesDifficulty;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
              <Target className="w-6 h-6 text-orange-600 dark:text-orange-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Daily Challenges
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Manage challenge templates and monitor system health
              </p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleGenerateChallenges}
              disabled={generating}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
            >
              {generating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              Generate Today's Challenges
            </button>
            <button
              onClick={handleCreate}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700"
            >
              <Plus className="w-4 h-4" />
              New Template
            </button>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow border border-gray-100 dark:border-gray-700">
            <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 mb-1">
              <Calendar className="w-4 h-4" />
              <span className="text-sm font-medium">Today's</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {stats.todays_challenges}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow border border-gray-100 dark:border-gray-700">
            <div className="flex items-center gap-2 text-green-600 dark:text-green-400 mb-1">
              <CheckCircle className="w-4 h-4" />
              <span className="text-sm font-medium">Completions</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {stats.completions_today}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow border border-gray-100 dark:border-gray-700">
            <div className="flex items-center gap-2 text-purple-600 dark:text-purple-400 mb-1">
              <Target className="w-4 h-4" />
              <span className="text-sm font-medium">Templates</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {stats.active_templates}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow border border-gray-100 dark:border-gray-700">
            <div className="flex items-center gap-2 text-orange-600 dark:text-orange-400 mb-1">
              <Flame className="w-4 h-4" />
              <span className="text-sm font-medium">Active Streaks</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {stats.users_with_streaks}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow border border-gray-100 dark:border-gray-700">
            <div className="flex items-center gap-2 text-yellow-600 dark:text-yellow-400 mb-1">
              <Trophy className="w-4 h-4" />
              <span className="text-sm font-medium">Best Streak</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {stats.longest_current_streak} days
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg flex items-center gap-2 text-red-700 dark:text-red-400">
          <AlertTriangle className="w-5 h-5" />
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search templates..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          />
        </div>
        <select
          value={filterDifficulty}
          onChange={(e) => setFilterDifficulty(e.target.value as ChallengeDifficulty | 'all')}
          className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
        >
          <option value="all">All Difficulties</option>
          {difficultyOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Templates List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-100 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700/50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Template
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Difficulty
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  XP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
              {filteredTemplates.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    No templates found. Create your first challenge template!
                  </td>
                </tr>
              ) : (
                filteredTemplates.map((template) => (
                  <tr key={template.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
                          <Target className="w-4 h-4 text-orange-600 dark:text-orange-400" />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">
                            {template.title}
                          </p>
                          {template.description && (
                            <p className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                              {template.description}
                            </p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-sm text-gray-600 dark:text-gray-300 capitalize">
                        {template.challenge_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`px-2 py-1 text-xs font-medium rounded-full border ${
                          DIFFICULTY_COLORS[template.difficulty as ChallengeDifficulty] || ''
                        }`}
                      >
                        {template.difficulty}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-300">
                      {template.target_count}
                    </td>
                    <td className="px-6 py-4">
                      <span className="flex items-center gap-1 text-sm text-yellow-600 dark:text-yellow-400">
                        <Zap className="w-4 h-4" />
                        {template.base_xp_reward}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {template.is_active ? (
                        <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-full">
                          <CheckCircle className="w-3 h-3" />
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400 rounded-full">
                          Inactive
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleEdit(template)}
                          className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                          title="Edit"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(template)}
                          className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                {editingTemplate ? 'Edit Template' : 'New Challenge Template'}
              </h2>
              <button
                onClick={() => {
                  setShowForm(false);
                  setEditingTemplate(null);
                }}
                className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSave} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Title *
                </label>
                <input
                  type="text"
                  required
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="e.g., Complete 2 Quizzes"
                  className="w-full px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Optional description"
                  rows={2}
                  className="w-full px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Challenge Type *
                  </label>
                  <select
                    required
                    value={formData.challenge_type}
                    onChange={(e) =>
                      setFormData({ ...formData, challenge_type: e.target.value as ChallengeType })
                    }
                    className="w-full px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                  >
                    {challengeTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Difficulty *
                  </label>
                  <select
                    required
                    value={formData.difficulty}
                    onChange={(e) =>
                      setFormData({ ...formData, difficulty: e.target.value as ChallengeDifficulty })
                    }
                    className="w-full px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                  >
                    {difficultyOptions.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label} ({opt.xpRange})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Target Count *
                  </label>
                  <input
                    type="number"
                    required
                    min={1}
                    value={formData.target_count}
                    onChange={(e) =>
                      setFormData({ ...formData, target_count: parseInt(e.target.value) || 1 })
                    }
                    className="w-full px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Base XP Reward *
                  </label>
                  <input
                    type="number"
                    required
                    min={1}
                    value={formData.base_xp_reward}
                    onChange={(e) =>
                      setFormData({ ...formData, base_xp_reward: parseInt(e.target.value) || 50 })
                    }
                    className="w-full px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
                  />
                </div>
              </div>

              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="is_active"
                  checked={formData.is_active}
                  onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                  className="w-4 h-4 rounded border-gray-300"
                />
                <label htmlFor="is_active" className="text-sm text-gray-700 dark:text-gray-300">
                  Active (included in daily challenge pool)
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  type="button"
                  onClick={() => {
                    setShowForm(false);
                    setEditingTemplate(null);
                  }}
                  className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50"
                >
                  {saving && <Loader2 className="w-4 h-4 animate-spin" />}
                  {editingTemplate ? 'Update' : 'Create'} Template
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default DailyChallengesAdmin;
