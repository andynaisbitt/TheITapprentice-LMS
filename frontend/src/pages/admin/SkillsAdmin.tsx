// src/pages/admin/SkillsAdmin.tsx
/**
 * Skills Admin Page
 * Manage skills, view analytics, and seed default skills
 */

import { useState, useEffect } from 'react';
import {
  Swords,
  Plus,
  Edit2,
  Trash2,
  Search,
  Loader2,
  BarChart3,
  Users,
  TrendingUp,
  Zap,
  RefreshCw,
  Eye,
  EyeOff,
  Save,
  X,
} from 'lucide-react';
import { apiClient } from '../../services/api/client';

// Types
interface Skill {
  id: number;
  name: string;
  slug: string;
  description: string;
  icon: string;
  category: 'technical' | 'soft';
  display_order: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface SystemAnalytics {
  total_users_with_skills: number;
  total_xp_awarded: number;
  total_level_ups: number;
  most_popular_skill: string | null;
  highest_avg_level_skill: string | null;
  skills_by_category: {
    technical: number;
    soft: number;
  };
}

interface SkillAnalytics {
  skill_name: string;
  total_users_with_progress: number;
  total_xp_awarded: number;
  average_level: number;
  users_at_level_99: number;
  level_distribution: Record<string, number>;
  xp_by_source: Record<string, number>;
}

const SKILL_ICONS = ['🖥️', '🔒', '💻', '⚙️', '☁️', '🗄️', '🔄', '🌐', '🔧', '💬', '🧩', '📋'];

const SkillsAdmin: React.FC = () => {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'technical' | 'soft'>('all');
  const [showInactive, setShowInactive] = useState(false);
  const [systemAnalytics, setSystemAnalytics] = useState<SystemAnalytics | null>(null);
  const [selectedSkillAnalytics, setSelectedSkillAnalytics] = useState<SkillAnalytics | null>(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState(false);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editingSkill, setEditingSkill] = useState<Skill | null>(null);
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    description: '',
    icon: '💻',
    category: 'technical' as 'technical' | 'soft',
    display_order: 1,
    is_active: true,
  });

  useEffect(() => {
    loadSkills();
    loadSystemAnalytics();
  }, [showInactive]);

  const loadSkills = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get(`/api/v1/admin/skills/?include_inactive=${showInactive}`);
      setSkills(response.data);
    } catch (error) {
      console.error('Failed to load skills:', error);
      setSkills([]);
    } finally {
      setLoading(false);
    }
  };

  const loadSystemAnalytics = async () => {
    try {
      const response = await apiClient.get('/api/v1/admin/skills/analytics/overview');
      setSystemAnalytics(response.data);
    } catch (error) {
      console.error('Failed to load system analytics:', error);
    }
  };

  const loadSkillAnalytics = async (slug: string) => {
    setLoadingAnalytics(true);
    try {
      const response = await apiClient.get(`/api/v1/admin/skills/analytics/${slug}`);
      setSelectedSkillAnalytics(response.data);
    } catch (error) {
      console.error('Failed to load skill analytics:', error);
    } finally {
      setLoadingAnalytics(false);
    }
  };

  const handleSeedSkills = async () => {
    if (!confirm('This will seed/update the default 12 IT skills. Continue?')) return;

    try {
      const response = await apiClient.post('/api/v1/admin/skills/seed');
      alert(response.data.message);
      loadSkills();
    } catch (error) {
      console.error('Failed to seed skills:', error);
      alert('Failed to seed skills');
    }
  };

  const handleEdit = (skill: Skill) => {
    setEditingSkill(skill);
    setFormData({
      name: skill.name,
      slug: skill.slug,
      description: skill.description,
      icon: skill.icon,
      category: skill.category,
      display_order: skill.display_order,
      is_active: skill.is_active,
    });
    setShowForm(true);
  };

  const handleDelete = async (skillId: number) => {
    if (!confirm('Are you sure? This will deactivate the skill if users have progress, or delete it permanently.')) return;

    try {
      await apiClient.delete(`/api/v1/admin/skills/${skillId}`);
      loadSkills();
    } catch (error) {
      console.error('Failed to delete skill:', error);
      alert('Failed to delete skill');
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      if (editingSkill) {
        await apiClient.put(`/api/v1/admin/skills/${editingSkill.id}`, formData);
      } else {
        await apiClient.post('/api/v1/admin/skills/', formData);
      }

      setShowForm(false);
      setEditingSkill(null);
      resetForm();
      loadSkills();
    } catch (error: any) {
      console.error('Failed to save skill:', error);
      alert(error.response?.data?.detail || 'Failed to save skill');
    } finally {
      setSaving(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      slug: '',
      description: '',
      icon: '💻',
      category: 'technical',
      display_order: 1,
      is_active: true,
    });
  };

  const getCategoryColor = (category: string) => {
    return category === 'technical'
      ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
      : 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400';
  };

  const filteredSkills = skills.filter(skill => {
    if (categoryFilter !== 'all' && skill.category !== categoryFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!skill.name.toLowerCase().includes(term) &&
          !skill.slug.toLowerCase().includes(term) &&
          !skill.description.toLowerCase().includes(term)) {
        return false;
      }
    }
    return true;
  });

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
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Swords className="w-7 h-7 text-primary" />
            Skills Management
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Manage IT skills, view analytics, and configure XP system
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSeedSkills}
            className="inline-flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Seed Defaults
          </button>
          <button
            onClick={() => {
              setEditingSkill(null);
              resetForm();
              setShowForm(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Skill
          </button>
        </div>
      </div>

      {/* System Analytics Cards */}
      {systemAnalytics && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <Users className="w-5 h-5 text-blue-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Users with Skills</span>
            </div>
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {systemAnalytics.total_users_with_skills.toLocaleString()}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="w-5 h-5 text-yellow-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Total XP Awarded</span>
            </div>
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {systemAnalytics.total_xp_awarded.toLocaleString()}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="w-5 h-5 text-green-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Total Level Ups</span>
            </div>
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {systemAnalytics.total_level_ups.toLocaleString()}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <BarChart3 className="w-5 h-5 text-purple-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Most Popular</span>
            </div>
            <div className="text-lg font-bold text-gray-900 dark:text-white truncate">
              {systemAnalytics.most_popular_skill || 'N/A'}
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search skills..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value as 'all' | 'technical' | 'soft')}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Categories</option>
          <option value="technical">Technical</option>
          <option value="soft">Soft Skills</option>
        </select>
        <label className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg cursor-pointer">
          <input
            type="checkbox"
            checked={showInactive}
            onChange={(e) => setShowInactive(e.target.checked)}
            className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
          />
          <span className="text-sm text-gray-700 dark:text-gray-300">Show Inactive</span>
        </label>
      </div>

      {/* Skills Table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 dark:bg-gray-700/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Skill
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Category
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Order
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {filteredSkills.map((skill) => (
              <tr
                key={skill.id}
                className={`hover:bg-gray-50 dark:hover:bg-gray-700/50 ${
                  !skill.is_active ? 'opacity-60' : ''
                }`}
              >
                <td className="px-4 py-4">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{skill.icon}</span>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">
                        {skill.name}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {skill.slug}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-4">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${getCategoryColor(skill.category)}`}>
                    {skill.category}
                  </span>
                </td>
                <td className="px-4 py-4 text-gray-900 dark:text-white">
                  {skill.display_order}
                </td>
                <td className="px-4 py-4">
                  {skill.is_active ? (
                    <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
                      <Eye className="w-4 h-4" />
                      Active
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-gray-400">
                      <EyeOff className="w-4 h-4" />
                      Inactive
                    </span>
                  )}
                </td>
                <td className="px-4 py-4">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => loadSkillAnalytics(skill.slug)}
                      className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      title="View Analytics"
                    >
                      <BarChart3 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleEdit(skill)}
                      className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      title="Edit"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDelete(skill.id)}
                      className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredSkills.length === 0 && (
          <div className="text-center py-12">
            <Swords className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">No skills found</p>
            <button
              onClick={handleSeedSkills}
              className="mt-4 text-primary hover:underline"
            >
              Seed default skills
            </button>
          </div>
        )}
      </div>

      {/* Skill Analytics Modal */}
      {selectedSkillAnalytics && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-lg">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {selectedSkillAnalytics.skill_name} Analytics
              </h2>
              <button
                onClick={() => setSelectedSkillAnalytics(null)}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              {loadingAnalytics ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <div className="text-sm text-gray-500 dark:text-gray-400">Total Users</div>
                    <div className="text-2xl font-bold text-gray-900 dark:text-white">
                      {selectedSkillAnalytics.total_users_with_progress.toLocaleString()}
                    </div>
                  </div>
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <div className="text-sm text-gray-500 dark:text-gray-400">Total XP</div>
                    <div className="text-2xl font-bold text-gray-900 dark:text-white">
                      {selectedSkillAnalytics.total_xp_awarded.toLocaleString()}
                    </div>
                  </div>
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <div className="text-sm text-gray-500 dark:text-gray-400">Avg Level</div>
                    <div className="text-2xl font-bold text-gray-900 dark:text-white">
                      {selectedSkillAnalytics.average_level.toFixed(1)}
                    </div>
                  </div>
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <div className="text-sm text-gray-500 dark:text-gray-400">Level 99 Users</div>
                    <div className="text-2xl font-bold text-cyan-500">
                      {selectedSkillAnalytics.users_at_level_99}
                    </div>
                  </div>
                  {Object.keys(selectedSkillAnalytics.level_distribution || {}).length > 0 && (
                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 col-span-2">
                      <div className="text-sm text-gray-500 dark:text-gray-400 mb-2">Level Distribution</div>
                      <div className="flex gap-2 flex-wrap">
                        {Object.entries(selectedSkillAnalytics.level_distribution).map(([range, count]) => (
                          <div key={range} className="text-xs bg-gray-200 dark:bg-gray-600 rounded px-2 py-1">
                            <span className="font-medium">{range}:</span> {count}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-lg max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingSkill ? 'Edit Skill' : 'Create New Skill'}
              </h2>
            </div>

            <div className="p-6 overflow-y-auto flex-1 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Name *
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="e.g., Networking"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Slug *
                  </label>
                  <input
                    type="text"
                    value={formData.slug}
                    onChange={(e) => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/\s+/g, '-') })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="e.g., networking"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="Brief description of this skill"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Icon
                  </label>
                  <div className="flex flex-wrap gap-2 p-2 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                    {SKILL_ICONS.map((icon) => (
                      <button
                        key={icon}
                        type="button"
                        onClick={() => setFormData({ ...formData, icon })}
                        className={`w-10 h-10 rounded-lg text-xl flex items-center justify-center transition-colors ${
                          formData.icon === icon
                            ? 'bg-primary text-white'
                            : 'hover:bg-gray-200 dark:hover:bg-gray-600'
                        }`}
                      >
                        {icon}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Category
                  </label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value as 'technical' | 'soft' })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="technical">Technical</option>
                    <option value="soft">Soft Skills</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Display Order
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="99"
                    value={formData.display_order}
                    onChange={(e) => setFormData({ ...formData, display_order: parseInt(e.target.value) || 1 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer pb-2">
                    <input
                      type="checkbox"
                      checked={formData.is_active}
                      onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                      className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Active</span>
                  </label>
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowForm(false);
                  setEditingSkill(null);
                  resetForm();
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !formData.name || !formData.slug}
                className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
              >
                {saving ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {editingSkill ? 'Save Changes' : 'Create Skill'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SkillsAdmin;
