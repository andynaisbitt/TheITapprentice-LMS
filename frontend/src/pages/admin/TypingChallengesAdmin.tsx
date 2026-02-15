// src/pages/admin/TypingChallengesAdmin.tsx
/**
 * Typing Challenges Management
 * Create and manage typing challenge templates
 */

import { useState, useEffect } from 'react';
import {
  Swords,
  Plus,
  Edit2,
  Trash2,
  Search,
  Loader2,
  Trophy,
  Users,
  Target,
  RefreshCw,
  Gamepad2,
  Zap,
} from 'lucide-react';
import { apiClient } from '../../services/api/client';

interface Challenge {
  id: string;
  title: string;
  description: string;
  challenge_type: 'typing_game' | 'typing_wpm';
  difficulty: 'easy' | 'medium' | 'hard';
  target_count: number;
  base_xp_reward: number;
  icon: string;
  is_active: boolean;
}

interface TypingAnalytics {
  total_games_played: number;
  total_players: number;
  average_wpm: number;
  average_accuracy: number;
  games_last_7_days: number;
  active_players_today: number;
}

export const TypingChallengesAdmin: React.FC = () => {
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [analytics, setAnalytics] = useState<TypingAnalytics | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [editingChallenge, setEditingChallenge] = useState<Challenge | null>(null);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    challenge_type: 'typing_game' as Challenge['challenge_type'],
    difficulty: 'medium' as Challenge['difficulty'],
    target_count: 3,
    base_xp_reward: 100,
    icon: 'keyboard',
    is_active: true,
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      // Load typing game analytics
      const analyticsRes = await apiClient.get('/api/v1/games/typing/admin/analytics');
      setAnalytics(analyticsRes.data);

      // Load challenge templates (filtered to typing-related)
      const templatesRes = await apiClient.get('/api/v1/progress/admin/challenges/templates?include_inactive=true');
      const typingChallenges = (templatesRes.data || []).filter(
        (c: any) => c.challenge_type === 'typing_game' || c.challenge_type === 'typing_wpm'
      );
      setChallenges(typingChallenges);
    } catch (error) {
      console.error('Failed to load data:', error);
      setChallenges([]);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (challenge: Challenge) => {
    setEditingChallenge(challenge);
    setFormData({
      title: challenge.title,
      description: challenge.description || '',
      challenge_type: challenge.challenge_type,
      difficulty: challenge.difficulty,
      target_count: challenge.target_count,
      base_xp_reward: challenge.base_xp_reward,
      icon: challenge.icon || 'keyboard',
      is_active: challenge.is_active,
    });
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this challenge template?')) return;
    try {
      await apiClient.delete(`/api/v1/progress/admin/challenges/templates/${id}`);
      setChallenges(challenges.filter(c => c.id !== id));
    } catch (error) {
      console.error('Failed to delete:', error);
      alert('Failed to delete challenge template');
    }
  };

  const handleSave = async () => {
    try {
      if (editingChallenge) {
        const response = await apiClient.put(
          `/api/v1/progress/admin/challenges/templates/${editingChallenge.id}`,
          formData
        );
        setChallenges(challenges.map(c =>
          c.id === editingChallenge.id ? response.data : c
        ));
      } else {
        const response = await apiClient.post('/api/v1/progress/admin/challenges/templates', formData);
        setChallenges([...challenges, response.data]);
      }
      setShowForm(false);
      setEditingChallenge(null);
    } catch (error) {
      console.error('Failed to save:', error);
      alert('Failed to save challenge template');
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy':
        return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
      case 'medium':
        return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
      case 'hard':
        return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
      default:
        return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
    }
  };

  const getChallengeTypeLabel = (type: string) => {
    switch (type) {
      case 'typing_game':
        return 'Play Games';
      case 'typing_wpm':
        return 'Achieve WPM';
      default:
        return type;
    }
  };

  const filteredChallenges = challenges.filter(challenge => {
    if (typeFilter !== 'all' && challenge.challenge_type !== typeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!challenge.title.toLowerCase().includes(term) &&
          !(challenge.description || '').toLowerCase().includes(term)) {
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
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Typing Challenges
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Create and manage typing challenge templates for daily challenges
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
          <button
            onClick={() => {
              setEditingChallenge(null);
              setFormData({
                title: '',
                description: '',
                challenge_type: 'typing_game',
                difficulty: 'medium',
                target_count: 3,
                base_xp_reward: 100,
                icon: 'keyboard',
                is_active: true,
              });
              setShowForm(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Challenge
          </button>
        </div>
      </div>

      {/* Stats - Real Analytics */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Gamepad2 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {analytics?.total_games_played?.toLocaleString() || 0}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Games Played</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
            <Users className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {analytics?.total_players?.toLocaleString() || 0}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Players</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
            <Zap className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {analytics?.average_wpm?.toFixed(0) || 0} WPM
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Avg Speed</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
            <Target className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {analytics?.average_accuracy?.toFixed(1) || 0}%
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Avg Accuracy</p>
          </div>
        </div>
      </div>

      {/* Challenge Templates Info */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <p className="text-sm text-blue-700 dark:text-blue-300">
          <strong>Challenge Templates:</strong> These templates are used to generate daily typing challenges.
          Active templates are randomly selected each day to create challenges for users.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search challenge templates..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Types</option>
          <option value="typing_game">Play Games</option>
          <option value="typing_wpm">Achieve WPM</option>
        </select>
      </div>

      {/* Challenge Templates List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Challenge Template
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Difficulty
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  XP Reward
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 w-20"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredChallenges.map((challenge) => (
                <tr key={challenge.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-4">
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {challenge.title}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                        {challenge.description || 'No description'}
                      </p>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                      {getChallengeTypeLabel(challenge.challenge_type)}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full capitalize ${getDifficultyColor(challenge.difficulty)}`}>
                      {challenge.difficulty}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-600 dark:text-gray-300">
                    {challenge.challenge_type === 'typing_wpm' ? (
                      <span>{challenge.target_count} WPM</span>
                    ) : (
                      <span>{challenge.target_count} games</span>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    <div className="text-sm font-medium text-primary flex items-center gap-1">
                      <Trophy className="w-4 h-4" />
                      +{challenge.base_xp_reward} XP
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    {challenge.is_active ? (
                      <span className="px-2 py-0.5 text-xs rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">
                        Active
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500">
                        Inactive
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleEdit(challenge)}
                        className="p-2 text-gray-400 hover:text-primary transition-colors"
                        title="Edit"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(challenge.id)}
                        className="p-2 text-gray-400 hover:text-red-500 transition-colors"
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
        </div>

        {filteredChallenges.length === 0 && (
          <div className="text-center py-12">
            <Swords className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">
              {challenges.length === 0
                ? 'No typing challenge templates yet. Create one to get started!'
                : 'No challenges match your filters'
              }
            </p>
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-lg max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingChallenge ? 'Edit Challenge Template' : 'Create New Challenge Template'}
              </h2>
            </div>

            <div className="p-6 overflow-y-auto flex-1 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Title *
                </label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="e.g., Speed Demon"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="Brief description of the challenge"
                  rows={2}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Challenge Type
                  </label>
                  <select
                    value={formData.challenge_type}
                    onChange={(e) => setFormData({ ...formData, challenge_type: e.target.value as Challenge['challenge_type'] })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="typing_game">Play X Games</option>
                    <option value="typing_wpm">Achieve X WPM</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Difficulty
                  </label>
                  <select
                    value={formData.difficulty}
                    onChange={(e) => setFormData({ ...formData, difficulty: e.target.value as Challenge['difficulty'] })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="easy">Easy</option>
                    <option value="medium">Medium</option>
                    <option value="hard">Hard</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Target {formData.challenge_type === 'typing_wpm' ? '(WPM)' : '(Games)'}
                  </label>
                  <input
                    type="number"
                    value={formData.target_count}
                    onChange={(e) => setFormData({ ...formData, target_count: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    min={1}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    {formData.challenge_type === 'typing_wpm'
                      ? 'WPM to achieve in a single game'
                      : 'Number of games to complete'}
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    XP Reward
                  </label>
                  <input
                    type="number"
                    value={formData.base_xp_reward}
                    onChange={(e) => setFormData({ ...formData, base_xp_reward: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    min={0}
                    step={10}
                  />
                </div>
              </div>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.is_active}
                  onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                  className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  Active (will be included in daily challenge generation)
                </span>
              </label>
            </div>

            <div className="p-6 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowForm(false);
                  setEditingChallenge(null);
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!formData.title}
                className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
              >
                {editingChallenge ? 'Save Changes' : 'Create Template'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TypingChallengesAdmin;
