// src/pages/admin/TypingChallengesAdmin.tsx
/**
 * Typing Challenges Management
 * Create and manage special typing challenges
 */

import { useState, useEffect } from 'react';
import {
  Swords,
  Plus,
  Edit2,
  Trash2,
  Search,
  Loader2,
  Calendar,
  Trophy,
  Clock,
  Users,
  Target,
} from 'lucide-react';

interface Challenge {
  id: string;
  name: string;
  description: string;
  type: 'daily' | 'weekly' | 'special' | 'tournament';
  word_list_id: string;
  word_list_name: string;
  target_wpm: number;
  target_accuracy: number;
  time_limit_seconds: number;
  xp_reward: number;
  badge_reward?: string;
  start_date: string;
  end_date: string;
  is_active: boolean;
  participants: number;
  completions: number;
}

export const TypingChallengesAdmin: React.FC = () => {
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [editingChallenge, setEditingChallenge] = useState<Challenge | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'daily' as Challenge['type'],
    word_list_id: '',
    target_wpm: 60,
    target_accuracy: 95,
    time_limit_seconds: 60,
    xp_reward: 100,
    badge_reward: '',
    start_date: '',
    end_date: '',
    is_active: true,
  });

  useEffect(() => {
    loadChallenges();
  }, []);

  const loadChallenges = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call

      // Mock data
      setChallenges([
        {
          id: 'daily-speed',
          name: 'Daily Speed Challenge',
          description: 'Hit 70 WPM with 95% accuracy to earn bonus XP',
          type: 'daily',
          word_list_id: 'common-words',
          word_list_name: 'Common English Words',
          target_wpm: 70,
          target_accuracy: 95,
          time_limit_seconds: 60,
          xp_reward: 150,
          start_date: new Date().toISOString().split('T')[0],
          end_date: new Date().toISOString().split('T')[0],
          is_active: true,
          participants: 234,
          completions: 89,
        },
        {
          id: 'weekend-warrior',
          name: 'Weekend Warrior',
          description: 'Complete 5 typing games this weekend',
          type: 'weekly',
          word_list_id: 'programming-terms',
          word_list_name: 'Programming Keywords',
          target_wpm: 60,
          target_accuracy: 90,
          time_limit_seconds: 120,
          xp_reward: 500,
          badge_reward: 'weekend_warrior',
          start_date: '2026-01-18',
          end_date: '2026-01-19',
          is_active: true,
          participants: 156,
          completions: 42,
        },
        {
          id: 'new-year-speedster',
          name: 'New Year Speedster',
          description: 'Special New Year challenge - achieve 100 WPM!',
          type: 'special',
          word_list_id: 'common-words',
          word_list_name: 'Common English Words',
          target_wpm: 100,
          target_accuracy: 90,
          time_limit_seconds: 60,
          xp_reward: 1000,
          badge_reward: 'new_year_speedster',
          start_date: '2026-01-01',
          end_date: '2026-01-31',
          is_active: true,
          participants: 567,
          completions: 23,
        },
        {
          id: 'code-sprint-2026',
          name: 'Code Sprint Tournament',
          description: 'Monthly coding-themed typing tournament',
          type: 'tournament',
          word_list_id: 'code-snippets',
          word_list_name: 'Code Snippets',
          target_wpm: 50,
          target_accuracy: 98,
          time_limit_seconds: 180,
          xp_reward: 2000,
          badge_reward: 'code_sprint_champion',
          start_date: '2026-01-15',
          end_date: '2026-01-22',
          is_active: false,
          participants: 89,
          completions: 12,
        },
      ]);
    } catch (error) {
      console.error('Failed to load challenges:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (challenge: Challenge) => {
    setEditingChallenge(challenge);
    setFormData({
      name: challenge.name,
      description: challenge.description,
      type: challenge.type,
      word_list_id: challenge.word_list_id,
      target_wpm: challenge.target_wpm,
      target_accuracy: challenge.target_accuracy,
      time_limit_seconds: challenge.time_limit_seconds,
      xp_reward: challenge.xp_reward,
      badge_reward: challenge.badge_reward || '',
      start_date: challenge.start_date,
      end_date: challenge.end_date,
      is_active: challenge.is_active,
    });
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this challenge?')) return;
    setChallenges(challenges.filter(c => c.id !== id));
  };

  const handleSave = async () => {
    if (editingChallenge) {
      setChallenges(challenges.map(c =>
        c.id === editingChallenge.id
          ? { ...c, ...formData, word_list_name: 'Updated List' }
          : c
      ));
    } else {
      const newChallenge: Challenge = {
        id: formData.name.toLowerCase().replace(/\s+/g, '-'),
        ...formData,
        word_list_name: 'New List',
        participants: 0,
        completions: 0,
      };
      setChallenges([...challenges, newChallenge]);
    }

    setShowForm(false);
    setEditingChallenge(null);
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'daily':
        return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
      case 'weekly':
        return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
      case 'special':
        return 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400';
      case 'tournament':
        return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
      default:
        return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
    }
  };

  const getStatusBadge = (challenge: Challenge) => {
    const now = new Date();
    const start = new Date(challenge.start_date);
    const end = new Date(challenge.end_date);
    end.setHours(23, 59, 59);

    if (!challenge.is_active) {
      return <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500">Inactive</span>;
    }
    if (now < start) {
      return <span className="px-2 py-0.5 text-xs rounded-full bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400">Upcoming</span>;
    }
    if (now > end) {
      return <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500">Ended</span>;
    }
    return <span className="px-2 py-0.5 text-xs rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">Active</span>;
  };

  const filteredChallenges = challenges.filter(challenge => {
    if (typeFilter !== 'all' && challenge.type !== typeFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!challenge.name.toLowerCase().includes(term) &&
          !challenge.description.toLowerCase().includes(term)) {
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
            Create and manage special typing challenges
          </p>
        </div>
        <button
          onClick={() => {
            setEditingChallenge(null);
            setFormData({
              name: '',
              description: '',
              type: 'daily',
              word_list_id: '',
              target_wpm: 60,
              target_accuracy: 95,
              time_limit_seconds: 60,
              xp_reward: 100,
              badge_reward: '',
              start_date: new Date().toISOString().split('T')[0],
              end_date: new Date().toISOString().split('T')[0],
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

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Swords className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{challenges.length}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Challenges</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
            <Target className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {challenges.filter(c => c.is_active).length}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Active</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
            <Users className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {challenges.reduce((sum, c) => sum + c.participants, 0)}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Participants</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
            <Trophy className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {challenges.reduce((sum, c) => sum + c.completions, 0)}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Completions</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search challenges..."
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
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="special">Special</option>
          <option value="tournament">Tournament</option>
        </select>
      </div>

      {/* Challenges List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Challenge
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Duration
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Reward
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Stats
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
                        {challenge.name}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                        {challenge.description}
                      </p>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getTypeColor(challenge.type)}`}>
                      {challenge.type}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-600 dark:text-gray-300">
                    <div>{challenge.target_wpm} WPM</div>
                    <div className="text-xs text-gray-400">{challenge.target_accuracy}% accuracy</div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-600 dark:text-gray-300">
                    <div className="flex items-center gap-1">
                      <Calendar className="w-4 h-4 text-gray-400" />
                      {challenge.start_date}
                    </div>
                    <div className="flex items-center gap-1 text-xs text-gray-400">
                      <Clock className="w-3 h-3" />
                      {challenge.time_limit_seconds}s limit
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <div className="text-sm font-medium text-primary">
                      +{challenge.xp_reward} XP
                    </div>
                    {challenge.badge_reward && (
                      <div className="text-xs text-gray-400 flex items-center gap-1">
                        <Trophy className="w-3 h-3" />
                        Badge
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    {getStatusBadge(challenge)}
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">
                    <div>{challenge.participants} joined</div>
                    <div className="text-xs">{challenge.completions} completed</div>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleEdit(challenge)}
                        className="p-2 text-gray-400 hover:text-primary transition-colors"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(challenge.id)}
                        className="p-2 text-gray-400 hover:text-red-500 transition-colors"
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
            <p className="text-gray-500 dark:text-gray-400">No challenges found</p>
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingChallenge ? 'Edit Challenge' : 'Create New Challenge'}
              </h2>
            </div>

            <div className="p-6 overflow-y-auto flex-1 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Challenge Name *
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="e.g., Speed Sprint Challenge"
                  />
                </div>
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description
                  </label>
                  <input
                    type="text"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="Brief description of the challenge"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Type
                  </label>
                  <select
                    value={formData.type}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value as Challenge['type'] })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="special">Special</option>
                    <option value="tournament">Tournament</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Target WPM
                  </label>
                  <input
                    type="number"
                    value={formData.target_wpm}
                    onChange={(e) => setFormData({ ...formData, target_wpm: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Target Accuracy %
                  </label>
                  <input
                    type="number"
                    value={formData.target_accuracy}
                    onChange={(e) => setFormData({ ...formData, target_accuracy: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Time Limit (seconds)
                  </label>
                  <input
                    type="number"
                    value={formData.time_limit_seconds}
                    onChange={(e) => setFormData({ ...formData, time_limit_seconds: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    XP Reward
                  </label>
                  <input
                    type="number"
                    value={formData.xp_reward}
                    onChange={(e) => setFormData({ ...formData, xp_reward: parseInt(e.target.value) || 0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Badge (optional)
                  </label>
                  <input
                    type="text"
                    value={formData.badge_reward}
                    onChange={(e) => setFormData({ ...formData, badge_reward: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="badge_id"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Start Date
                  </label>
                  <input
                    type="date"
                    value={formData.start_date}
                    onChange={(e) => setFormData({ ...formData, start_date: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    End Date
                  </label>
                  <input
                    type="date"
                    value={formData.end_date}
                    onChange={(e) => setFormData({ ...formData, end_date: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
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
                <span className="text-sm text-gray-700 dark:text-gray-300">Active</span>
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
                disabled={!formData.name}
                className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
              >
                {editingChallenge ? 'Save Changes' : 'Create Challenge'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TypingChallengesAdmin;
