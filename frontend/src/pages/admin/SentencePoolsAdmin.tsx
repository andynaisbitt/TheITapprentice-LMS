// src/pages/admin/SentencePoolsAdmin.tsx
/**
 * Sentence Pool Management for PVP Typing Game
 * Create and manage sentence pools for PVP rounds
 */

import { useState, useEffect } from 'react';
import {
  Type,
  Plus,
  Edit2,
  Trash2,
  Search,
  Loader2,
  Star,
  Eye,
  ChevronDown,
  ChevronUp,
  BarChart3,
  Gamepad2,
} from 'lucide-react';

interface SentencePool {
  id: string;
  name: string;
  description: string | null;
  difficulty: 'easy' | 'medium' | 'hard' | 'expert';
  category: string;
  sentences: string[];
  min_length: number;
  max_length: number;
  avg_word_count: number;
  is_active: boolean;
  is_featured: boolean;
  display_order: number;
  round_suitable: number[];
  difficulty_weight: number;
  times_used: number;
  avg_wpm: number;
  avg_accuracy: number;
  created_at: string;
  sentence_count: number;
}

interface PoolStats {
  total_pools: number;
  active_pools: number;
  by_difficulty: Record<string, number>;
  by_category: Record<string, number>;
  top_pools: Array<{
    id: string;
    name: string;
    times_used: number;
    avg_wpm: number;
    avg_accuracy: number;
  }>;
}

const CATEGORIES = ['general', 'tech', 'programming', 'quotes', 'literature', 'science', 'business'];
const DIFFICULTIES = ['easy', 'medium', 'hard', 'expert'];

export const SentencePoolsAdmin: React.FC = () => {
  const [pools, setPools] = useState<SentencePool[]>([]);
  const [stats, setStats] = useState<PoolStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [difficultyFilter, setDifficultyFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [editingPool, setEditingPool] = useState<SentencePool | null>(null);
  const [expandedPool, setExpandedPool] = useState<string | null>(null);
  const [showStats, setShowStats] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    difficulty: 'medium' as SentencePool['difficulty'],
    category: 'general',
    sentences: '',
    min_length: 20,
    max_length: 200,
    is_featured: false,
    is_active: true,
    round_suitable: [1, 2, 3] as number[],
    difficulty_weight: 1.0,
    display_order: 0,
  });

  useEffect(() => {
    loadPools();
    loadStats();
  }, []);

  const loadPools = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/games/typing/sentence-pools?is_active=', {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch sentence pools');
      }

      const data = await response.json();
      setPools(data.pools || []);
    } catch (error) {
      console.error('Failed to load sentence pools:', error);
      setPools([]);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response = await fetch('/api/v1/games/typing/admin/sentence-pools/stats/summary', {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const handleEdit = (pool: SentencePool) => {
    setEditingPool(pool);
    setFormData({
      name: pool.name,
      description: pool.description || '',
      difficulty: pool.difficulty,
      category: pool.category,
      sentences: pool.sentences.join('\n'),
      min_length: pool.min_length,
      max_length: pool.max_length,
      is_featured: pool.is_featured,
      is_active: pool.is_active,
      round_suitable: pool.round_suitable || [1, 2, 3],
      difficulty_weight: pool.difficulty_weight,
      display_order: pool.display_order,
    });
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this sentence pool?')) return;

    try {
      const response = await fetch(`/api/v1/games/typing/admin/sentence-pools/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to delete sentence pool');
      }

      setPools(pools.filter(p => p.id !== id));
      loadStats();
    } catch (error) {
      console.error('Failed to delete sentence pool:', error);
      alert('Failed to delete sentence pool');
    }
  };

  const handleSave = async () => {
    const sentencesArray = formData.sentences
      .split('\n')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    if (sentencesArray.length === 0) {
      alert('Please add at least one sentence');
      return;
    }

    // Validate sentence lengths
    for (const sentence of sentencesArray) {
      if (sentence.length < formData.min_length) {
        alert(`Sentence too short: "${sentence.substring(0, 50)}..." (min: ${formData.min_length} chars)`);
        return;
      }
      if (sentence.length > formData.max_length) {
        alert(`Sentence too long: "${sentence.substring(0, 50)}..." (max: ${formData.max_length} chars)`);
        return;
      }
    }

    const payload = {
      name: formData.name,
      description: formData.description || null,
      difficulty: formData.difficulty,
      category: formData.category,
      sentences: sentencesArray,
      min_length: formData.min_length,
      max_length: formData.max_length,
      is_featured: formData.is_featured,
      is_active: formData.is_active,
      round_suitable: formData.round_suitable,
      difficulty_weight: formData.difficulty_weight,
      display_order: formData.display_order,
    };

    try {
      if (editingPool) {
        const response = await fetch(`/api/v1/games/typing/admin/sentence-pools/${editingPool.id}`, {
          method: 'PUT',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Failed to update sentence pool');
        }

        const updatedPool = await response.json();
        setPools(pools.map(p => p.id === editingPool.id ? updatedPool : p));
      } else {
        const response = await fetch('/api/v1/games/typing/admin/sentence-pools', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Failed to create sentence pool');
        }

        const newPool = await response.json();
        setPools([...pools, newPool]);
      }

      setShowForm(false);
      setEditingPool(null);
      resetForm();
      loadStats();
    } catch (error) {
      console.error('Failed to save sentence pool:', error);
      alert(error instanceof Error ? error.message : 'Failed to save sentence pool');
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      difficulty: 'medium',
      category: 'general',
      sentences: '',
      min_length: 20,
      max_length: 200,
      is_featured: false,
      is_active: true,
      round_suitable: [1, 2, 3],
      difficulty_weight: 1.0,
      display_order: 0,
    });
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy':
        return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
      case 'medium':
        return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
      case 'hard':
        return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
      case 'expert':
        return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
      default:
        return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
    }
  };

  const toggleRoundSuitable = (round: number) => {
    const current = formData.round_suitable;
    if (current.includes(round)) {
      if (current.length > 1) {
        setFormData({ ...formData, round_suitable: current.filter(r => r !== round) });
      }
    } else {
      setFormData({ ...formData, round_suitable: [...current, round].sort() });
    }
  };

  const filteredPools = pools.filter(pool => {
    if (difficultyFilter !== 'all' && pool.difficulty !== difficultyFilter) return false;
    if (categoryFilter !== 'all' && pool.category !== categoryFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!pool.name.toLowerCase().includes(term) &&
          !(pool.description || '').toLowerCase().includes(term) &&
          !pool.category.toLowerCase().includes(term)) {
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
            Sentence Pools
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Manage sentence pools for PVP typing rounds
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowStats(!showStats)}
            className="inline-flex items-center gap-2 px-4 py-2 text-gray-600 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <BarChart3 className="w-4 h-4" />
            Stats
          </button>
          <button
            onClick={() => {
              setEditingPool(null);
              resetForm();
              setShowForm(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Pool
          </button>
        </div>
      </div>

      {/* Stats Panel */}
      {showStats && stats && (
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Pool Statistics</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <p className="text-2xl font-bold text-primary">{stats.total_pools}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Pools</p>
            </div>
            <div className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <p className="text-2xl font-bold text-green-500">{stats.active_pools}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Active</p>
            </div>
            <div className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <p className="text-2xl font-bold text-blue-500">
                {Object.keys(stats.by_category).length}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Categories</p>
            </div>
            <div className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <p className="text-2xl font-bold text-purple-500">
                {Object.keys(stats.by_difficulty).length}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Difficulties</p>
            </div>
          </div>

          {stats.top_pools.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Most Used Pools</h4>
              <div className="space-y-2">
                {stats.top_pools.slice(0, 5).map((pool, idx) => (
                  <div key={pool.id} className="flex items-center justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">
                      {idx + 1}. {pool.name}
                    </span>
                    <span className="text-gray-500 dark:text-gray-500">
                      {pool.times_used} uses | {pool.avg_wpm} WPM | {pool.avg_accuracy}% acc
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search sentence pools..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <select
          value={difficultyFilter}
          onChange={(e) => setDifficultyFilter(e.target.value)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Difficulties</option>
          {DIFFICULTIES.map(d => (
            <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>
          ))}
        </select>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Categories</option>
          {CATEGORIES.map(c => (
            <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>
          ))}
        </select>
      </div>

      {/* Pools List */}
      <div className="space-y-4">
        {filteredPools.map((pool) => (
          <div
            key={pool.id}
            className={`bg-white dark:bg-gray-800 rounded-xl shadow-sm border ${
              pool.is_active
                ? 'border-gray-200 dark:border-gray-700'
                : 'border-gray-200 dark:border-gray-700 opacity-60'
            }`}
          >
            <div className="p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Type className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-gray-900 dark:text-white">
                        {pool.name}
                      </h3>
                      {pool.is_featured && (
                        <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                      )}
                      {!pool.is_active && (
                        <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-500 rounded">
                          Inactive
                        </span>
                      )}
                    </div>
                    {pool.description && (
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        {pool.description}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setExpandedPool(expandedPool === pool.id ? null : pool.id)}
                    className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  >
                    {expandedPool === pool.id ? (
                      <ChevronUp className="w-5 h-5" />
                    ) : (
                      <ChevronDown className="w-5 h-5" />
                    )}
                  </button>
                  <button
                    onClick={() => handleEdit(pool)}
                    className="p-2 text-gray-400 hover:text-primary hover:bg-primary/10 rounded-lg transition-colors"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(pool.id)}
                    className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 mb-3">
                <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${getDifficultyColor(pool.difficulty)}`}>
                  {pool.difficulty}
                </span>
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400">
                  {pool.category}
                </span>
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                  {pool.sentence_count} sentences
                </span>
                <span className="flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400">
                  <Gamepad2 className="w-3 h-3" />
                  Rounds: {pool.round_suitable.join(', ')}
                </span>
              </div>

              <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
                <span>Used {pool.times_used} times</span>
                {pool.avg_wpm > 0 && <span>Avg WPM: {pool.avg_wpm.toFixed(1)}</span>}
                {pool.avg_accuracy > 0 && <span>Avg Accuracy: {pool.avg_accuracy.toFixed(1)}%</span>}
                <span>Weight: {pool.difficulty_weight}x</span>
              </div>
            </div>

            {/* Expanded view with sentences */}
            {expandedPool === pool.id && (
              <div className="border-t border-gray-200 dark:border-gray-700 p-5 bg-gray-50 dark:bg-gray-900/50">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                  Sentences ({pool.sentences.length})
                </h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {pool.sentences.map((sentence, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700 text-sm text-gray-600 dark:text-gray-300"
                    >
                      <span className="text-gray-400 mr-2">{idx + 1}.</span>
                      {sentence}
                      <span className="ml-2 text-xs text-gray-400">({sentence.length} chars)</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {filteredPools.length === 0 && (
        <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
          <Type className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">No sentence pools found</p>
          <button
            onClick={() => {
              setEditingPool(null);
              resetForm();
              setShowForm(true);
            }}
            className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-primary hover:bg-primary/10 rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Create your first pool
          </button>
        </div>
      )}

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingPool ? 'Edit Sentence Pool' : 'Create New Sentence Pool'}
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
                    placeholder="e.g., Programming Quotes"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Category
                  </label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    {CATEGORIES.map(c => (
                      <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="Brief description of this sentence pool"
                />
              </div>

              <div className="grid grid-cols-4 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Difficulty
                  </label>
                  <select
                    value={formData.difficulty}
                    onChange={(e) => setFormData({ ...formData, difficulty: e.target.value as SentencePool['difficulty'] })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    {DIFFICULTIES.map(d => (
                      <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Min Length
                  </label>
                  <input
                    type="number"
                    min="5"
                    max="500"
                    value={formData.min_length}
                    onChange={(e) => setFormData({ ...formData, min_length: parseInt(e.target.value) || 20 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Max Length
                  </label>
                  <input
                    type="number"
                    min="20"
                    max="1000"
                    value={formData.max_length}
                    onChange={(e) => setFormData({ ...formData, max_length: parseInt(e.target.value) || 200 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Weight
                  </label>
                  <input
                    type="number"
                    min="0.1"
                    max="10"
                    step="0.1"
                    value={formData.difficulty_weight}
                    onChange={(e) => setFormData({ ...formData, difficulty_weight: parseFloat(e.target.value) || 1.0 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Suitable for Rounds
                </label>
                <div className="flex items-center gap-4">
                  {[1, 2, 3].map(round => (
                    <label key={round} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={formData.round_suitable.includes(round)}
                        onChange={() => toggleRoundSuitable(round)}
                        className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">Round {round}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Sentences (one per line) *
                </label>
                <textarea
                  value={formData.sentences}
                  onChange={(e) => setFormData({ ...formData, sentences: e.target.value })}
                  rows={10}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
                  placeholder="Enter sentences, one per line...&#10;Each sentence should be between min and max length."
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {formData.sentences.split('\n').filter(s => s.trim()).length} sentences entered
                  | Length range: {formData.min_length}-{formData.max_length} characters
                </p>
              </div>

              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.is_featured}
                    onChange={(e) => setFormData({ ...formData, is_featured: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Featured</span>
                </label>
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
            </div>

            <div className="p-6 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowForm(false);
                  setEditingPool(null);
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!formData.name || !formData.sentences.trim()}
                className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
              >
                {editingPool ? 'Save Changes' : 'Create Pool'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SentencePoolsAdmin;
