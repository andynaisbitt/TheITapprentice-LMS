// src/pages/admin/WordListsAdmin.tsx
/**
 * Typing Game Word Lists Management
 * Create and manage word lists for typing games
 */

import { useState, useEffect } from 'react';
import {
  Keyboard,
  Plus,
  Edit2,
  Trash2,
  Search,
  Loader2,
  Star,
  Lock,
  Eye,
  Copy,
} from 'lucide-react';

interface WordList {
  id: string;
  name: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard' | 'expert';
  theme: string;
  words: string[];
  unlock_level: number;
  is_featured: boolean;
  is_active: boolean;
  times_played: number;
  created_at: string;
}

const THEMES = ['general', 'programming', 'technology', 'science', 'business', 'gaming', 'creative'];

export const WordListsAdmin: React.FC = () => {
  const [wordLists, setWordLists] = useState<WordList[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [difficultyFilter, setDifficultyFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [editingList, setEditingList] = useState<WordList | null>(null);
  const [formData, setFormData] = useState({
    id: '',
    name: '',
    description: '',
    difficulty: 'medium' as WordList['difficulty'],
    theme: 'general',
    words: '',
    unlock_level: 1,
    is_featured: false,
    is_active: true,
  });

  useEffect(() => {
    loadWordLists();
  }, []);

  const loadWordLists = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/games/typing/admin/word-lists');

      // Mock data
      setWordLists([
        {
          id: 'common-words',
          name: 'Common English Words',
          description: 'The most frequently used English words',
          difficulty: 'easy',
          theme: 'general',
          words: ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it'],
          unlock_level: 1,
          is_featured: true,
          is_active: true,
          times_played: 1523,
          created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 90).toISOString(),
        },
        {
          id: 'programming-terms',
          name: 'Programming Keywords',
          description: 'Common programming terms and keywords',
          difficulty: 'medium',
          theme: 'programming',
          words: ['function', 'variable', 'const', 'return', 'import', 'export', 'class', 'interface'],
          unlock_level: 3,
          is_featured: true,
          is_active: true,
          times_played: 892,
          created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString(),
        },
        {
          id: 'linux-commands',
          name: 'Linux Commands',
          description: 'Essential Linux terminal commands',
          difficulty: 'hard',
          theme: 'technology',
          words: ['chmod', 'grep', 'sudo', 'apt-get', 'systemctl', 'journalctl', 'docker'],
          unlock_level: 5,
          is_featured: false,
          is_active: true,
          times_played: 456,
          created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30).toISOString(),
        },
        {
          id: 'code-snippets',
          name: 'Code Snippets',
          description: 'Real code patterns and syntax',
          difficulty: 'expert',
          theme: 'programming',
          words: ['const handleSubmit = async (e) => {', 'import { useState } from "react"', 'export default function App()'],
          unlock_level: 8,
          is_featured: false,
          is_active: true,
          times_played: 234,
          created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15).toISOString(),
        },
      ]);
    } catch (error) {
      console.error('Failed to load word lists:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (wordList: WordList) => {
    setEditingList(wordList);
    setFormData({
      id: wordList.id,
      name: wordList.name,
      description: wordList.description,
      difficulty: wordList.difficulty,
      theme: wordList.theme,
      words: wordList.words.join('\n'),
      unlock_level: wordList.unlock_level,
      is_featured: wordList.is_featured,
      is_active: wordList.is_active,
    });
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this word list?')) return;
    // TODO: Implement delete API call
    setWordLists(wordLists.filter(w => w.id !== id));
  };

  const handleSave = async () => {
    const wordsArray = formData.words.split('\n').map(w => w.trim()).filter(Boolean);

    if (editingList) {
      setWordLists(wordLists.map(w =>
        w.id === editingList.id
          ? { ...w, ...formData, words: wordsArray }
          : w
      ));
    } else {
      const newList: WordList = {
        id: formData.id || formData.name.toLowerCase().replace(/\s+/g, '-'),
        name: formData.name,
        description: formData.description,
        difficulty: formData.difficulty,
        theme: formData.theme,
        words: wordsArray,
        unlock_level: formData.unlock_level,
        is_featured: formData.is_featured,
        is_active: formData.is_active,
        times_played: 0,
        created_at: new Date().toISOString(),
      };
      setWordLists([...wordLists, newList]);
    }

    setShowForm(false);
    setEditingList(null);
    setFormData({
      id: '',
      name: '',
      description: '',
      difficulty: 'medium',
      theme: 'general',
      words: '',
      unlock_level: 1,
      is_featured: false,
      is_active: true,
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

  const filteredLists = wordLists.filter(list => {
    if (difficultyFilter !== 'all' && list.difficulty !== difficultyFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!list.name.toLowerCase().includes(term) &&
          !list.description.toLowerCase().includes(term) &&
          !list.theme.toLowerCase().includes(term)) {
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
            Word Lists
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Manage word lists for typing games
          </p>
        </div>
        <button
          onClick={() => {
            setEditingList(null);
            setFormData({
              id: '',
              name: '',
              description: '',
              difficulty: 'medium',
              theme: 'general',
              words: '',
              unlock_level: 1,
              is_featured: false,
              is_active: true,
            });
            setShowForm(true);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Word List
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search word lists..."
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
          <option value="easy">Easy</option>
          <option value="medium">Medium</option>
          <option value="hard">Hard</option>
          <option value="expert">Expert</option>
        </select>
      </div>

      {/* Word Lists Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredLists.map((list) => (
          <div
            key={list.id}
            className={`bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 border ${
              list.is_active
                ? 'border-gray-200 dark:border-gray-700'
                : 'border-gray-200 dark:border-gray-700 opacity-60'
            }`}
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <Keyboard className="w-5 h-5 text-primary" />
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {list.name}
                </h3>
              </div>
              <div className="flex items-center gap-1">
                {list.is_featured && (
                  <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                )}
                {!list.is_active && (
                  <span className="text-xs text-gray-400">Inactive</span>
                )}
              </div>
            </div>

            <p className="text-sm text-gray-500 dark:text-gray-400 mb-3 line-clamp-2">
              {list.description}
            </p>

            <div className="flex items-center gap-2 mb-3">
              <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${getDifficultyColor(list.difficulty)}`}>
                {list.difficulty}
              </span>
              <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                {list.theme}
              </span>
              {list.unlock_level > 1 && (
                <span className="flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400">
                  <Lock className="w-3 h-3" />
                  Lv.{list.unlock_level}
                </span>
              )}
            </div>

            <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 mb-4">
              <span>{list.words.length} words</span>
              <span>{list.times_played.toLocaleString()} plays</span>
            </div>

            {/* Sample words */}
            <div className="mb-4">
              <p className="text-xs text-gray-400 dark:text-gray-500 mb-1">Sample words:</p>
              <p className="text-sm text-gray-600 dark:text-gray-300 truncate">
                {list.words.slice(0, 5).join(', ')}...
              </p>
            </div>

            <div className="flex items-center gap-2 pt-3 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => handleEdit(list)}
                className="flex-1 flex items-center justify-center gap-1 px-3 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                <Edit2 className="w-4 h-4" />
                Edit
              </button>
              <button
                className="flex-1 flex items-center justify-center gap-1 px-3 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                <Eye className="w-4 h-4" />
                Preview
              </button>
              <button
                onClick={() => handleDelete(list.id)}
                className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {filteredLists.length === 0 && (
        <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-xl">
          <Keyboard className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">No word lists found</p>
        </div>
      )}

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingList ? 'Edit Word List' : 'Create New Word List'}
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
                    placeholder="e.g., JavaScript Keywords"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    ID
                  </label>
                  <input
                    type="text"
                    value={formData.id}
                    onChange={(e) => setFormData({ ...formData, id: e.target.value })}
                    placeholder="Auto-generated if empty"
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
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
                  placeholder="Brief description of this word list"
                />
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Difficulty
                  </label>
                  <select
                    value={formData.difficulty}
                    onChange={(e) => setFormData({ ...formData, difficulty: e.target.value as WordList['difficulty'] })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="easy">Easy</option>
                    <option value="medium">Medium</option>
                    <option value="hard">Hard</option>
                    <option value="expert">Expert</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Theme
                  </label>
                  <select
                    value={formData.theme}
                    onChange={(e) => setFormData({ ...formData, theme: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    {THEMES.map((theme) => (
                      <option key={theme} value={theme}>
                        {theme.charAt(0).toUpperCase() + theme.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Unlock Level
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="10"
                    value={formData.unlock_level}
                    onChange={(e) => setFormData({ ...formData, unlock_level: parseInt(e.target.value) || 1 })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Words (one per line)
                </label>
                <textarea
                  value={formData.words}
                  onChange={(e) => setFormData({ ...formData, words: e.target.value })}
                  rows={8}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
                  placeholder="Enter words or phrases, one per line..."
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {formData.words.split('\n').filter(Boolean).length} words entered
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
                  setEditingList(null);
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!formData.name || !formData.words.trim()}
                className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
              >
                {editingList ? 'Save Changes' : 'Create Word List'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WordListsAdmin;
