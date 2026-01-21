// frontend/src/plugins/typing-game/pages/PracticeGamePage.tsx
/**
 * Practice Mode Page - Select word lists and practice typing
 * Allows users to choose from available word lists and start practice sessions
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Keyboard,
  Target,
  Play,
  ArrowLeft,
  Search,
  Filter,
  Loader2,
  Star,
  Lock,
  BookOpen,
  Code,
  Cpu,
  Beaker,
  Briefcase,
  Gamepad2,
  Sparkles
} from 'lucide-react';
import { useAuth } from '../../../state/contexts/AuthContext';
import { typingGameApi } from '../services/typingGameApi';
import { QuickBrownFoxGame } from '../components/QuickBrownFoxGame';
import type { TypingWordList } from '../types';

type DifficultyFilter = 'all' | 'easy' | 'medium' | 'hard' | 'expert';
type ThemeFilter = 'all' | 'general' | 'programming' | 'technology' | 'science' | 'business' | 'gaming' | 'creative';

const themeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  general: BookOpen,
  programming: Code,
  technology: Cpu,
  science: Beaker,
  business: Briefcase,
  gaming: Gamepad2,
  creative: Sparkles,
};

const difficultyColors: Record<string, { bg: string; text: string }> = {
  easy: { bg: 'bg-green-100 dark:bg-green-900/30', text: 'text-green-600 dark:text-green-400' },
  medium: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-600 dark:text-yellow-400' },
  hard: { bg: 'bg-orange-100 dark:bg-orange-900/30', text: 'text-orange-600 dark:text-orange-400' },
  expert: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-600 dark:text-red-400' },
};

export const PracticeGamePage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { isAuthenticated, user } = useAuth();

  // State
  const [wordLists, setWordLists] = useState<TypingWordList[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [difficultyFilter, setDifficultyFilter] = useState<DifficultyFilter>('all');
  const [themeFilter, setThemeFilter] = useState<ThemeFilter>('all');
  const [selectedWordList, setSelectedWordList] = useState<TypingWordList | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);

  // Check if we should start with a specific word list
  useEffect(() => {
    const wordListId = searchParams.get('wordList');
    if (wordListId && wordLists.length > 0) {
      const wl = wordLists.find(w => w.id === wordListId);
      if (wl) {
        setSelectedWordList(wl);
        setIsPlaying(true);
      }
    }
  }, [searchParams, wordLists]);

  // Fetch word lists
  useEffect(() => {
    const fetchWordLists = async () => {
      setLoading(true);
      setError(null);
      try {
        const lists = await typingGameApi.getWordLists();
        setWordLists(lists);
      } catch (err) {
        console.error('Failed to fetch word lists:', err);
        setError('Failed to load word lists. Please try again.');
      } finally {
        setLoading(false);
      }
    };

    fetchWordLists();
  }, []);

  // Filter word lists
  const filteredWordLists = wordLists.filter(wl => {
    // Search filter
    if (searchTerm && !wl.name.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !wl.description?.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    // Difficulty filter
    if (difficultyFilter !== 'all' && wl.difficulty !== difficultyFilter) {
      return false;
    }
    // Theme filter
    if (themeFilter !== 'all' && wl.theme !== themeFilter) {
      return false;
    }
    return true;
  });

  // Handle game completion
  const handleGameComplete = useCallback(() => {
    setIsPlaying(false);
    setSelectedWordList(null);
  }, []);

  // If playing, show the game
  if (isPlaying && selectedWordList) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <QuickBrownFoxGame
          wordListId={selectedWordList.id}
          onComplete={handleGameComplete}
          onExit={() => {
            setIsPlaying(false);
            setSelectedWordList(null);
          }}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-6xl mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <button
            onClick={() => navigate('/games/typing')}
            className="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white mb-4"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Typing Games
          </button>

          <div className="flex items-center gap-4 mb-2">
            <div className="w-14 h-14 bg-gradient-to-br from-green-500 to-teal-600 rounded-xl flex items-center justify-center shadow-lg">
              <Target className="w-7 h-7 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Practice Mode
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Select a word list to practice your typing skills
              </p>
            </div>
          </div>
        </motion.div>

        {/* Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 mb-6"
        >
          <div className="flex flex-col md:flex-row gap-4">
            {/* Search */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search word lists..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50"
              />
            </div>

            {/* Difficulty Filter */}
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <select
                value={difficultyFilter}
                onChange={(e) => setDifficultyFilter(e.target.value as DifficultyFilter)}
                className="pl-10 pr-8 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50 appearance-none"
              >
                <option value="all">All Difficulties</option>
                <option value="easy">Easy</option>
                <option value="medium">Medium</option>
                <option value="hard">Hard</option>
                <option value="expert">Expert</option>
              </select>
            </div>

            {/* Theme Filter */}
            <div className="relative">
              <BookOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <select
                value={themeFilter}
                onChange={(e) => setThemeFilter(e.target.value as ThemeFilter)}
                className="pl-10 pr-8 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50 appearance-none"
              >
                <option value="all">All Themes</option>
                <option value="general">General</option>
                <option value="programming">Programming</option>
                <option value="technology">Technology</option>
                <option value="science">Science</option>
                <option value="business">Business</option>
                <option value="gaming">Gaming</option>
                <option value="creative">Creative</option>
              </select>
            </div>
          </div>
        </motion.div>

        {/* Word Lists Grid */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-green-500" />
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <p className="text-red-500 mb-4">{error}</p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600"
            >
              Try Again
            </button>
          </div>
        ) : filteredWordLists.length === 0 ? (
          <div className="text-center py-12">
            <Keyboard className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">
              {searchTerm || difficultyFilter !== 'all' || themeFilter !== 'all'
                ? 'No word lists match your filters'
                : 'No word lists available yet'}
            </p>
          </div>
        ) : (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="grid md:grid-cols-2 lg:grid-cols-3 gap-6"
          >
            {filteredWordLists.map((wordList, idx) => {
              const ThemeIcon = themeIcons[wordList.theme || 'general'] || BookOpen;
              const diffStyle = difficultyColors[wordList.difficulty || 'medium'];
              const isLocked = wordList.unlock_level && (user?.level || 1) < wordList.unlock_level;

              return (
                <motion.div
                  key={wordList.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 + idx * 0.05 }}
                  className={`bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden ${
                    isLocked ? 'opacity-60' : ''
                  }`}
                >
                  {/* Header */}
                  <div className="p-4 border-b border-gray-100 dark:border-gray-700">
                    <div className="flex items-start gap-3">
                      <div className="w-10 h-10 bg-gradient-to-br from-green-500 to-teal-600 rounded-lg flex items-center justify-center flex-shrink-0">
                        <ThemeIcon className="w-5 h-5 text-white" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-semibold text-gray-900 dark:text-white truncate">
                          {wordList.name}
                        </h3>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${diffStyle.bg} ${diffStyle.text}`}>
                            {wordList.difficulty}
                          </span>
                          {wordList.is_featured && (
                            <span className="flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400">
                              <Star className="w-3 h-3" /> Featured
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Body */}
                  <div className="p-4">
                    {wordList.description && (
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-3 line-clamp-2">
                        {wordList.description}
                      </p>
                    )}

                    <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 mb-4">
                      <span>{wordList.word_count || 0} words</span>
                      <span>{wordList.times_played || 0} plays</span>
                    </div>

                    {isLocked ? (
                      <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 py-2">
                        <Lock className="w-4 h-4" />
                        <span className="text-sm">Unlocks at Level {wordList.unlock_level}</span>
                      </div>
                    ) : (
                      <button
                        onClick={() => {
                          setSelectedWordList(wordList);
                          setIsPlaying(true);
                        }}
                        className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-gradient-to-r from-green-500 to-teal-600 text-white rounded-lg font-medium hover:opacity-90 transition-opacity"
                      >
                        <Play className="w-4 h-4" />
                        Practice
                      </button>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </motion.div>
        )}

        {/* Stats Footer */}
        {!loading && filteredWordLists.length > 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="mt-8 text-center text-sm text-gray-500 dark:text-gray-400"
          >
            Showing {filteredWordLists.length} of {wordLists.length} word lists
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default PracticeGamePage;
