// frontend/src/plugins/quizzes/pages/QuizzesPage.tsx
/**
 * Quizzes Browse Page
 * Main page for browsing and searching quizzes
 */
import React, { useState, useMemo } from 'react';
import { QuizCard } from '../components/QuizCard';
import { useQuizzes, useFeaturedQuizzes, useMyQuizStats } from '../hooks/useQuizzes';
import { useAuth } from '../../../state/contexts/AuthContext';
import type { QuizDifficulty } from '../types';

const QuizzesPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedDifficulty, setSelectedDifficulty] = useState<QuizDifficulty | ''>('');

  const { quizzes: featuredQuizzes } = useFeaturedQuizzes(3);
  const { quizzes, loading, error } = useQuizzes({
    category: selectedCategory || undefined,
    difficulty: selectedDifficulty || undefined,
  });
  const { stats } = useMyQuizStats();
  const [hidePassed, setHidePassed] = useState(false);

  // Derive set of quiz IDs the user has passed
  const passedQuizIds = useMemo(() => {
    if (!stats?.recent_attempts) return new Set<string>();
    return new Set(
      stats.recent_attempts.filter(a => a.passed).map(a => a.quiz_id)
    );
  }, [stats]);

  // Filter quizzes based on hidePassed
  const displayQuizzes = hidePassed ? quizzes.filter(q => !passedQuizIds.has(q.id)) : quizzes;
  const displayFeatured = hidePassed ? featuredQuizzes.filter(q => !passedQuizIds.has(q.id)) : featuredQuizzes;

  // Extract unique categories from quizzes
  const categories = Array.from(new Set(quizzes.map(q => q.category).filter(Boolean)));

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-indigo-600 text-white py-8 sm:py-16">
        <div className="container mx-auto px-4">
          <h1 className="text-2xl sm:text-4xl md:text-5xl font-bold mb-2 sm:mb-4">Quizzes</h1>
          <p className="text-sm sm:text-xl text-purple-100 mb-4 sm:mb-8">
            Test your knowledge and earn XP with interactive quizzes
          </p>

          {/* User Stats (if logged in) */}
          {isAuthenticated && stats && (
            <div className="flex flex-wrap gap-3 sm:gap-6 mt-4 sm:mt-6">
              <div className="bg-white/10 backdrop-blur-sm rounded-lg px-3 sm:px-4 py-2 sm:py-3">
                <div className="text-lg sm:text-2xl font-bold">{stats.quizzes_passed}</div>
                <div className="text-xs sm:text-sm text-purple-200">Passed</div>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg px-3 sm:px-4 py-2 sm:py-3">
                <div className="text-lg sm:text-2xl font-bold">{stats.average_score.toFixed(0)}%</div>
                <div className="text-xs sm:text-sm text-purple-200">Avg Score</div>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg px-3 sm:px-4 py-2 sm:py-3">
                <div className="text-lg sm:text-2xl font-bold">{stats.total_xp_earned}</div>
                <div className="text-xs sm:text-sm text-purple-200">XP Earned</div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="container mx-auto px-4 py-6 sm:py-8">
        {/* Featured Quizzes */}
        {displayFeatured.length > 0 && !selectedCategory && !selectedDifficulty && (
          <div className="mb-8 sm:mb-12">
            <h2 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white mb-4 sm:mb-6">
              Featured Quizzes
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              {displayFeatured.map((quiz) => (
                <QuizCard key={quiz.id} quiz={quiz} />
              ))}
            </div>
          </div>
        )}

        {/* Mobile Inline Filters */}
        <div className="lg:hidden mb-6">
          <div className="flex gap-2 overflow-x-auto pb-2 no-scrollbar">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="flex-shrink-0 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
            >
              <option value="">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
            <select
              value={selectedDifficulty}
              onChange={(e) => setSelectedDifficulty(e.target.value as QuizDifficulty | '')}
              className="flex-shrink-0 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
            >
              <option value="">All Levels</option>
              <option value="easy">Easy</option>
              <option value="medium">Medium</option>
              <option value="hard">Hard</option>
              <option value="expert">Expert</option>
            </select>
            {(selectedCategory || selectedDifficulty) && (
              <button
                onClick={() => { setSelectedCategory(''); setSelectedDifficulty(''); }}
                className="flex-shrink-0 px-3 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg text-sm hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
              >
                Clear
              </button>
            )}
            {isAuthenticated && (
              <label className="flex items-center gap-2 cursor-pointer select-none whitespace-nowrap flex-shrink-0">
                <input
                  type="checkbox"
                  checked={hidePassed}
                  onChange={(e) => setHidePassed(e.target.checked)}
                  className="w-4 h-4 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Hide passed</span>
              </label>
            )}
          </div>
        </div>

        <div className="flex flex-col lg:flex-row gap-8">
          {/* Filters Sidebar - hidden on mobile */}
          <aside className="hidden lg:block lg:w-64 flex-shrink-0">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 sticky top-4">
              <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">
                Filters
              </h3>

              {/* Category Filter */}
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Category
                </label>
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
                >
                  <option value="">All Categories</option>
                  {categories.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat}
                    </option>
                  ))}
                </select>
              </div>

              {/* Difficulty Filter */}
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Difficulty
                </label>
                <select
                  value={selectedDifficulty}
                  onChange={(e) => setSelectedDifficulty(e.target.value as QuizDifficulty | '')}
                  className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
                >
                  <option value="">All Levels</option>
                  <option value="easy">Easy</option>
                  <option value="medium">Medium</option>
                  <option value="hard">Hard</option>
                  <option value="expert">Expert</option>
                </select>
              </div>

              {/* Clear Filters */}
              {(selectedCategory || selectedDifficulty) && (
                <button
                  onClick={() => {
                    setSelectedCategory('');
                    setSelectedDifficulty('');
                  }}
                  className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                >
                  Clear Filters
                </button>
              )}

              {/* Hide passed toggle */}
              {isAuthenticated && (
                <label className="flex items-center gap-2 cursor-pointer select-none mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <input
                    type="checkbox"
                    checked={hidePassed}
                    onChange={(e) => setHidePassed(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Hide passed quizzes</span>
                </label>
              )}
            </div>
          </aside>

          {/* Main Content */}
          <main className="flex-1">
            {/* Results Header */}
            <div className="flex items-center justify-between mb-4 sm:mb-6">
              <h2 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">
                {selectedCategory || selectedDifficulty ? 'Filtered Quizzes' : 'All Quizzes'}
              </h2>
              <span className="text-sm sm:text-base text-gray-600 dark:text-gray-400">
                {displayQuizzes.length} quiz{displayQuizzes.length !== 1 ? 'zes' : ''}
              </span>
            </div>

            {/* Loading State */}
            {loading && (
              <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600"></div>
              </div>
            )}

            {/* Error State */}
            {error && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-800 dark:text-red-200">
                <p className="font-medium">Error loading quizzes</p>
                <p className="text-sm mt-1">{error}</p>
              </div>
            )}

            {/* Quiz Grid */}
            {!loading && !error && (
              <>
                {displayQuizzes.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6">
                    {displayQuizzes.map((quiz) => (
                      <QuizCard key={quiz.id} quiz={quiz} />
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <svg
                      className="mx-auto h-24 w-24 text-gray-400 dark:text-gray-600 mb-4"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <h3 className="text-xl font-medium text-gray-900 dark:text-white mb-2">
                      No quizzes found
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Try adjusting your filters or check back later
                    </p>
                  </div>
                )}
              </>
            )}
          </main>
        </div>
      </div>
    </div>
  );
};

export default QuizzesPage;
