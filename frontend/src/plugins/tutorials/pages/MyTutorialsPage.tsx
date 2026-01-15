// frontend/src/plugins/tutorials/pages/MyTutorialsPage.tsx
/**
 * My Tutorials Page
 * Shows user's tutorial progress (in-progress and completed)
 */
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMyTutorialProgress } from '../hooks/useTutorials';
import type { TutorialProgressStatus } from '../types';

const MyTutorialsPage: React.FC = () => {
  const [filter, setFilter] = useState<TutorialProgressStatus | undefined>(undefined);
  const { progress, loading, error } = useMyTutorialProgress(filter);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="container mx-auto px-4 py-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            My Tutorials
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Track your learning progress
          </p>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        {/* Filter Tabs */}
        <div className="flex items-center gap-4 mb-8">
          <button
            onClick={() => setFilter(undefined)}
            className={`px-4 py-2 rounded-md font-medium transition-colors ${
              filter === undefined
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
            }`}
          >
            All
          </button>
          <button
            onClick={() => setFilter('in_progress')}
            className={`px-4 py-2 rounded-md font-medium transition-colors ${
              filter === 'in_progress'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
            }`}
          >
            In Progress
          </button>
          <button
            onClick={() => setFilter('completed')}
            className={`px-4 py-2 rounded-md font-medium transition-colors ${
              filter === 'completed'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
            }`}
          >
            Completed
          </button>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-800 dark:text-red-200">
            <p className="font-medium">Error loading progress</p>
            <p className="text-sm mt-1">{error}</p>
          </div>
        )}

        {/* Progress List */}
        {!loading && !error && (
          <>
            {progress.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {progress.map((item) => (
                  <div
                    key={item.id}
                    className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden hover:shadow-xl transition-shadow"
                  >
                    <div className="p-6">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1">
                          <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-2">
                            Tutorial #{item.tutorial_id}
                          </h3>
                          <div className="flex items-center gap-2">
                            {item.status === 'completed' ? (
                              <span className="px-2 py-1 bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 rounded text-xs font-medium">
                                ✓ Completed
                              </span>
                            ) : (
                              <span className="px-2 py-1 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300 rounded text-xs font-medium">
                                In Progress
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Progress Bar */}
                      <div className="mb-4">
                        <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400 mb-2">
                          <span>Progress</span>
                          <span className="font-semibold">{item.progress_percentage || 0}%</span>
                        </div>
                        <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-blue-500 to-purple-600 transition-all"
                            style={{ width: `${item.progress_percentage || 0}%` }}
                          />
                        </div>
                      </div>

                      {/* Stats */}
                      <div className="grid grid-cols-2 gap-4 mb-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <div>
                          <div className="text-xs text-gray-500 dark:text-gray-400">Steps</div>
                          <div className="text-sm font-semibold text-gray-900 dark:text-white">
                            {item.completed_step_ids.length} / {item.total_steps || '?'}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500 dark:text-gray-400">Time Spent</div>
                          <div className="text-sm font-semibold text-gray-900 dark:text-white">
                            {item.time_spent_minutes}m
                          </div>
                        </div>
                      </div>

                      {/* Last Accessed */}
                      <div className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                        Last accessed: {new Date(item.last_accessed_at).toLocaleDateString()}
                      </div>

                      {/* Action Button */}
                      <Link
                        to={`/tutorials/${item.tutorial_id}`}
                        className="block w-full px-4 py-2 bg-blue-600 text-white text-center rounded-md hover:bg-blue-700 transition-colors"
                      >
                        {item.status === 'completed' ? 'Review' : 'Continue'}
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg shadow-md">
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
                    d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
                  />
                </svg>
                <h3 className="text-xl font-medium text-gray-900 dark:text-white mb-2">
                  No tutorials in progress
                </h3>
                <p className="text-gray-600 dark:text-gray-400 mb-6">
                  Start a tutorial to track your learning progress
                </p>
                <Link
                  to="/tutorials"
                  className="inline-block px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                >
                  Browse Tutorials
                </Link>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default MyTutorialsPage;
