// frontend/src/plugins/tutorials/pages/admin/TutorialAnalyticsPage.tsx
/**
 * Tutorial Analytics Dashboard - Admin Only
 * Shows detailed analytics for all tutorials with performance metrics
 */
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import * as tutorialApi from '../../services/tutorialApi';
import type { TutorialListItem, TutorialAnalytics } from '../../types';

interface TutorialWithAnalytics extends TutorialListItem {
  analytics?: TutorialAnalytics;
  loadingAnalytics?: boolean;
}

export const TutorialAnalyticsPage: React.FC = () => {
  const navigate = useNavigate();
  const [tutorials, setTutorials] = useState<TutorialWithAnalytics[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<'views' | 'completions' | 'completion_rate'>('views');
  const [selectedTutorial, setSelectedTutorial] = useState<TutorialWithAnalytics | null>(null);

  useEffect(() => {
    fetchTutorials();
  }, []);

  const fetchTutorials = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await tutorialApi.getAllTutorialsAdmin({ limit: 100 });
      setTutorials(data);
    } catch (err: any) {
      console.error('Error fetching tutorials:', err);
      setError(err.message || 'Failed to load tutorials');
    } finally {
      setLoading(false);
    }
  };

  const loadAnalytics = async (tutorialId: number) => {
    setTutorials((prev) =>
      prev.map((t) =>
        t.id === tutorialId ? { ...t, loadingAnalytics: true } : t
      )
    );

    try {
      const analytics = await tutorialApi.getTutorialAnalytics(tutorialId);
      setTutorials((prev) =>
        prev.map((t) =>
          t.id === tutorialId
            ? { ...t, analytics, loadingAnalytics: false }
            : t
        )
      );
    } catch (err: any) {
      console.error('Error loading analytics:', err);
      setTutorials((prev) =>
        prev.map((t) =>
          t.id === tutorialId ? { ...t, loadingAnalytics: false } : t
        )
      );
    }
  };

  const viewDetailedAnalytics = (tutorial: TutorialWithAnalytics) => {
    if (!tutorial.analytics && !tutorial.loadingAnalytics) {
      loadAnalytics(tutorial.id);
    }
    setSelectedTutorial(tutorial);
  };

  const closeDetailedView = () => {
    setSelectedTutorial(null);
  };

  const sortedTutorials = [...tutorials].sort((a, b) => {
    switch (sortBy) {
      case 'views':
        return b.view_count - a.view_count;
      case 'completions':
        return b.completion_count - a.completion_count;
      case 'completion_rate':
        const rateA = a.analytics?.completion_rate || 0;
        const rateB = b.analytics?.completion_rate || 0;
        return rateB - rateA;
      default:
        return 0;
    }
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 max-w-7xl mx-auto">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <p className="text-red-600 dark:text-red-400">{error}</p>
          <button
            onClick={fetchTutorials}
            className="mt-2 text-sm text-red-700 dark:text-red-300 hover:underline"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Tutorial Analytics
          </h1>
          <p className="mt-1 text-gray-600 dark:text-gray-400">
            Performance metrics and insights for all tutorials
          </p>
        </div>
        <button
          onClick={() => navigate('/admin/tutorials')}
          className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
        >
          Back to Management
        </button>
      </div>

      {/* Global Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Total Tutorials
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {tutorials.length}
              </p>
            </div>
            <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-full">
              <svg className="w-8 h-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Total Views
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {tutorials.reduce((sum, t) => sum + t.view_count, 0).toLocaleString()}
              </p>
            </div>
            <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-full">
              <svg className="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-purple-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Total Completions
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {tutorials.reduce((sum, t) => sum + t.completion_count, 0).toLocaleString()}
              </p>
            </div>
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-full">
              <svg className="w-8 h-8 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-orange-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Published
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {tutorials.filter(t => t.is_published).length}
              </p>
            </div>
            <div className="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-full">
              <svg className="w-8 h-8 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Sort Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4">
        <div className="flex items-center gap-4">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
            Sort by:
          </span>
          <button
            onClick={() => setSortBy('views')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              sortBy === 'views'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
            }`}
          >
            Views
          </button>
          <button
            onClick={() => setSortBy('completions')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              sortBy === 'completions'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
            }`}
          >
            Completions
          </button>
          <button
            onClick={() => setSortBy('completion_rate')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              sortBy === 'completion_rate'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
            }`}
          >
            Completion Rate
          </button>
        </div>
      </div>

      {/* Tutorials Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Tutorial
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Difficulty
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Views
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Completions
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {sortedTutorials.map((tutorial) => (
                <tr
                  key={tutorial.id}
                  className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-start gap-3">
                      {tutorial.thumbnail_url && (
                        <img
                          src={tutorial.thumbnail_url}
                          alt={tutorial.title}
                          className="w-16 h-12 object-cover rounded"
                        />
                      )}
                      <div className="flex-1">
                        <p className="font-medium text-gray-900 dark:text-white">
                          {tutorial.title}
                        </p>
                        <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-1">
                          {tutorial.description}
                        </p>
                        {tutorial.category && (
                          <span className="inline-block mt-1 px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                            {tutorial.category.name}
                          </span>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-center">
                    <span
                      className={`inline-block px-2 py-1 text-xs font-medium rounded-full ${
                        tutorial.difficulty === 'beginner'
                          ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                          : tutorial.difficulty === 'intermediate'
                          ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300'
                          : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
                      }`}
                    >
                      {tutorial.difficulty}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-center text-gray-900 dark:text-white font-medium">
                    {tutorial.view_count.toLocaleString()}
                  </td>
                  <td className="px-6 py-4 text-center text-gray-900 dark:text-white font-medium">
                    {tutorial.completion_count.toLocaleString()}
                  </td>
                  <td className="px-6 py-4 text-center">
                    {tutorial.is_published ? (
                      <span className="inline-block px-2 py-1 text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 rounded-full">
                        Published
                      </span>
                    ) : (
                      <span className="inline-block px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 rounded-full">
                        Draft
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-center">
                    <button
                      onClick={() => viewDetailedAnalytics(tutorial)}
                      className="px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded transition-colors"
                    >
                      View Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {tutorials.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-600 dark:text-gray-400">
              No tutorials found. Create your first tutorial to see analytics.
            </p>
          </div>
        )}
      </div>

      {/* Detailed Analytics Modal */}
      {selectedTutorial && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6 flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {selectedTutorial.title}
                </h2>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Detailed Analytics
                </p>
              </div>
              <button
                onClick={closeDetailedView}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                <svg className="w-6 h-6 text-gray-600 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-6">
              {selectedTutorial.loadingAnalytics ? (
                <div className="flex items-center justify-center py-12">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
                </div>
              ) : selectedTutorial.analytics ? (
                <>
                  {/* Analytics Stats Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400">Total Views</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {selectedTutorial.analytics.total_views.toLocaleString()}
                      </p>
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400">Total Starts</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {selectedTutorial.analytics.total_starts.toLocaleString()}
                      </p>
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400">Total Completions</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {selectedTutorial.analytics.total_completions.toLocaleString()}
                      </p>
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400">Completion Rate</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {(selectedTutorial.analytics.completion_rate * 100).toFixed(1)}%
                      </p>
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400">Avg Time</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {selectedTutorial.analytics.average_time_minutes
                          ? `${selectedTutorial.analytics.average_time_minutes.toFixed(0)}m`
                          : 'N/A'}
                      </p>
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                      <p className="text-sm text-gray-600 dark:text-gray-400">XP Reward</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                        {selectedTutorial.xp_reward}
                      </p>
                    </div>
                  </div>

                  {/* Step Dropoff Rates */}
                  {selectedTutorial.analytics.step_dropoff_rates.length > 0 && (
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        Step-by-Step Analysis
                      </h3>
                      <div className="space-y-3">
                        {selectedTutorial.analytics.step_dropoff_rates.map((step) => (
                          <div
                            key={step.step_id}
                            className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4"
                          >
                            <div className="flex items-center justify-between mb-2">
                              <p className="font-medium text-gray-900 dark:text-white">
                                {step.step_title}
                              </p>
                              <span className="text-sm text-gray-600 dark:text-gray-400">
                                {step.completions} completions
                              </span>
                            </div>
                            <div className="flex items-center gap-3">
                              <div className="flex-1 bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                                <div
                                  className="bg-blue-600 h-2 rounded-full transition-all"
                                  style={{
                                    width: `${Math.max(0, 100 - step.dropoff_rate * 100)}%`,
                                  }}
                                ></div>
                              </div>
                              <span className="text-sm font-medium text-gray-900 dark:text-white">
                                {(step.dropoff_rate * 100).toFixed(1)}% dropoff
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-center py-12">
                  <p className="text-gray-600 dark:text-gray-400">
                    Failed to load analytics. Please try again.
                  </p>
                  <button
                    onClick={() => loadAnalytics(selectedTutorial.id)}
                    className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  >
                    Retry
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TutorialAnalyticsPage;
