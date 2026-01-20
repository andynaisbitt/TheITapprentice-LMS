// frontend/src/plugins/quizzes/pages/admin/QuizManagerPage.tsx
/**
 * Quiz Manager Admin Page
 * CRUD interface for managing quizzes
 */
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAdminQuizzes, deleteQuiz, updateQuiz } from '../../hooks/useQuizzes';
import type { QuizAdminResponse, QuizStatus, QuizDifficulty } from '../../types';

const statusColors: Record<QuizStatus, string> = {
  draft: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  published: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  archived: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

const difficultyColors: Record<QuizDifficulty, string> = {
  easy: 'text-green-600 dark:text-green-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  hard: 'text-orange-600 dark:text-orange-400',
  expert: 'text-red-600 dark:text-red-400',
};

const QuizManagerPage: React.FC = () => {
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');

  const { quizzes, loading, error, refetch } = useAdminQuizzes({
    status: statusFilter || undefined,
    search: searchTerm || undefined,
  });

  const handleDelete = async (quiz: QuizAdminResponse) => {
    if (!confirm(`Are you sure you want to delete "${quiz.title}"?`)) return;

    try {
      await deleteQuiz(quiz.id);
      refetch();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete quiz');
    }
  };

  const handleStatusChange = async (quiz: QuizAdminResponse, newStatus: QuizStatus) => {
    try {
      await updateQuiz(quiz.id, { status: newStatus });
      refetch();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update quiz status');
    }
  };

  const handleToggleFeatured = async (quiz: QuizAdminResponse) => {
    try {
      await updateQuiz(quiz.id, { is_featured: !quiz.is_featured });
      refetch();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update quiz');
    }
  };

  // Stats
  const stats = {
    total: quizzes.length,
    published: quizzes.filter(q => q.status === 'published').length,
    draft: quizzes.filter(q => q.status === 'draft').length,
    totalAttempts: quizzes.reduce((sum, q) => sum + q.total_attempts, 0),
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Quiz Manager</h1>
          <p className="text-gray-600 dark:text-gray-400">Create and manage quizzes</p>
        </div>
        <Link
          to="/admin/quizzes/new"
          className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors flex items-center gap-2"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Quiz
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Total Quizzes</div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.published}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Published</div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-gray-600 dark:text-gray-400">{stats.draft}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Drafts</div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">{stats.totalAttempts}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Total Attempts</div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px]">
            <input
              type="text"
              placeholder="Search quizzes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
          >
            <option value="">All Status</option>
            <option value="draft">Draft</option>
            <option value="published">Published</option>
            <option value="archived">Archived</option>
          </select>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600"></div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-800 dark:text-red-200 mb-6">
          {error}
        </div>
      )}

      {/* Quiz Table */}
      {!loading && !error && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Quiz
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Category
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Questions
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Stats
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {quizzes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    No quizzes found. Create your first quiz!
                  </td>
                </tr>
              ) : (
                quizzes.map((quiz) => (
                  <tr key={quiz.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-gray-900 dark:text-white">
                              {quiz.title}
                            </span>
                            {quiz.is_featured && (
                              <span className="text-yellow-500" title="Featured">
                                ★
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            ID: {quiz.id}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <div className="text-sm text-gray-900 dark:text-white">
                          {quiz.category || '-'}
                        </div>
                        <div className={`text-xs capitalize ${difficultyColors[quiz.difficulty]}`}>
                          {quiz.difficulty}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm">
                        <div className="font-medium text-gray-900 dark:text-white">
                          {quiz.question_count} questions
                        </div>
                        <div className="text-gray-500 dark:text-gray-400">
                          {quiz.xp_reward} XP
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <select
                        value={quiz.status}
                        onChange={(e) => handleStatusChange(quiz, e.target.value as QuizStatus)}
                        className={`px-2 py-1 text-xs font-medium rounded ${statusColors[quiz.status]} border-0 focus:ring-2 focus:ring-purple-500`}
                      >
                        <option value="draft">Draft</option>
                        <option value="published">Published</option>
                        <option value="archived">Archived</option>
                      </select>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm">
                        <div className="text-gray-900 dark:text-white">
                          {quiz.total_attempts} attempts
                        </div>
                        <div className="text-gray-500 dark:text-gray-400">
                          {quiz.pass_rate.toFixed(0)}% pass rate
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleToggleFeatured(quiz)}
                          className={`p-2 rounded-lg ${
                            quiz.is_featured
                              ? 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30'
                              : 'text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
                          }`}
                          title={quiz.is_featured ? 'Remove from featured' : 'Add to featured'}
                        >
                          <svg className="w-5 h-5" fill={quiz.is_featured ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                          </svg>
                        </button>
                        <Link
                          to={`/admin/quizzes/${quiz.id}/edit`}
                          className="p-2 text-blue-600 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg"
                          title="Edit"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </Link>
                        <a
                          href={`/quizzes/${quiz.id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-2 text-green-600 hover:bg-green-100 dark:hover:bg-green-900/30 rounded-lg"
                          title="Preview"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                          </svg>
                        </a>
                        <button
                          onClick={() => handleDelete(quiz)}
                          className="p-2 text-red-600 hover:bg-red-100 dark:hover:bg-red-900/30 rounded-lg"
                          title="Delete"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default QuizManagerPage;
