// frontend/src/plugins/quizzes/pages/QuizHistoryPage.tsx
/**
 * Quiz History Page
 * Shows user's quiz attempt history with stats and filtering
 */
import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Trophy,
  Clock,
  Target,
  TrendingUp,
  Calendar,
  ChevronRight,
  Award,
  XCircle,
  CheckCircle,
  Filter,
  BarChart2,
} from 'lucide-react';
import { useMyAttempts, useMyQuizStats } from '../hooks/useQuizzes';
import { useAuth } from '../../../state/contexts/AuthContext';
import type { QuizAttempt } from '../types';

type FilterType = 'all' | 'passed' | 'failed';
type SortType = 'date' | 'score' | 'time';

const QuizHistoryPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const { attempts, loading: attemptsLoading } = useMyAttempts();
  const { stats, loading: statsLoading } = useMyQuizStats();

  const [filter, setFilter] = useState<FilterType>('all');
  const [sortBy, setSortBy] = useState<SortType>('date');
  const [sortDesc, setSortDesc] = useState(true);

  // Filter and sort attempts
  const filteredAttempts = useMemo(() => {
    let result = [...attempts];

    // Filter
    if (filter === 'passed') {
      result = result.filter(a => a.passed);
    } else if (filter === 'failed') {
      result = result.filter(a => !a.passed);
    }

    // Sort
    result.sort((a, b) => {
      let comparison = 0;
      switch (sortBy) {
        case 'date':
          comparison = new Date(a.completed_at || a.started_at).getTime() -
                       new Date(b.completed_at || b.started_at).getTime();
          break;
        case 'score':
          comparison = a.percentage - b.percentage;
          break;
        case 'time':
          comparison = (a.time_taken_seconds || 0) - (b.time_taken_seconds || 0);
          break;
      }
      return sortDesc ? -comparison : comparison;
    });

    return result;
  }, [attempts, filter, sortBy, sortDesc]);

  // Format time display
  const formatTime = (seconds: number | undefined) => {
    if (!seconds) return '-';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Format date display
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <Trophy className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
            Sign in to view your quiz history
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Track your progress and see how you've improved over time
          </p>
          <Link
            to="/login"
            className="inline-flex items-center px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition-colors"
          >
            Sign In
          </Link>
        </div>
      </div>
    );
  }

  const loading = attemptsLoading || statsLoading;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-indigo-600 text-white py-12">
        <div className="container mx-auto px-4">
          <div className="flex items-center gap-2 text-purple-200 mb-4">
            <Link to="/quizzes" className="hover:text-white">Quizzes</Link>
            <ChevronRight className="w-4 h-4" />
            <span>History</span>
          </div>
          <h1 className="text-3xl md:text-4xl font-bold mb-2">Quiz History</h1>
          <p className="text-purple-100">
            Track your quiz attempts and monitor your progress
          </p>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        {/* Stats Overview */}
        {stats && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-8"
          >
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
                  <BarChart2 className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.total_attempts}
                  </div>
                  <div className="text-xs text-gray-500">Total Attempts</div>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center">
                  <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.quizzes_passed}
                  </div>
                  <div className="text-xs text-gray-500">Passed</div>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-red-100 dark:bg-red-900/30 rounded-lg flex items-center justify-center">
                  <XCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.quizzes_failed}
                  </div>
                  <div className="text-xs text-gray-500">Failed</div>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                  <Target className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.average_score.toFixed(0)}%
                  </div>
                  <div className="text-xs text-gray-500">Avg Score</div>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg flex items-center justify-center">
                  <Trophy className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.best_score.toFixed(0)}%
                  </div>
                  <div className="text-xs text-gray-500">Best Score</div>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg flex items-center justify-center">
                  <Award className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                </div>
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {stats.total_xp_earned}
                  </div>
                  <div className="text-xs text-gray-500">XP Earned</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Filters and Sort */}
        <div className="flex flex-col sm:flex-row gap-4 mb-6">
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as FilterType)}
              className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Attempts</option>
              <option value="passed">Passed Only</option>
              <option value="failed">Failed Only</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-gray-400" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortType)}
              className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500"
            >
              <option value="date">Sort by Date</option>
              <option value="score">Sort by Score</option>
              <option value="time">Sort by Time</option>
            </select>
            <button
              onClick={() => setSortDesc(!sortDesc)}
              className="px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              {sortDesc ? '↓ Desc' : '↑ Asc'}
            </button>
          </div>

          <div className="flex-1" />

          <Link
            to="/quizzes"
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition-colors text-center"
          >
            Take a Quiz
          </Link>
        </div>

        {/* Attempts List */}
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600" />
          </div>
        ) : filteredAttempts.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-12 bg-white dark:bg-gray-800 rounded-xl shadow-md"
          >
            <Trophy className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
              {filter === 'all' ? 'No quiz attempts yet' : `No ${filter} attempts`}
            </h3>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              {filter === 'all'
                ? 'Start taking quizzes to build your history!'
                : 'Try adjusting your filters'}
            </p>
            <Link
              to="/quizzes"
              className="inline-flex items-center px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition-colors"
            >
              Browse Quizzes
            </Link>
          </motion.div>
        ) : (
          <div className="space-y-4">
            {filteredAttempts.map((attempt, index) => (
              <motion.div
                key={attempt.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="bg-white dark:bg-gray-800 rounded-xl shadow-md p-4 hover:shadow-lg transition-shadow"
              >
                <div className="flex flex-col sm:flex-row sm:items-center gap-4">
                  {/* Status Icon */}
                  <div className={`w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0 ${
                    attempt.passed
                      ? 'bg-green-100 dark:bg-green-900/30'
                      : 'bg-red-100 dark:bg-red-900/30'
                  }`}>
                    {attempt.passed ? (
                      <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
                    ) : (
                      <XCircle className="w-6 h-6 text-red-600 dark:text-red-400" />
                    )}
                  </div>

                  {/* Quiz Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Link
                        to={`/quizzes/${attempt.quiz_id}`}
                        className="font-semibold text-gray-900 dark:text-white hover:text-purple-600 dark:hover:text-purple-400 truncate"
                      >
                        Quiz #{attempt.quiz_id.slice(0, 8)}...
                      </Link>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        attempt.passed
                          ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                          : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                      }`}>
                        {attempt.passed ? 'Passed' : 'Failed'}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {formatDate(attempt.completed_at || attempt.started_at)}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        {formatTime(attempt.time_taken_seconds)}
                      </span>
                      <span>Attempt #{attempt.attempt_number}</span>
                    </div>
                  </div>

                  {/* Score */}
                  <div className="flex items-center gap-6">
                    <div className="text-center">
                      <div className={`text-2xl font-bold ${
                        attempt.passed
                          ? 'text-green-600 dark:text-green-400'
                          : 'text-red-600 dark:text-red-400'
                      }`}>
                        {attempt.percentage.toFixed(0)}%
                      </div>
                      <div className="text-xs text-gray-500">
                        {attempt.score}/{attempt.max_score} pts
                      </div>
                    </div>

                    {attempt.xp_awarded > 0 && (
                      <div className="text-center">
                        <div className="text-xl font-bold text-indigo-600 dark:text-indigo-400">
                          +{attempt.xp_awarded}
                        </div>
                        <div className="text-xs text-gray-500">XP</div>
                      </div>
                    )}

                    <Link
                      to={`/quizzes/${attempt.quiz_id}`}
                      className="p-2 text-gray-400 hover:text-purple-600 dark:hover:text-purple-400"
                    >
                      <ChevronRight className="w-5 h-5" />
                    </Link>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}

        {/* Summary */}
        {filteredAttempts.length > 0 && (
          <div className="mt-6 text-center text-sm text-gray-500 dark:text-gray-400">
            Showing {filteredAttempts.length} of {attempts.length} attempts
          </div>
        )}
      </div>
    </div>
  );
};

export default QuizHistoryPage;
