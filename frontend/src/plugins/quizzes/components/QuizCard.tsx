// frontend/src/plugins/quizzes/components/QuizCard.tsx
/**
 * Quiz Card Component
 * Displays a quiz summary with stats and actions
 */
import React from 'react';
import { Link } from 'react-router-dom';
import type { QuizSummary, QuizDifficulty } from '../types';

interface QuizCardProps {
  quiz: QuizSummary;
}

const difficultyColors: Record<QuizDifficulty, string> = {
  easy: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  hard: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  expert: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

const difficultyLabels: Record<QuizDifficulty, string> = {
  easy: 'Easy',
  medium: 'Medium',
  hard: 'Hard',
  expert: 'Expert',
};

export const QuizCard: React.FC<QuizCardProps> = ({ quiz }) => {
  return (
    <Link
      to={`/quizzes/${quiz.id}`}
      className="block bg-white dark:bg-gray-800 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 overflow-hidden group"
    >
      {/* Header with gradient */}
      <div className="h-3 bg-gradient-to-r from-purple-500 to-indigo-600"></div>

      <div className="p-6">
        {/* Category & Difficulty badges */}
        <div className="flex items-center gap-2 mb-3">
          {quiz.category && (
            <span className="px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
              {quiz.category}
            </span>
          )}
          <span className={`px-2 py-1 text-xs font-medium rounded ${difficultyColors[quiz.difficulty]}`}>
            {difficultyLabels[quiz.difficulty]}
          </span>
          {quiz.is_featured && (
            <span className="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400 rounded">
              Featured
            </span>
          )}
        </div>

        {/* Title */}
        <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-2 group-hover:text-purple-600 dark:group-hover:text-purple-400 transition-colors">
          {quiz.title}
        </h3>

        {/* Description */}
        {quiz.description && (
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4 line-clamp-2">
            {quiz.description}
          </p>
        )}

        {/* Stats row */}
        <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400 mb-4">
          <div className="flex items-center gap-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{quiz.question_count} questions</span>
          </div>

          {quiz.time_limit_minutes && (
            <div className="flex items-center gap-1">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>{quiz.time_limit_minutes} min</span>
            </div>
          )}

          <div className="flex items-center gap-1">
            <svg className="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <span>{quiz.xp_reward} XP</span>
          </div>
        </div>

        {/* Performance stats */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
          <div className="text-sm">
            <span className="text-gray-500 dark:text-gray-400">Pass rate: </span>
            <span className={`font-medium ${
              quiz.pass_rate >= 70 ? 'text-green-600 dark:text-green-400' :
              quiz.pass_rate >= 40 ? 'text-yellow-600 dark:text-yellow-400' :
              'text-red-600 dark:text-red-400'
            }`}>
              {quiz.pass_rate.toFixed(0)}%
            </span>
          </div>

          <div className="text-sm text-gray-500 dark:text-gray-400">
            {quiz.total_attempts} attempt{quiz.total_attempts !== 1 ? 's' : ''}
          </div>
        </div>

        {/* Passing score indicator */}
        <div className="mt-3 text-xs text-gray-500 dark:text-gray-400">
          Passing score: {quiz.passing_score}%
        </div>
      </div>
    </Link>
  );
};

export default QuizCard;
