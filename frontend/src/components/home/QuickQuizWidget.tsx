// src/components/home/QuickQuizWidget.tsx
/**
 * Quick Quiz Widget - Homepage component showcasing featured quizzes
 * Displays quiz cards with difficulty, question count, and XP rewards
 */

import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  HelpCircle,
  Clock,
  Star,
  Trophy,
  ChevronRight,
  Loader2,
  Sparkles,
  Target,
} from 'lucide-react';
import { useFeaturedQuizzes } from '../../plugins/quizzes/hooks/useQuizzes';
import type { QuizSummary, QuizDifficulty } from '../../plugins/quizzes/types';

const DIFFICULTY_CONFIG: Record<
  QuizDifficulty,
  { label: string; color: string; icon: string }
> = {
  easy: {
    label: 'Easy',
    color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    icon: '1',
  },
  medium: {
    label: 'Medium',
    color: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
    icon: '2',
  },
  hard: {
    label: 'Hard',
    color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
    icon: '3',
  },
  expert: {
    label: 'Expert',
    color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    icon: '4',
  },
};

export const QuickQuizWidget: React.FC = () => {
  const { quizzes, loading } = useFeaturedQuizzes(4);

  if (loading) {
    return (
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
        </div>
      </section>
    );
  }

  if (quizzes.length === 0) {
    return null; // Hide if no quizzes
  }

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <HelpCircle className="w-7 h-7 text-purple-600 dark:text-purple-400" />
            <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
              Test Your Knowledge
            </h2>
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Quick quizzes to practice what you've learned
          </p>
        </div>

        <Link
          to="/quizzes"
          className="hidden sm:flex items-center gap-2 text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 font-medium"
        >
          View all quizzes
          <ChevronRight className="w-5 h-5" />
        </Link>
      </div>

      {/* Quiz Cards Grid */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {quizzes.map((quiz, index) => (
          <QuizCard key={quiz.id} quiz={quiz} index={index} />
        ))}
      </div>

      {/* Mobile link */}
      <div className="mt-6 sm:hidden text-center">
        <Link
          to="/quizzes"
          className="inline-flex items-center gap-2 text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 font-medium"
        >
          View all quizzes
          <ChevronRight className="w-5 h-5" />
        </Link>
      </div>
    </section>
  );
};

// Individual quiz card
interface QuizCardProps {
  quiz: QuizSummary;
  index: number;
}

const QuizCard: React.FC<QuizCardProps> = ({ quiz, index }) => {
  const difficultyConfig = DIFFICULTY_CONFIG[quiz.difficulty];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.1 }}
    >
      <Link
        to={`/quizzes/${quiz.id}`}
        className="group block bg-white dark:bg-gray-800 rounded-xl shadow-md hover:shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden transition-all duration-300"
      >
        {/* Card Header with gradient */}
        <div className="relative h-24 bg-gradient-to-br from-purple-500 via-indigo-500 to-blue-600 p-4">
          {/* Difficulty badge */}
          <span
            className={`absolute top-3 right-3 px-2 py-0.5 text-xs font-medium rounded-full ${difficultyConfig.color}`}
          >
            {difficultyConfig.label}
          </span>

          {/* Question icon */}
          <div className="absolute -bottom-6 left-4 p-3 bg-white dark:bg-gray-700 rounded-xl shadow-lg">
            <Target className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>

          {/* Featured badge */}
          {quiz.is_featured && (
            <div className="absolute top-3 left-3">
              <Star className="w-5 h-5 text-yellow-300 fill-yellow-300" />
            </div>
          )}
        </div>

        {/* Card Content */}
        <div className="pt-8 p-4">
          {/* Category */}
          {quiz.category && (
            <span className="text-xs font-medium text-purple-600 dark:text-purple-400 uppercase tracking-wide">
              {quiz.category}
            </span>
          )}

          {/* Title */}
          <h3 className="font-semibold text-gray-900 dark:text-white mt-1 mb-2 line-clamp-2 group-hover:text-purple-600 dark:group-hover:text-purple-400 transition-colors">
            {quiz.title}
          </h3>

          {/* Stats Row */}
          <div className="flex items-center gap-3 text-sm text-gray-500 dark:text-gray-400 mb-3">
            <span className="flex items-center gap-1">
              <HelpCircle className="w-4 h-4" />
              {quiz.question_count} Qs
            </span>
            {quiz.time_limit_minutes && (
              <span className="flex items-center gap-1">
                <Clock className="w-4 h-4" />
                {quiz.time_limit_minutes}m
              </span>
            )}
          </div>

          {/* XP Reward & Pass Rate */}
          <div className="flex items-center justify-between pt-3 border-t border-gray-100 dark:border-gray-700">
            <div className="flex items-center gap-1 text-sm">
              <Sparkles className="w-4 h-4 text-yellow-500" />
              <span className="font-medium text-gray-700 dark:text-gray-300">
                {quiz.xp_reward} XP
              </span>
            </div>

            {quiz.total_attempts > 0 && quiz.pass_rate != null && (
              <div className="flex items-center gap-1 text-sm">
                <Trophy className="w-4 h-4 text-green-500" />
                <span className="text-gray-600 dark:text-gray-400">
                  {quiz.pass_rate.toFixed(0)}% pass
                </span>
              </div>
            )}
          </div>
        </div>
      </Link>
    </motion.div>
  );
};

export default QuickQuizWidget;
