// frontend/src/plugins/quizzes/pages/QuizPlayerPage.tsx
/**
 * Quiz Player Page
 * Interactive quiz-taking interface with timer, progress, and results
 * Includes registration prompt for unauthenticated users
 */
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuiz, useQuizzes, useQuizLeaderboard, useMyAttempts, startQuizAttempt, submitQuizAttempt } from '../hooks/useQuizzes';
import { useAuth } from '../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../hooks/useRegistrationPrompt';
import type { QuizQuestion, QuizAttemptResult, QuestionResult, QuizDifficulty } from '../types';

type QuizPhase = 'overview' | 'playing' | 'results';

const difficultyColors: Record<QuizDifficulty, string> = {
  easy: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  hard: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  expert: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

const QuizPlayerPage: React.FC = () => {
  const { quizId } = useParams<{ quizId: string }>();
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  // Registration prompt for unauthenticated users
  const {
    isPromptOpen,
    closePrompt,
    handleSkip: handlePromptSkip,
    checkAuthAndProceed,
  } = useRegistrationPrompt({
    context: 'quiz',
    onSkip: () => {
      // User chose to skip - they can view quiz but not take it
    },
  });

  const { quiz, loading, error } = useQuiz(quizId);
  const { leaderboard } = useQuizLeaderboard(quizId);
  const { attempts, refetch: refetchAttempts } = useMyAttempts(quizId);

  // Fetch quizzes for "What's Next?" suggestions on results screen
  const { quizzes: allQuizzes } = useQuizzes({ limit: 10 });
  const suggestedQuizzes = useMemo(() => {
    if (!quiz || !allQuizzes.length) return [];
    return allQuizzes
      .filter(q => q.id !== quiz.id)
      .sort((a, b) => {
        // Prioritise same category, then same difficulty
        const aScore = (a.category === quiz.category ? 2 : 0) + (a.difficulty === quiz.difficulty ? 1 : 0);
        const bScore = (b.category === quiz.category ? 2 : 0) + (b.difficulty === quiz.difficulty ? 1 : 0);
        return bScore - aScore;
      })
      .slice(0, 3);
  }, [quiz, allQuizzes]);

  const [phase, setPhase] = useState<QuizPhase>('overview');
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [answers, setAnswers] = useState<Record<string, any>>({});
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const [result, setResult] = useState<QuizAttemptResult | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Timer effect
  useEffect(() => {
    if (phase !== 'playing' || timeRemaining === null || timeRemaining <= 0) return;

    const timer = setInterval(() => {
      setTimeRemaining(prev => {
        if (prev === null || prev <= 0) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [phase, timeRemaining]);

  // Auto-submit when time runs out
  useEffect(() => {
    if (timeRemaining === 0 && phase === 'playing') {
      handleSubmit();
    }
  }, [timeRemaining, phase]);

  const startQuiz = useCallback(async () => {
    if (!quiz) return;

    try {
      await startQuizAttempt(quiz.id);
      setPhase('playing');
      setCurrentQuestion(0);
      setAnswers({});
      if (quiz.time_limit_minutes) {
        setTimeRemaining(quiz.time_limit_minutes * 60);
      }
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to start quiz');
    }
  }, [quiz]);

  const handleAnswerChange = useCallback((questionId: number, value: any) => {
    setAnswers(prev => ({
      ...prev,
      [questionId.toString()]: value,
    }));
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!quiz || submitting) return;

    setSubmitting(true);
    try {
      const result = await submitQuizAttempt(quiz.id, { answers });
      setResult(result);
      setPhase('results');
      refetchAttempts();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to submit quiz');
    } finally {
      setSubmitting(false);
    }
  }, [quiz, answers, submitting, refetchAttempts]);

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600"></div>
      </div>
    );
  }

  if (error || !quiz) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Quiz Not Found</h1>
          <Link to="/quizzes" className="text-purple-600 hover:underline">
            Back to Quizzes
          </Link>
        </div>
      </div>
    );
  }

  // Overview Phase
  if (phase === 'overview') {
    const bestAttempt = attempts.find(a => a.is_complete);
    const canAttempt = quiz.max_attempts === 0 || attempts.filter(a => a.is_complete).length < quiz.max_attempts;

    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-4 sm:py-8">
        <div className="container mx-auto px-3 sm:px-4 max-w-4xl">
          {/* Back link */}
          <Link
            to="/quizzes"
            className="inline-flex items-center text-purple-600 dark:text-purple-400 hover:underline mb-4 sm:mb-6 text-sm sm:text-base"
          >
            <svg className="w-4 h-4 mr-1 sm:mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Quizzes
          </Link>

          {/* Quiz Header Card */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden mb-6 sm:mb-8">
            <div className="h-2 bg-gradient-to-r from-purple-500 to-indigo-600"></div>
            <div className="p-4 sm:p-6 lg:p-8">
              <div className="flex flex-wrap gap-2 mb-4">
                {quiz.category && (
                  <span className="px-3 py-1 text-sm font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full">
                    {quiz.category}
                  </span>
                )}
                <span className={`px-3 py-1 text-sm font-medium rounded-full ${difficultyColors[quiz.difficulty]}`}>
                  {quiz.difficulty.charAt(0).toUpperCase() + quiz.difficulty.slice(1)}
                </span>
              </div>

              <h1 className="text-xl sm:text-2xl lg:text-3xl font-bold text-gray-900 dark:text-white mb-3 sm:mb-4">{quiz.title}</h1>
              {quiz.description && (
                <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mb-4 sm:mb-6">{quiz.description}</p>
              )}

              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 mb-4 sm:mb-6">
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 sm:p-4 text-center">
                  <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{quiz.question_count}</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Questions</div>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 sm:p-4 text-center">
                  <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
                    {quiz.time_limit_minutes ? `${quiz.time_limit_minutes}m` : 'None'}
                  </div>
                  <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Time Limit</div>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 sm:p-4 text-center">
                  <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{quiz.passing_score}%</div>
                  <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Pass Score</div>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 sm:p-4 text-center">
                  <div className="text-lg sm:text-2xl font-bold text-purple-600 dark:text-purple-400">{quiz.xp_reward}</div>
                  <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">XP Reward</div>
                </div>
              </div>

              {/* Instructions */}
              {quiz.instructions && (
                <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-purple-800 dark:text-purple-200 mb-2">Instructions</h3>
                  <p className="text-purple-700 dark:text-purple-300 text-sm">{quiz.instructions}</p>
                </div>
              )}

              {/* Previous attempt info */}
              {bestAttempt && (
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 mb-6">
                  <h3 className="font-medium text-gray-900 dark:text-white mb-2">Your Best Attempt</h3>
                  <div className="flex items-center gap-4">
                    <span className={`text-lg font-bold ${bestAttempt.passed ? 'text-green-600' : 'text-red-600'}`}>
                      {bestAttempt.percentage.toFixed(0)}%
                    </span>
                    <span className={`px-2 py-1 text-xs rounded ${bestAttempt.passed ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'}`}>
                      {bestAttempt.passed ? 'PASSED' : 'FAILED'}
                    </span>
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      Attempt #{bestAttempt.attempt_number}
                    </span>
                  </div>
                </div>
              )}

              {/* Start Button */}
              {canAttempt ? (
                <button
                  onClick={startQuiz}
                  className="w-full md:w-auto px-8 py-3 bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-medium rounded-lg hover:from-purple-700 hover:to-indigo-700 transition-all"
                >
                  {bestAttempt ? 'Retry Quiz' : 'Start Quiz'}
                </button>
              ) : (
                isAuthenticated && (
                  <div className="text-center py-4 text-gray-600 dark:text-gray-400">
                    Maximum attempts ({quiz.max_attempts}) reached
                  </div>
                )
              )}

              {!isAuthenticated && (
                <p className="mt-3 text-sm text-gray-500 dark:text-gray-400 text-center">
                  Sign up to save your quiz results and earn XP
                </p>
              )}
            </div>
          </div>

          {/* Leaderboard */}
          {leaderboard && leaderboard.entries.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 sm:p-6">
              <h2 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-4">Leaderboard</h2>
              <div className="space-y-2">
                {leaderboard.entries.slice(0, 5).map((entry) => (
                  <div
                    key={entry.user_id}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <span className={`w-8 h-8 flex items-center justify-center rounded-full font-bold ${
                        entry.rank === 1 ? 'bg-yellow-400 text-yellow-900' :
                        entry.rank === 2 ? 'bg-gray-300 text-gray-700' :
                        entry.rank === 3 ? 'bg-orange-400 text-orange-900' :
                        'bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300'
                      }`}>
                        {entry.rank}
                      </span>
                      <span className="font-medium text-gray-900 dark:text-white">
                        {entry.display_name || entry.username}
                      </span>
                    </div>
                    <span className="font-bold text-purple-600 dark:text-purple-400">
                      {entry.best_score.toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Registration Prompt Modal */}
          <RegistrationPrompt
            isOpen={isPromptOpen}
            onClose={closePrompt}
            onSkip={handlePromptSkip}
            context="quiz"
          />
        </div>
      </div>
    );
  }

  // Playing Phase
  if (phase === 'playing') {
    const question = quiz.questions[currentQuestion];
    const answeredCount = Object.keys(answers).length;
    const progress = ((currentQuestion + 1) / quiz.questions.length) * 100;

    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        {/* Top Bar */}
        <div className="sticky top-0 bg-white dark:bg-gray-800 shadow-md z-10">
          <div className="container mx-auto px-3 sm:px-4 py-2 sm:py-4">
            {/* Mobile: stacked layout */}
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0 flex-1">
                <h1 className="font-bold text-sm sm:text-base text-gray-900 dark:text-white truncate">
                  {quiz.title}
                </h1>
                <span className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">
                  Question {currentQuestion + 1} of {quiz.questions.length}
                </span>
              </div>

              <div className="flex items-center gap-2 sm:gap-4 flex-shrink-0">
                {timeRemaining !== null && (
                  <div className={`flex items-center gap-1 sm:gap-2 px-2 sm:px-3 py-1 rounded-full text-xs sm:text-sm ${
                    timeRemaining < 60 ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                    timeRemaining < 300 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                    'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                  }`}>
                    <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="font-mono font-medium">{formatTime(timeRemaining)}</span>
                  </div>
                )}
                <span className="hidden sm:inline text-sm text-gray-600 dark:text-gray-400">
                  {answeredCount}/{quiz.questions.length} answered
                </span>
                <span className="sm:hidden text-xs text-gray-600 dark:text-gray-400">
                  {answeredCount}/{quiz.questions.length}
                </span>
              </div>
            </div>

            {/* Progress bar */}
            <div className="mt-2 sm:mt-3 h-1.5 sm:h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-purple-500 to-indigo-600 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        </div>

        {/* Question Content */}
        <div className="container mx-auto px-3 sm:px-4 py-4 sm:py-8 max-w-3xl">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 sm:p-6 lg:p-8">
            {/* Question */}
            <div className="mb-4 sm:mb-8">
              <div className="flex items-center gap-2 mb-3 sm:mb-4">
                <span className="px-3 py-1 text-sm font-medium bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded-full">
                  {question.points} point{question.points !== 1 ? 's' : ''}
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                  {question.question_type.replace('_', ' ')}
                </span>
              </div>

              {question.image_url && (
                <img
                  src={question.image_url}
                  alt="Question"
                  className="max-w-full h-auto rounded-lg mb-4"
                />
              )}

              <h2 className="text-xl font-medium text-gray-900 dark:text-white">
                {question.question_html ? (
                  <div dangerouslySetInnerHTML={{ __html: question.question_html }} />
                ) : (
                  question.question_text
                )}
              </h2>
            </div>

            {/* Answer Input */}
            <QuestionInput
              question={question}
              value={answers[question.id.toString()]}
              onChange={(value) => handleAnswerChange(question.id, value)}
            />
          </div>

          {/* Navigation */}
          <div className="fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 p-4 z-20 md:static md:border-0 md:bg-transparent md:dark:bg-transparent md:p-0 md:mt-6">
            <div className="flex items-center justify-between max-w-3xl mx-auto">
              <button
                onClick={() => setCurrentQuestion(prev => Math.max(0, prev - 1))}
                disabled={currentQuestion === 0}
                className="flex-shrink-0 px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>

              <div className="hidden md:flex gap-2">
                {quiz.questions.map((_, idx) => (
                  <button
                    key={idx}
                    onClick={() => setCurrentQuestion(idx)}
                    className={`w-8 h-8 rounded-full text-sm font-medium transition-colors ${
                      idx === currentQuestion
                        ? 'bg-purple-600 text-white'
                        : answers[quiz.questions[idx].id.toString()]
                        ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
                    }`}
                  >
                    {idx + 1}
                  </button>
                ))}
              </div>

              {/* Mobile: show question counter between buttons */}
              <span className="md:hidden text-sm text-gray-500 dark:text-gray-400">
                {currentQuestion + 1} / {quiz.questions.length}
              </span>

              {currentQuestion < quiz.questions.length - 1 ? (
                <button
                  onClick={() => setCurrentQuestion(prev => prev + 1)}
                  className="flex-shrink-0 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                >
                  Next
                </button>
              ) : (
                <button
                  onClick={handleSubmit}
                  disabled={submitting}
                  className="flex-shrink-0 px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
                >
                  {submitting ? 'Submitting...' : 'Submit Quiz'}
                </button>
              )}
            </div>
          </div>
          {/* Spacer for fixed bottom nav on mobile */}
          <div className="h-16 md:hidden"></div>
        </div>
      </div>
    );
  }

  // Results Phase
  if (phase === 'results' && result) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-4 sm:py-8">
        <div className="container mx-auto px-3 sm:px-4 max-w-3xl">
          {/* Result Card */}
          <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden mb-6 sm:mb-8 ${
            result.passed ? 'border-t-4 border-green-500' : 'border-t-4 border-red-500'
          }`}>
            <div className="p-4 sm:p-6 lg:p-8 text-center">
              <div className={`w-16 h-16 sm:w-24 sm:h-24 mx-auto rounded-full flex items-center justify-center mb-4 sm:mb-6 ${
                result.passed ? 'bg-green-100 dark:bg-green-900/30' : 'bg-red-100 dark:bg-red-900/30'
              }`}>
                {result.passed ? (
                  <svg className="w-8 h-8 sm:w-12 sm:h-12 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  <svg className="w-8 h-8 sm:w-12 sm:h-12 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                )}
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white mb-2">
                {result.passed ? 'Congratulations!' : 'Keep Trying!'}
              </h1>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mb-4 sm:mb-6">
                {result.passed ? 'You passed the quiz!' : `You need ${quiz.passing_score}% to pass.`}
              </p>

              <div className="text-3xl sm:text-5xl font-bold mb-4">
                <span className={result.passed ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}>
                  {result.percentage.toFixed(0)}%
                </span>
              </div>

              <div className="flex justify-center gap-4 sm:gap-8 text-gray-600 dark:text-gray-400">
                <div>
                  <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{result.score}/{result.max_score}</div>
                  <div className="text-sm">Points</div>
                </div>
                {result.time_taken_seconds && (
                  <div>
                    <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{formatTime(result.time_taken_seconds)}</div>
                    <div className="text-sm">Time</div>
                  </div>
                )}
                {result.xp_awarded > 0 && (
                  <div>
                    <div className="text-lg sm:text-2xl font-bold text-purple-600 dark:text-purple-400">+{result.xp_awarded}</div>
                    <div className="text-sm">XP Earned</div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Guest Sign-up CTA */}
          {!isAuthenticated && (
            <div className="bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-purple-900/20 dark:to-indigo-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4 sm:p-6 mb-6 sm:mb-8 text-center">
              <h3 className="text-lg font-semibold text-purple-900 dark:text-purple-100 mb-2">
                Want to save your score?
              </h3>
              <p className="text-purple-700 dark:text-purple-300 mb-4 text-sm">
                Sign up to save your results, earn {quiz.xp_reward} XP, track your progress, and compete on the leaderboard.
              </p>
              <div className="flex items-center justify-center gap-3">
                <Link
                  to="/register"
                  className="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg font-medium hover:from-purple-700 hover:to-indigo-700 transition-all"
                >
                  Create Free Account
                </Link>
                <Link
                  to="/login"
                  className="px-5 py-2.5 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium hover:bg-gray-300 dark:hover:bg-gray-600 transition-all"
                >
                  Sign In
                </Link>
              </div>
            </div>
          )}

          {/* Question Review */}
          {result.show_answers && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 sm:p-6 mb-6 sm:mb-8">
              <h2 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-4 sm:mb-6">Question Review</h2>
              <div className="space-y-6">
                {result.question_results.map((qr, idx) => {
                  const question = quiz.questions.find(q => q.id === qr.question_id);
                  if (!question) return null;

                  return (
                    <div key={qr.question_id} className={`p-4 rounded-lg ${
                      qr.correct ? 'bg-green-50 dark:bg-green-900/20' : 'bg-red-50 dark:bg-red-900/20'
                    }`}>
                      <div className="flex items-start gap-3">
                        <span className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center ${
                          qr.correct ? 'bg-green-500 text-white' : 'bg-red-500 text-white'
                        }`}>
                          {qr.correct ? '✓' : '✗'}
                        </span>
                        <div className="flex-1">
                          <p className="font-medium text-gray-900 dark:text-white mb-2">
                            {idx + 1}. {question.question_text}
                          </p>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">
                            Your answer: <span className="font-medium">{JSON.stringify(qr.user_answer)}</span>
                          </p>
                          {!qr.correct && qr.correct_answer && (
                            <p className="text-sm text-green-600 dark:text-green-400">
                              Correct answer: <span className="font-medium">{JSON.stringify(qr.correct_answer)}</span>
                            </p>
                          )}
                          {qr.explanation && (
                            <p className="text-sm text-gray-600 dark:text-gray-400 mt-2 italic">
                              {qr.explanation}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 sm:gap-4 justify-center">
            <button
              onClick={() => {
                setPhase('overview');
                setResult(null);
                setAnswers({});
              }}
              className="px-4 sm:px-6 py-2.5 sm:py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 text-sm sm:text-base"
            >
              Try Again
            </button>
            <Link
              to="/quizzes"
              className="px-4 sm:px-6 py-2.5 sm:py-3 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 text-sm sm:text-base"
            >
              Back to Quizzes
            </Link>
          </div>

          {/* What's Next? Suggestions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 sm:p-6 mt-6 sm:mt-8">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">What's Next?</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">

              {/* Suggested Quizzes */}
              {suggestedQuizzes.map((sq) => (
                <Link
                  key={sq.id}
                  to={`/quizzes/${sq.id}`}
                  onClick={() => {
                    setPhase('overview');
                    setResult(null);
                    setAnswers({});
                  }}
                  className="group flex flex-col p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-purple-400 dark:hover:border-purple-500 hover:shadow-md transition-all"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-lg">
                      <svg className="w-5 h-5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </span>
                    <span className="text-xs font-medium text-purple-600 dark:text-purple-400 uppercase">Quiz</span>
                  </div>
                  <h3 className="font-semibold text-gray-900 dark:text-white group-hover:text-purple-600 dark:group-hover:text-purple-400 transition-colors text-sm mb-1 line-clamp-2">
                    {sq.title}
                  </h3>
                  <div className="mt-auto pt-2 flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                    <span className={`px-2 py-0.5 rounded-full ${difficultyColors[sq.difficulty]}`}>
                      {sq.difficulty}
                    </span>
                    <span>{sq.question_count} Qs</span>
                    {sq.xp_reward > 0 && <span className="text-purple-600 dark:text-purple-400">+{sq.xp_reward} XP</span>}
                  </div>
                </Link>
              ))}

              {/* Typing Game Card */}
              <Link
                to="/typing-practice"
                className="group flex flex-col p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-emerald-400 dark:hover:border-emerald-500 hover:shadow-md transition-all"
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">
                    <svg className="w-5 h-5 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </span>
                  <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400 uppercase">Game</span>
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors text-sm mb-1">
                  Typing Speed Challenge
                </h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                  Test your typing speed and earn XP
                </p>
                <div className="mt-auto pt-2 flex items-center gap-2 text-xs text-emerald-600 dark:text-emerald-400">
                  Play now
                  <svg className="w-3 h-3 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </Link>

              {/* Browse Courses Card */}
              <Link
                to="/courses"
                className="group flex flex-col p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-blue-400 dark:hover:border-blue-500 hover:shadow-md transition-all"
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">
                    <svg className="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                    </svg>
                  </span>
                  <span className="text-xs font-medium text-blue-600 dark:text-blue-400 uppercase">Learn</span>
                </div>
                <h3 className="font-semibold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors text-sm mb-1">
                  Browse Courses & Tutorials
                </h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                  Continue building your IT skills
                </p>
                <div className="mt-auto pt-2 flex items-center gap-2 text-xs text-blue-600 dark:text-blue-400">
                  Explore
                  <svg className="w-3 h-3 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return null;
};

// Question Input Component
interface QuestionInputProps {
  question: QuizQuestion;
  value: any;
  onChange: (value: any) => void;
}

const QuestionInput: React.FC<QuestionInputProps> = ({ question, value, onChange }) => {
  switch (question.question_type) {
    case 'multiple_choice':
      return (
        <div className="space-y-3">
          {question.options.map((option) => (
            <label
              key={option.id}
              className={`flex items-center p-4 rounded-lg border-2 cursor-pointer transition-colors ${
                value === option.id
                  ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-purple-300 dark:hover:border-purple-700'
              }`}
            >
              <input
                type="radio"
                name={`question-${question.id}`}
                value={option.id}
                checked={value === option.id}
                onChange={() => onChange(option.id)}
                className="sr-only"
              />
              <span className={`w-5 h-5 rounded-full border-2 mr-3 flex items-center justify-center ${
                value === option.id
                  ? 'border-purple-500 bg-purple-500'
                  : 'border-gray-300 dark:border-gray-600'
              }`}>
                {value === option.id && (
                  <span className="w-2 h-2 rounded-full bg-white"></span>
                )}
              </span>
              <span className="text-gray-900 dark:text-white">{option.text}</span>
            </label>
          ))}
        </div>
      );

    case 'multiple_select':
      const selectedValues = Array.isArray(value) ? value : [];
      return (
        <div className="space-y-3">
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">Select all that apply</p>
          {question.options.map((option) => (
            <label
              key={option.id}
              className={`flex items-center p-4 rounded-lg border-2 cursor-pointer transition-colors ${
                selectedValues.includes(option.id)
                  ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-purple-300 dark:hover:border-purple-700'
              }`}
            >
              <input
                type="checkbox"
                value={option.id}
                checked={selectedValues.includes(option.id)}
                onChange={(e) => {
                  if (e.target.checked) {
                    onChange([...selectedValues, option.id]);
                  } else {
                    onChange(selectedValues.filter((v: string) => v !== option.id));
                  }
                }}
                className="sr-only"
              />
              <span className={`w-5 h-5 rounded border-2 mr-3 flex items-center justify-center ${
                selectedValues.includes(option.id)
                  ? 'border-purple-500 bg-purple-500'
                  : 'border-gray-300 dark:border-gray-600'
              }`}>
                {selectedValues.includes(option.id) && (
                  <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </span>
              <span className="text-gray-900 dark:text-white">{option.text}</span>
            </label>
          ))}
        </div>
      );

    case 'true_false':
      return (
        <div className="flex gap-4">
          {['true', 'false'].map((opt) => (
            <button
              key={opt}
              onClick={() => onChange(opt)}
              className={`flex-1 py-4 rounded-lg border-2 font-medium transition-colors ${
                value === opt
                  ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300'
                  : 'border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-purple-300 dark:hover:border-purple-700'
              }`}
            >
              {opt === 'true' ? 'True' : 'False'}
            </button>
          ))}
        </div>
      );

    case 'short_answer':
    case 'fill_blank':
      return (
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Type your answer..."
          className="w-full px-4 py-3 rounded-lg border-2 border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-purple-500 focus:outline-none"
        />
      );

    case 'code':
      return (
        <div>
          {question.code_template && (
            <pre className="bg-gray-100 dark:bg-gray-700 p-4 rounded-lg mb-4 text-sm overflow-x-auto">
              <code>{question.code_template}</code>
            </pre>
          )}
          <textarea
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Enter your code..."
            rows={8}
            className="w-full px-4 py-3 rounded-lg border-2 border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm focus:border-purple-500 focus:outline-none"
          />
        </div>
      );

    default:
      return (
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-4 py-3 rounded-lg border-2 border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:border-purple-500 focus:outline-none"
        />
      );
  }
};

export default QuizPlayerPage;
