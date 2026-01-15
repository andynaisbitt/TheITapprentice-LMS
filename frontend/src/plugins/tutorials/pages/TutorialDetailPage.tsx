// frontend/src/plugins/tutorials/pages/TutorialDetailPage.tsx
/**
 * Tutorial Detail/Viewer Page
 * Shows full tutorial with steps and progress tracking
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTutorial, useTutorialProgress } from '../hooks/useTutorials';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

const TutorialDetailPage: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const { tutorial, loading, error, refetch } = useTutorial(slug);
  const { startTutorial, completeStep, loading: actionLoading } = useTutorialProgress();

  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [showHints, setShowHints] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());

  // Initialize progress from tutorial data
  useEffect(() => {
    if (tutorial?.user_progress) {
      setCompletedSteps(new Set(tutorial.user_progress.completed_step_ids));

      // Find current step
      if (tutorial.user_progress.current_step_id) {
        const stepIndex = tutorial.steps.findIndex(
          (s) => s.id === tutorial.user_progress?.current_step_id
        );
        if (stepIndex !== -1) {
          setCurrentStepIndex(stepIndex);
        }
      }
    }
  }, [tutorial]);

  const handleStartTutorial = async () => {
    if (!tutorial) return;

    try {
      await startTutorial(tutorial.id);
      refetch();
    } catch (err) {
      console.error('Failed to start tutorial:', err);
    }
  };

  const handleCompleteStep = async () => {
    if (!tutorial) return;

    const currentStep = tutorial.steps[currentStepIndex];
    if (!currentStep) return;

    try {
      const result = await completeStep(tutorial.id, currentStep.id);

      // Update local state
      setCompletedSteps((prev) => new Set([...prev, currentStep.id]));

      // Show success message
      if (result.tutorial_completed) {
        alert(`🎉 Congratulations! You completed the tutorial and earned ${result.xp_awarded} XP!`);
      }

      // Move to next step if available
      if (result.next_step_id) {
        const nextIndex = tutorial.steps.findIndex((s) => s.id === result.next_step_id);
        if (nextIndex !== -1) {
          setCurrentStepIndex(nextIndex);
          setShowHints(false);
        }
      }

      refetch();
    } catch (err) {
      console.error('Failed to complete step:', err);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error || !tutorial) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
            Tutorial not found
          </h2>
          <button
            onClick={() => navigate('/tutorials')}
            className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Back to Tutorials
          </button>
        </div>
      </div>
    );
  }

  const currentStep = tutorial.steps[currentStepIndex];
  const progressPercentage = tutorial.user_progress?.progress_percentage || 0;
  const isStepCompleted = currentStep ? completedSteps.has(currentStep.id) : false;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => navigate('/tutorials')}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
              </button>
              <div>
                <h1 className="text-xl font-bold text-gray-900 dark:text-white">{tutorial.title}</h1>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Step {currentStepIndex + 1} of {tutorial.steps.length}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-sm text-gray-600 dark:text-gray-400">Progress</div>
                <div className="text-lg font-bold text-blue-600">{progressPercentage}%</div>
              </div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="mt-4 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-purple-600 transition-all duration-300"
              style={{ width: `${progressPercentage}%` }}
            />
          </div>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Steps Sidebar */}
          <aside className="lg:col-span-1">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4 sticky top-24">
              <h3 className="font-bold text-gray-900 dark:text-white mb-4">Steps</h3>
              <div className="space-y-2">
                {tutorial.steps.map((step, idx) => (
                  <button
                    key={step.id}
                    onClick={() => setCurrentStepIndex(idx)}
                    className={`w-full text-left px-3 py-2 rounded-md transition-colors ${
                      idx === currentStepIndex
                        ? 'bg-blue-100 dark:bg-blue-900 text-blue-900 dark:text-blue-100'
                        : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      {completedSteps.has(step.id) ? (
                        <span className="text-green-500">✓</span>
                      ) : (
                        <span className="text-gray-400">{idx + 1}</span>
                      )}
                      <span className="text-sm truncate">{step.title}</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </aside>

          {/* Main Content */}
          <main className="lg:col-span-3">
            {!tutorial.user_progress && (
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6 mb-6">
                <h3 className="text-lg font-bold text-blue-900 dark:text-blue-100 mb-2">
                  Ready to start learning?
                </h3>
                <p className="text-blue-800 dark:text-blue-200 mb-4">
                  Track your progress and earn {tutorial.xp_reward} XP upon completion!
                </p>
                <button
                  onClick={handleStartTutorial}
                  disabled={actionLoading}
                  className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                >
                  {actionLoading ? 'Starting...' : 'Start Tutorial'}
                </button>
              </div>
            )}

            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-8">
              {currentStep && (
                <>
                  <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-6">
                    {currentStep.title}
                  </h2>

                  {/* Content */}
                  {currentStep.content && (
                    <div className="prose dark:prose-invert max-w-none mb-8">
                      <ReactMarkdown>{currentStep.content}</ReactMarkdown>
                    </div>
                  )}

                  {/* Code Example */}
                  {currentStep.code_example && (
                    <div className="mb-8">
                      <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                        Code Example
                      </h4>
                      <SyntaxHighlighter
                        language={currentStep.code_language || 'javascript'}
                        style={vscDarkPlus}
                        className="rounded-lg"
                      >
                        {currentStep.code_example}
                      </SyntaxHighlighter>
                    </div>
                  )}

                  {/* Hints */}
                  {currentStep.hints && currentStep.hints.length > 0 && (
                    <div className="mb-8">
                      <button
                        onClick={() => setShowHints(!showHints)}
                        className="flex items-center gap-2 text-yellow-600 dark:text-yellow-400 hover:text-yellow-700 dark:hover:text-yellow-300"
                      >
                        <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                        </svg>
                        {showHints ? 'Hide' : 'Show'} Hints ({currentStep.hints.length})
                      </button>

                      {showHints && (
                        <div className="mt-4 space-y-2">
                          {currentStep.hints.map((hint, idx) => (
                            <div
                              key={idx}
                              className="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md"
                            >
                              <p className="text-yellow-900 dark:text-yellow-100">{hint}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center justify-between pt-6 border-t border-gray-200 dark:border-gray-700">
                    <button
                      onClick={() => setCurrentStepIndex(Math.max(0, currentStepIndex - 1))}
                      disabled={currentStepIndex === 0}
                      className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Previous
                    </button>

                    <div className="flex items-center gap-4">
                      {!isStepCompleted && tutorial.user_progress && (
                        <button
                          onClick={handleCompleteStep}
                          disabled={actionLoading}
                          className="px-6 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
                        >
                          {actionLoading ? 'Completing...' : 'Mark as Complete'}
                        </button>
                      )}

                      {currentStepIndex < tutorial.steps.length - 1 && (
                        <button
                          onClick={() => setCurrentStepIndex(currentStepIndex + 1)}
                          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                        >
                          Next Step
                        </button>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
};

export default TutorialDetailPage;
