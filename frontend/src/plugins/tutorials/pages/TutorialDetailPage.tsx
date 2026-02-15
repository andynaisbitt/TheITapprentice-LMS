// frontend/src/plugins/tutorials/pages/TutorialDetailPage.tsx
/**
 * Tutorial Detail/Viewer Page
 * Shows full tutorial with steps and progress tracking
 * Includes registration prompt for unauthenticated users
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTutorial, useTutorialProgress } from '../hooks/useTutorials';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { useAuth } from '../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../hooks/useRegistrationPrompt';

const TutorialDetailPage: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const { tutorial, loading, error, refetch } = useTutorial(slug);
  const { startTutorial, completeStep, loading: actionLoading } = useTutorialProgress();

  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [showHints, setShowHints] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const [guestMode, setGuestMode] = useState(false);
  const [showCompletionModal, setShowCompletionModal] = useState(false);
  const [xpAwarded, setXpAwarded] = useState(0);
  const [tutorialStarted, setTutorialStarted] = useState(false);

  // Registration prompt for unauthenticated users
  const {
    isPromptOpen,
    closePrompt,
    handleSkip: handlePromptSkip,
    checkAuthAndProceed,
  } = useRegistrationPrompt({
    context: 'tutorial',
    onSkip: () => {
      // User chose to continue without registration - enable guest mode
      setGuestMode(true);
      setTutorialStarted(true);
    },
  });

  // Initialize progress from tutorial data
  useEffect(() => {
    if (tutorial?.user_progress) {
      setCompletedSteps(new Set(tutorial.user_progress.completed_step_ids));
      setTutorialStarted(true);

      // Find the first incomplete step to set as current
      const sortedSteps = [...tutorial.steps].sort((a, b) => a.step_order - b.step_order);
      const firstIncompleteIndex = sortedSteps.findIndex(
        (s) => !tutorial.user_progress?.completed_step_ids.includes(s.id)
      );

      if (firstIncompleteIndex !== -1) {
        setCurrentStepIndex(firstIncompleteIndex);
      } else {
        // All steps completed, show last step
        setCurrentStepIndex(tutorial.steps.length - 1);
      }
    } else {
      // No progress - reset to first step
      setCurrentStepIndex(0);
      if (!guestMode) {
        setTutorialStarted(false);
      }
    }
  }, [tutorial, guestMode]);

  // Helper: Check if a step can be navigated to (sequential progression)
  const canNavigateToStep = (stepIndex: number): boolean => {
    if (!tutorial || !tutorialStarted) return false;

    const sortedSteps = [...tutorial.steps].sort((a, b) => a.step_order - b.step_order);

    // Can always go to completed steps
    if (completedSteps.has(sortedSteps[stepIndex]?.id)) return true;

    // Can go to first incomplete step (the "current" step)
    const firstIncompleteIndex = sortedSteps.findIndex((s) => !completedSteps.has(s.id));
    return stepIndex === firstIncompleteIndex;
  };

  // Helper: Get the index of the first incomplete step
  const getFirstIncompleteStepIndex = (): number => {
    if (!tutorial) return 0;
    const sortedSteps = [...tutorial.steps].sort((a, b) => a.step_order - b.step_order);
    const index = sortedSteps.findIndex((s) => !completedSteps.has(s.id));
    return index === -1 ? tutorial.steps.length - 1 : index;
  };

  // Handle step navigation with validation
  const handleStepNavigation = (stepIndex: number) => {
    if (!tutorialStarted && !guestMode) {
      // Tutorial not started - show start prompt
      return;
    }

    if (canNavigateToStep(stepIndex)) {
      setCurrentStepIndex(stepIndex);
      setShowHints(false);
      // Scroll to top of page smoothly
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const handleStartTutorial = async () => {
    if (!tutorial) return;

    // Check if user is authenticated - if not, show registration prompt
    if (!checkAuthAndProceed()) {
      return; // Prompt is now showing
    }

    try {
      await startTutorial(tutorial.id);
      setTutorialStarted(true);
      setCurrentStepIndex(0);
      refetch();
    } catch (err) {
      console.error('Failed to start tutorial:', err);
    }
  };

  // Handle completing a step - shows registration prompt if in guest mode
  const handleCompleteStepWithAuth = async () => {
    if (!tutorial) return;

    // If in guest mode, just track locally without saving to server
    if (guestMode || !isAuthenticated) {
      const currentStep = tutorial.steps[currentStepIndex];
      if (currentStep) {
        const newCompleted = new Set([...completedSteps, currentStep.id]);
        setCompletedSteps(newCompleted);

        // Check if this was the last step (all steps now completed)
        if (newCompleted.size >= tutorial.steps.length) {
          // Show guest completion modal
          setXpAwarded(tutorial.xp_reward || 0);
          setShowCompletionModal(true);
        } else {
          // Move to next step
          setCurrentStepIndex(currentStepIndex + 1);
          setShowHints(false);
          // Scroll to top to show new step
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      }
      return;
    }

    // Authenticated user - save progress to server
    await handleCompleteStep();
  };

  const handleCompleteStep = async () => {
    if (!tutorial) return;

    const currentStep = tutorial.steps[currentStepIndex];
    if (!currentStep) return;

    try {
      const result = await completeStep(tutorial.id, currentStep.id);

      // Update local state
      setCompletedSteps((prev) => new Set([...prev, currentStep.id]));

      // Show completion modal
      if (result.tutorial_completed) {
        setXpAwarded(result.xp_awarded || tutorial.xp_reward || 0);
        setShowCompletionModal(true);
      }

      // Move to next step if available
      if (result.next_step_id) {
        const nextIndex = tutorial.steps.findIndex((s) => s.id === result.next_step_id);
        if (nextIndex !== -1) {
          setCurrentStepIndex(nextIndex);
          setShowHints(false);
          // Scroll to top to show new step
          window.scrollTo({ top: 0, behavior: 'smooth' });
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

  // Sort steps by step_order for consistent display
  const sortedSteps = [...tutorial.steps].sort((a, b) => a.step_order - b.step_order);
  const currentStep = sortedSteps[currentStepIndex];
  const progressPercentage = tutorialStarted
    ? Math.round((completedSteps.size / tutorial.steps.length) * 100)
    : 0;
  const isStepCompleted = currentStep ? completedSteps.has(currentStep.id) : false;
  const isCurrentStepTheActiveOne = currentStepIndex === getFirstIncompleteStepIndex();
  const canProceedToNext = isStepCompleted && currentStepIndex < tutorial.steps.length - 1;

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
                {[...tutorial.steps].sort((a, b) => a.step_order - b.step_order).map((step, idx) => {
                  const isCompleted = completedSteps.has(step.id);
                  const isCurrentStep = idx === currentStepIndex;
                  const isAccessible = canNavigateToStep(idx);
                  const isLocked = !isAccessible && !isCompleted && tutorialStarted;

                  return (
                    <button
                      key={step.id}
                      onClick={() => handleStepNavigation(idx)}
                      disabled={!isAccessible && tutorialStarted}
                      className={`w-full text-left px-3 py-2 rounded-md transition-colors ${
                        isCurrentStep
                          ? 'bg-blue-100 dark:bg-blue-900 text-blue-900 dark:text-blue-100'
                          : isCompleted
                          ? 'bg-green-50 dark:bg-green-900/20 text-gray-800 dark:text-gray-200 hover:bg-green-100 dark:hover:bg-green-900/30'
                          : isLocked
                          ? 'opacity-50 cursor-not-allowed bg-gray-50 dark:bg-gray-800 text-gray-400 dark:text-gray-500'
                          : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        {isCompleted ? (
                          <span className="w-5 h-5 flex items-center justify-center rounded-full bg-green-500 text-white text-xs">✓</span>
                        ) : isLocked ? (
                          <span className="w-5 h-5 flex items-center justify-center text-gray-400">
                            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                            </svg>
                          </span>
                        ) : isCurrentStep ? (
                          <span className="w-5 h-5 flex items-center justify-center rounded-full bg-blue-500 text-white text-xs">{idx + 1}</span>
                        ) : (
                          <span className="w-5 h-5 flex items-center justify-center text-gray-400 text-sm">{idx + 1}</span>
                        )}
                        <span className={`text-sm truncate ${isLocked ? 'text-gray-400 dark:text-gray-500' : 'text-gray-800 dark:text-gray-200'}`}>
                          {step.title}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Progress Summary */}
              {tutorialStarted && (
                <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    Completed: {completedSteps.size} of {tutorial.steps.length} steps
                  </div>
                </div>
              )}
            </div>
          </aside>

          {/* Main Content */}
          <main className="lg:col-span-3">
            {!tutorial.user_progress && !guestMode && (
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6 mb-6">
                <h3 className="text-lg font-bold text-blue-900 dark:text-blue-100 mb-2">
                  Ready to start learning?
                </h3>
                <p className="text-blue-800 dark:text-blue-200 mb-4">
                  {isAuthenticated
                    ? `Track your progress and earn ${tutorial.xp_reward} XP upon completion!`
                    : `Sign up to track your progress and earn ${tutorial.xp_reward} XP!`}
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

            {guestMode && !isAuthenticated && (
              <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mb-6">
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-yellow-600 dark:text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  <p className="text-yellow-800 dark:text-yellow-200 text-sm">
                    You're learning as a guest. <button onClick={() => checkAuthAndProceed()} className="underline font-medium hover:no-underline">Sign up</button> to save your progress and earn XP!
                  </p>
                </div>
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
                    <div className="prose prose-base sm:prose-lg dark:prose-invert max-w-none mb-8
                                 prose-headings:font-bold prose-headings:text-gray-900 dark:prose-headings:text-gray-100
                                 prose-headings:tracking-tight prose-headings:scroll-mt-20
                                 prose-h2:text-2xl sm:prose-h2:text-3xl prose-h2:mt-12 prose-h2:mb-4
                                 prose-h3:text-xl sm:prose-h3:text-2xl prose-h3:mt-8 prose-h3:mb-3
                                 prose-p:text-gray-700 dark:prose-p:text-gray-300 prose-p:leading-relaxed
                                 prose-a:text-blue-600 dark:prose-a:text-blue-400
                                 prose-strong:text-gray-900 dark:prose-strong:text-gray-100
                                 prose-code:text-gray-900 dark:prose-code:text-gray-100 prose-code:bg-gray-100 dark:prose-code:bg-slate-800
                                 prose-pre:bg-gray-100 dark:prose-pre:bg-slate-800">
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
                      onClick={() => handleStepNavigation(currentStepIndex - 1)}
                      disabled={currentStepIndex === 0}
                      className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Previous
                    </button>

                    <div className="flex items-center gap-4">
                      {!isStepCompleted && (tutorial.user_progress || guestMode) && (
                        <button
                          onClick={handleCompleteStepWithAuth}
                          disabled={actionLoading}
                          className="px-6 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
                        >
                          {actionLoading ? 'Completing...' : 'Mark as Complete'}
                        </button>
                      )}

                      {/* Show "Complete step to continue" message when step not completed */}
                      {!isStepCompleted && currentStepIndex < tutorial.steps.length - 1 && (tutorial.user_progress || guestMode) && (
                        <span className="text-sm text-gray-500 dark:text-gray-400 italic">
                          Complete this step to continue
                        </span>
                      )}

                      {/* Only show Next Step button when current step is completed */}
                      {canProceedToNext && (
                        <button
                          onClick={() => handleStepNavigation(currentStepIndex + 1)}
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

      {/* Tutorial Completion Modal */}
      {showCompletionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full p-8 transform animate-in zoom-in-95 duration-300">
            {/* Success Icon */}
            <div className="flex justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-green-400 to-emerald-500 flex items-center justify-center shadow-lg">
                <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                </svg>
              </div>
            </div>

            {/* Title */}
            <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-2">
              Tutorial Complete!
            </h2>

            {/* Tutorial Name */}
            <p className="text-center text-gray-600 dark:text-gray-400 mb-6">
              You've successfully completed <span className="font-semibold text-gray-900 dark:text-white">{tutorial?.title}</span>
            </p>

            {/* XP Reward or Guest CTA */}
            {isAuthenticated ? (
              <div className="bg-gradient-to-r from-yellow-50 to-amber-50 dark:from-yellow-900/20 dark:to-amber-900/20 border border-yellow-200 dark:border-yellow-800 rounded-xl p-4 mb-6">
                <div className="flex items-center justify-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-gradient-to-br from-yellow-400 to-amber-500 flex items-center justify-center">
                    <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                      <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm text-yellow-700 dark:text-yellow-300 font-medium">XP Earned</p>
                    <p className="text-2xl font-bold text-yellow-800 dark:text-yellow-200">+{xpAwarded} XP</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200 dark:border-blue-800 rounded-xl p-4 mb-6">
                <div className="text-center">
                  <p className="text-sm text-blue-700 dark:text-blue-300 font-medium mb-1">
                    You could have earned
                  </p>
                  <p className="text-2xl font-bold text-blue-800 dark:text-blue-200 mb-2">+{xpAwarded} XP</p>
                  <p className="text-sm text-blue-600 dark:text-blue-400">
                    Sign up to save your progress and earn XP rewards!
                  </p>
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-col gap-3">
              {!isAuthenticated && (
                <button
                  onClick={() => navigate('/register')}
                  className="w-full px-6 py-3 bg-gradient-to-r from-green-500 to-emerald-600 text-white rounded-xl font-semibold hover:from-green-600 hover:to-emerald-700 transition-all shadow-md hover:shadow-lg"
                >
                  Sign Up to Earn XP
                </button>
              )}
              <button
                onClick={() => navigate('/tutorials')}
                className="w-full px-6 py-3 bg-gradient-to-r from-blue-500 to-indigo-600 text-white rounded-xl font-semibold hover:from-blue-600 hover:to-indigo-700 transition-all shadow-md hover:shadow-lg"
              >
                Browse More Tutorials
              </button>
              <button
                onClick={() => setShowCompletionModal(false)}
                className="w-full px-6 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-xl font-semibold hover:bg-gray-200 dark:hover:bg-gray-600 transition-all"
              >
                Stay on This Page
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Registration Prompt Modal */}
      <RegistrationPrompt
        isOpen={isPromptOpen}
        onClose={closePrompt}
        onSkip={handlePromptSkip}
        context="tutorial"
      />
    </div>
  );
};

export default TutorialDetailPage;
