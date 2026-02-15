// src/pages/courses/CoursePlayer.tsx
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ChevronLeft,
  ChevronRight,
  CheckCircle,
  BookOpen,
  Menu,
  X,
  Award,
  Medal
} from 'lucide-react';
import confetti from 'canvas-confetti';
import ReactMarkdown from 'react-markdown';
import { coursesApi } from '../../services/coursesApi';
import type { Course as CourseDetail, CourseModule, ModuleSection, ContentBlock } from '../../types';
import { useToast } from '../../../../components/ui/Toast';

// Placeholder hooks until XP notification system is implemented
const useXPNotification = () => ({ showXPGain: (_xp: number, _reason: string) => {} });
const useAchievementNotification = () => ({ showAchievementUnlock: (_achievement: any) => {} });

// Quiz answer validation function (standalone to prevent re-creation)
const checkQuizAnswer = (question: any, userAnswer: any): boolean => {
  const correct = question.correct_answer;
  if (correct === undefined || correct === null) return false;
  if (userAnswer === undefined || userAnswer === null || userAnswer === '') return false;

  switch (question.type) {
    case 'multiple_choice':
    case 'true_false':
      return String(userAnswer).toLowerCase().trim() === String(correct).toLowerCase().trim();

    case 'multiple_select':
      if (!Array.isArray(userAnswer) || !Array.isArray(correct)) return false;
      const userSet = new Set(userAnswer.map((a: string) => String(a).toLowerCase().trim()));
      const correctSet = new Set(correct.map((c: string) => String(c).toLowerCase().trim()));
      return userSet.size === correctSet.size &&
        [...userSet].every(v => correctSet.has(v));

    case 'short_answer':
    case 'fill_blank':
      const userLower = String(userAnswer).toLowerCase().trim();
      if (Array.isArray(correct)) {
        return correct.some((c: string) => String(c).toLowerCase().trim() === userLower);
      }
      return userLower === String(correct).toLowerCase().trim();

    case 'code_challenge':
      return String(userAnswer).trim() === String(correct).trim();

    default:
      return false;
  }
};

// QuizBlockPlayer - MUST be outside CoursePlayer to prevent remounting on parent re-render
const QuizBlockPlayer: React.FC<{
  blockId: string;
  content: any;
  onQuizComplete: (blockId: string, passed: boolean, score: number, maxScore: number) => void;
}> = ({ blockId, content, onQuizComplete }) => {
  const questions = content?.questions || [];
  const passingScore = content?.passing_score || 70;

  const [answers, setAnswers] = useState<Record<string, any>>({});
  const [showResults, setShowResults] = useState(false);
  const [results, setResults] = useState<Record<string, boolean>>({});
  const [score, setScore] = useState(0);
  const [maxScore, setMaxScore] = useState(0);

  const handleAnswerChange = (questionId: string, value: any) => {
    setAnswers(prev => ({ ...prev, [questionId]: value }));
    if (showResults) {
      setShowResults(false);
      setResults({});
    }
  };

  const handleMultiSelectChange = (questionId: string, option: string, checked: boolean) => {
    setAnswers(prev => {
      const current = Array.isArray(prev[questionId]) ? prev[questionId] : [];
      if (checked) {
        return { ...prev, [questionId]: [...current, option] };
      } else {
        return { ...prev, [questionId]: current.filter((o: string) => o !== option) };
      }
    });
    if (showResults) {
      setShowResults(false);
      setResults({});
    }
  };

  const handleCheckAnswers = () => {
    let totalScore = 0;
    let totalMaxScore = 0;
    const newResults: Record<string, boolean> = {};

    questions.forEach((question: any) => {
      const qId = question.id;
      const userAnswer = answers[qId];
      const isCorrect = checkQuizAnswer(question, userAnswer);
      newResults[qId] = isCorrect;
      totalMaxScore += question.points || 1;
      if (isCorrect) {
        totalScore += question.points || 1;
      }
    });

    setResults(newResults);
    setScore(totalScore);
    setMaxScore(totalMaxScore);
    setShowResults(true);

    const percentage = totalMaxScore > 0 ? (totalScore / totalMaxScore) * 100 : 0;
    const passed = percentage >= passingScore;
    onQuizComplete(blockId, passed, totalScore, totalMaxScore);
  };

  const percentage = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;
  const passed = percentage >= passingScore;

  return (
    <div className="bg-gray-50 dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 my-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2 flex items-center gap-2">
        <span className="text-2xl">📝</span>
        Quiz
        {showResults && (
          <span className={`ml-auto text-sm font-normal px-3 py-1 rounded-full ${
            passed
              ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
              : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
          }`}>
            {percentage}% - {passed ? 'Passed!' : `Need ${passingScore}% to pass`}
          </span>
        )}
      </h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Passing score: {passingScore}% • {questions.length} question{questions.length !== 1 ? 's' : ''}
      </p>

      <div className="space-y-6">
        {questions.map((question: any, qIdx: number) => {
          const qId = question.id;
          const isCorrect = results[qId];
          const wasAnswered = showResults;

          return (
            <div
              key={qId || qIdx}
              className={`bg-white dark:bg-gray-900 rounded-lg p-4 border-2 transition-colors ${
                wasAnswered
                  ? isCorrect
                    ? 'border-green-400 dark:border-green-500'
                    : 'border-red-400 dark:border-red-500'
                  : 'border-gray-200 dark:border-gray-700'
              }`}
            >
              <div className="flex items-start gap-2 mb-3">
                <span className="text-blue-600 dark:text-blue-400 font-medium">Q{qIdx + 1}.</span>
                <p className="font-medium text-gray-900 dark:text-white flex-1">{question.question}</p>
                {wasAnswered && (
                  <span className={`text-lg ${isCorrect ? 'text-green-500' : 'text-red-500'}`}>
                    {isCorrect ? '✓' : '✗'}
                  </span>
                )}
              </div>

              {/* Multiple Choice / True-False */}
              {(question.type === 'multiple_choice' || question.type === 'true_false') && (
                <div className="space-y-2 ml-6">
                  {(question.options || (question.type === 'true_false' ? ['True', 'False'] : [])).map((option: string, oIdx: number) => {
                    const isSelected = answers[qId]?.toString().toLowerCase() === option.toLowerCase();
                    const isCorrectOption = question.correct_answer?.toString().toLowerCase() === option.toLowerCase();
                    return (
                      <label
                        key={oIdx}
                        className={`flex items-center gap-3 p-2 rounded cursor-pointer transition-colors ${
                          wasAnswered
                            ? isCorrectOption
                              ? 'bg-green-50 dark:bg-green-900/20'
                              : isSelected
                                ? 'bg-red-50 dark:bg-red-900/20'
                                : ''
                            : 'hover:bg-gray-50 dark:hover:bg-gray-800'
                        }`}
                      >
                        <input
                          type="radio"
                          name={`quiz-${blockId}-q${qIdx}`}
                          checked={isSelected}
                          onChange={() => handleAnswerChange(qId, option)}
                          disabled={showResults && passed}
                          className="w-4 h-4 text-blue-600"
                        />
                        <span className="text-gray-700 dark:text-gray-300">{option}</span>
                        {wasAnswered && isCorrectOption && (
                          <span className="ml-auto text-green-600 dark:text-green-400 text-sm">✓ Correct</span>
                        )}
                      </label>
                    );
                  })}
                </div>
              )}

              {/* Multiple Select */}
              {question.type === 'multiple_select' && question.options && (
                <div className="space-y-2 ml-6">
                  <p className="text-xs text-gray-500 mb-1">Select all that apply:</p>
                  {question.options.map((option: string, oIdx: number) => {
                    const selectedAnswers = Array.isArray(answers[qId]) ? answers[qId] : [];
                    const isSelected = selectedAnswers.includes(option);
                    const correctAnswers = Array.isArray(question.correct_answer) ? question.correct_answer : [];
                    const isCorrectOption = correctAnswers.includes(option);
                    return (
                      <label
                        key={oIdx}
                        className={`flex items-center gap-3 p-2 rounded cursor-pointer transition-colors ${
                          wasAnswered
                            ? isCorrectOption
                              ? 'bg-green-50 dark:bg-green-900/20'
                              : isSelected
                                ? 'bg-red-50 dark:bg-red-900/20'
                                : ''
                            : 'hover:bg-gray-50 dark:hover:bg-gray-800'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => handleMultiSelectChange(qId, option, e.target.checked)}
                          disabled={showResults && passed}
                          className="w-4 h-4 text-blue-600 rounded"
                        />
                        <span className="text-gray-700 dark:text-gray-300">{option}</span>
                        {wasAnswered && isCorrectOption && (
                          <span className="ml-auto text-green-600 dark:text-green-400 text-sm">✓ Correct</span>
                        )}
                      </label>
                    );
                  })}
                </div>
              )}

              {/* Short Answer / Fill Blank */}
              {(question.type === 'short_answer' || question.type === 'fill_blank') && (
                <div className="ml-6">
                  <input
                    type="text"
                    value={answers[qId] || ''}
                    onChange={(e) => handleAnswerChange(qId, e.target.value)}
                    placeholder="Type your answer..."
                    disabled={showResults && passed}
                    className={`w-full p-2 border rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white ${
                      wasAnswered
                        ? isCorrect
                          ? 'border-green-400'
                          : 'border-red-400'
                        : 'border-gray-300 dark:border-gray-600'
                    }`}
                  />
                  {wasAnswered && !isCorrect && (
                    <p className="text-sm text-green-600 dark:text-green-400 mt-1">
                      Correct answer: {Array.isArray(question.correct_answer) ? question.correct_answer.join(' or ') : question.correct_answer}
                    </p>
                  )}
                </div>
              )}

              {/* Code Challenge */}
              {question.type === 'code_challenge' && (
                <div className="ml-6">
                  <textarea
                    value={answers[qId] || question.code_snippet || ''}
                    onChange={(e) => handleAnswerChange(qId, e.target.value)}
                    rows={4}
                    disabled={showResults && passed}
                    className={`w-full p-3 font-mono text-sm rounded-lg bg-gray-900 text-green-400 border ${
                      wasAnswered
                        ? isCorrect
                          ? 'border-green-400'
                          : 'border-red-400'
                        : 'border-gray-600'
                    }`}
                  />
                </div>
              )}

              {/* Explanation */}
              {wasAnswered && question.explanation && (
                <div className="mt-3 ml-6 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <p className="text-sm text-blue-700 dark:text-blue-300">
                    <strong>Explanation:</strong> {question.explanation}
                  </p>
                </div>
              )}

              {/* Points */}
              {question.points && (
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-2 ml-6">
                  {question.points} point{question.points !== 1 ? 's' : ''}
                  {wasAnswered && (
                    <span className={isCorrect ? 'text-green-600' : 'text-red-600'}>
                      {' '}• {isCorrect ? `+${question.points}` : '+0'}
                    </span>
                  )}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {questions.length > 0 && (
        <div className="mt-4 flex items-center justify-between">
          {showResults && (
            <div className={`text-sm font-medium ${passed ? 'text-green-600' : 'text-red-600'}`}>
              Score: {score}/{maxScore} ({percentage}%)
            </div>
          )}
          <div className="ml-auto flex gap-2">
            {showResults && !passed && (
              <button
                onClick={() => {
                  setShowResults(false);
                  setResults({});
                  setAnswers({});
                }}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg font-medium transition-colors"
              >
                Try Again
              </button>
            )}
            {!showResults && (
              <button
                onClick={handleCheckAnswers}
                disabled={Object.keys(answers).length === 0}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition-colors disabled:cursor-not-allowed"
              >
                Check Answers
              </button>
            )}
            {showResults && passed && (
              <span className="px-4 py-2 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-lg font-medium flex items-center gap-2">
                <CheckCircle className="w-4 h-4" />
                Quiz Passed!
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const CoursePlayer: React.FC = () => {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { showXPGain } = useXPNotification();
  const { showAchievementUnlock } = useAchievementNotification();

  const [course, setCourse] = useState<CourseDetail | null>(null);
  const [currentModule, setCurrentModule] = useState<CourseModule | null>(null);
  const [currentSection, setCurrentSection] = useState<ModuleSection | null>(null);
  const [completedSections, setCompletedSections] = useState<Set<string>>(new Set());
  const [moduleProgress, setModuleProgress] = useState<Record<string, string[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [showCompletionModal, setShowCompletionModal] = useState(false);
  const [completionData, setCompletionData] = useState<any>(null);
  const [courseWasAlreadyComplete, setCourseWasAlreadyComplete] = useState(false);
  const [courseJustCompleted, setCourseJustCompleted] = useState(false);
  const [earnedCertificate, setEarnedCertificate] = useState<any>(null);
  const [guestMode, setGuestMode] = useState(false);
  const [guestWarningShown, setGuestWarningShown] = useState(false);
  // Quiz state - tracks which quizzes have been passed in current section
  const [quizResults, setQuizResults] = useState<Record<string, { passed: boolean; score: number; maxScore: number }>>({});

  // Fire confetti when course completion modal shows
  useEffect(() => {
    if (showCompletionModal && completionData?.course_complete) {
      const duration = 3000;
      const end = Date.now() + duration;

      const frame = () => {
        confetti({
          particleCount: 3,
          angle: 60,
          spread: 55,
          origin: { x: 0, y: 0.7 },
        });
        confetti({
          particleCount: 3,
          angle: 120,
          spread: 55,
          origin: { x: 1, y: 0.7 },
        });
        if (Date.now() < end) {
          requestAnimationFrame(frame);
        }
      };
      frame();
    }
  }, [showCompletionModal, completionData]);

  // Fetch course and progress data
  useEffect(() => {
    const fetchData = async () => {
      if (!courseId) return;

      try {
        setLoading(true);
        setError(null);

        // Fetch course details
        const courseData = await coursesApi.getCourse(courseId);
        setCourse(courseData);

        // Try to fetch existing progress
        try {
          const progressData = await coursesApi.getProgress(courseId);

          // Load completed sections from all modules
          const allCompleted = new Set<string>();
          const progressMap: Record<string, string[]> = {};

          if (progressData.module_progress) {
            Object.entries(progressData.module_progress).forEach(([moduleId, progress]: [string, any]) => {
              const sections = progress.completed_sections || [];
              progressMap[moduleId] = sections;
              sections.forEach((sId: string) => allCompleted.add(sId));
            });
          }

          // Check if all sections are actually completed but course isn't marked complete
          // This detects corrupted data from the previous JSON mutation bug
          if (!progressData.is_complete && courseData.modules) {
            const totalSections = courseData.modules.reduce(
              (sum, mod) => sum + (mod.sections?.length || 0), 0
            );
            if (totalSections > 0 && allCompleted.size >= totalSections) {
              console.log('[CoursePlayer] All sections complete but course not marked complete - triggering repair');
              try {
                const repairResult = await coursesApi.repairProgress(courseId);
                console.log('[CoursePlayer] Repair result:', repairResult);
                if (repairResult.is_complete) {
                  setCourseWasAlreadyComplete(true);
                  setCompletedSections(allCompleted);
                  setModuleProgress(progressMap);
                  setLoading(false);
                  return;
                }
              } catch (repairErr) {
                console.error('[CoursePlayer] Repair failed:', repairErr);
              }
            }
          }

          // Track if course was already complete (to prevent showing completion modal again)
          if (progressData.is_complete) {
            setCourseWasAlreadyComplete(true);
            console.log('[CoursePlayer] Course already complete - will not show completion modal');
          }

          setCompletedSections(allCompleted);
          setModuleProgress(progressMap);

          // Resume from last accessed module or start from beginning
          if (progressData.current_module && courseData.modules) {
            const lastModule = courseData.modules.find(m => m.id === progressData.current_module);
            if (lastModule && lastModule.sections && lastModule.sections.length > 0) {
              const sortedSections = lastModule.sections.sort((a, b) => a.order_index - b.order_index);
              // Find first incomplete section in this module, or first section
              const firstIncomplete = sortedSections.find(s => !allCompleted.has(s.id));
              setCurrentModule(lastModule);
              setCurrentSection(firstIncomplete || sortedSections[0]);
              return;
            }
          }

          // Fall through to default start
        } catch (progressErr) {
          console.log('No existing progress, starting fresh');
        }

        // Start from first module, first section
        const sortedModules = courseData.modules?.sort((a, b) => a.order_index - b.order_index) || [];
        if (sortedModules.length > 0) {
          const firstModule = sortedModules[0];
          const sortedSections = firstModule.sections?.sort((a, b) => a.order_index - b.order_index) || [];
          if (sortedSections.length > 0) {
            setCurrentModule(firstModule);
            setCurrentSection(sortedSections[0]);
          }
        }
      } catch (err: any) {
        console.error('Error loading course:', err);
        setError(err.response?.data?.detail || 'Failed to load course');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [courseId]);

  // Navigate to section (with completion check)
  const navigateToSection = (module: CourseModule, section: ModuleSection) => {
    // Reset quiz results when changing sections
    if (currentSection?.id !== section.id) {
      setQuizResults({});
    }

    // Allow navigation to already completed sections (review)
    if (completedSections.has(section.id)) {
      setCurrentModule(module);
      setCurrentSection(section);
      window.scrollTo(0, 0);
      return;
    }

    // Allow navigation if this is the current section
    if (currentSection?.id === section.id) {
      return;
    }

    // Check if user is trying to skip ahead
    const sortedModules = course?.modules?.sort((a, b) => a.order_index - b.order_index) || [];
    const sortedSections = module.sections?.sort((a, b) => a.order_index - b.order_index) || [];

    // Find the first incomplete section in the entire course
    let foundFirstIncomplete = false;
    let canAccess = false;

    for (const mod of sortedModules) {
      const modSections = mod.sections?.sort((a, b) => a.order_index - b.order_index) || [];
      for (const sec of modSections) {
        if (!completedSections.has(sec.id)) {
          foundFirstIncomplete = true;
          // Can only access the first incomplete section
          if (sec.id === section.id) {
            canAccess = true;
          }
          break;
        }
      }
      if (foundFirstIncomplete) break;
    }

    if (!canAccess) {
      toast.warning('Please complete the previous sections in order before accessing this one.');
      return;
    }

    setCurrentModule(module);
    setCurrentSection(section);
    window.scrollTo(0, 0);
  };

  // Mark section complete
  const markSectionComplete = async () => {
    if (!currentSection || !currentModule || !courseId) return;

    // Don't mark if already complete
    if (completedSections.has(currentSection.id)) {
      console.log('Section already marked complete');
      return;
    }

    // Check if section has quizzes that need to be passed
    const quizBlocks = currentSection.content_blocks?.filter(b => b.type === 'quiz') || [];
    if (quizBlocks.length > 0) {
      const unpassed = quizBlocks.filter(block => {
        const blockId = block.id || `block-${currentSection.content_blocks.indexOf(block)}`;
        const result = quizResults[blockId];
        return !result || !result.passed;
      });

      if (unpassed.length > 0) {
        toast.warning(`Please pass ${unpassed.length === 1 ? 'the quiz' : 'all quizzes'} before marking this section complete.`);
        return;
      }
    }

    try {
      // Optimistically update UI
      setCompletedSections(prev => new Set(prev).add(currentSection.id));

      // Get current completed sections for this module (avoid duplicates)
      const currentModuleSections = moduleProgress[currentModule.id] || [];
      const updatedSections = currentModuleSections.includes(currentSection.id)
        ? currentModuleSections
        : [...currentModuleSections, currentSection.id];

      console.log('Updating progress:', {
        courseId,
        moduleId: currentModule.id,
        sectionId: currentSection.id,
        updatedSections
      });

      // Update progress in backend
      const result = await coursesApi.updateProgress(courseId, currentModule.id, {
        completed_sections: updatedSections,
        time_spent: 0 // Could track actual time
      });

      console.log('Progress update result:', result);

      // Update local progress state
      setModuleProgress(prev => ({
        ...prev,
        [currentModule.id]: result.completed_sections || updatedSections
      }));

      // Show XP notification if course was just completed
      const resultAny = result as any;
      if (result.course_complete && resultAny?.xp_gains?.length > 0) {
        showXPGain(resultAny.total_xp_gained || 0, 'Course completed');
        resultAny.xp_gains.forEach((xpGain: any) => {
          xpGain?.achievements_unlocked?.forEach((achievement: any) => {
            showAchievementUnlock(achievement);
          });
        });
      }

      // Show completion modal ONLY if:
      // 1. Module or course was just completed (not already complete)
      // 2. Course wasn't already complete when we loaded the page
      if ((result.module_completed || result.course_complete) && !courseWasAlreadyComplete) {
        console.log('[CoursePlayer] Showing completion modal', {
          module_completed: result.module_completed,
          course_complete: result.course_complete,
          was_already_complete: courseWasAlreadyComplete,
          certificate: result.certificate,
          certificate_id: result.certificate_id
        });

        // If course just completed, fetch certificate as backup if not in response
        let certificateData = result.certificate || null;
        if (result.course_complete) {
          setCourseJustCompleted(true);

          if (!certificateData && courseId) {
            try {
              const cert = await coursesApi.getCourseCertificate(courseId);
              certificateData = {
                title: cert.title,
                description: cert.description || '',
                verification_code: cert.verification_code,
                skills_acquired: cert.skills_acquired || [],
              };
              console.log('[CoursePlayer] Fetched certificate as backup:', certificateData);
            } catch (certErr) {
              console.log('[CoursePlayer] No certificate available yet:', certErr);
            }
          }

          if (certificateData) {
            setEarnedCertificate(certificateData);
          }
        }

        setCompletionData({ ...result, certificate: certificateData });
        setShowCompletionModal(true);
      } else if (courseWasAlreadyComplete) {
        console.log('[CoursePlayer] Skipping completion modal - course already complete');
      }
    } catch (err: any) {
      console.error('Error marking section complete:', err);

      if (err.response?.status === 401) {
        // Guest user - enable guest mode and keep optimistic update
        setGuestMode(true);
        if (!guestWarningShown) {
          toast.info('You\'re browsing as a guest. Sign up to save your progress and earn XP!');
          setGuestWarningShown(true);
        }
        // Keep the optimistic update so guest can continue navigating
        setModuleProgress(prev => ({
          ...prev,
          [currentModule.id]: [...(prev[currentModule.id] || []), currentSection.id]
        }));
      } else {
        toast.error('Failed to save progress. Please try again.');
        // Only rollback on non-auth errors
        setCompletedSections(prev => {
          const newSet = new Set(prev);
          newSet.delete(currentSection.id);
          return newSet;
        });
      }
    }
  };

  // Get next section
  const getNextSection = () => {
    if (!course || !currentModule || !currentSection) return null;

    const modules = course.modules?.sort((a, b) => a.order_index - b.order_index) || [];
    const currentModuleIndex = modules.findIndex(m => m.id === currentModule.id);

    const sections = currentModule.sections?.sort((a, b) => a.order_index - b.order_index) || [];
    const currentSectionIndex = sections.findIndex(s => s.id === currentSection.id);

    // Next section in current module
    if (currentSectionIndex < sections.length - 1) {
      return {
        module: currentModule,
        section: sections[currentSectionIndex + 1]
      };
    }

    // First section of next module
    if (currentModuleIndex < modules.length - 1) {
      const nextModule = modules[currentModuleIndex + 1];
      const nextSections = nextModule.sections?.sort((a, b) => a.order_index - b.order_index) || [];
      if (nextSections.length > 0) {
        return {
          module: nextModule,
          section: nextSections[0]
        };
      }
    }

    return null;
  };

  // Get previous section
  const getPreviousSection = () => {
    if (!course || !currentModule || !currentSection) return null;

    const modules = course.modules?.sort((a, b) => a.order_index - b.order_index) || [];
    const currentModuleIndex = modules.findIndex(m => m.id === currentModule.id);

    const sections = currentModule.sections?.sort((a, b) => a.order_index - b.order_index) || [];
    const currentSectionIndex = sections.findIndex(s => s.id === currentSection.id);

    // Previous section in current module
    if (currentSectionIndex > 0) {
      return {
        module: currentModule,
        section: sections[currentSectionIndex - 1]
      };
    }

    // Last section of previous module
    if (currentModuleIndex > 0) {
      const prevModule = modules[currentModuleIndex - 1];
      const prevSections = prevModule.sections?.sort((a, b) => a.order_index - b.order_index) || [];
      if (prevSections.length > 0) {
        return {
          module: prevModule,
          section: prevSections[prevSections.length - 1]
        };
      }
    }

    return null;
  };

  // Check if can navigate to next
  const canNavigateNext = () => {
    if (!currentSection) return false;
    // Must complete current section before moving forward
    return completedSections.has(currentSection.id);
  };

  // Handle next button click
  const handleNext = () => {
    const nextSection = getNextSection();

    // If no next section, we're at the end
    if (!nextSection) {
      if (completedSections.has(currentSection!.id)) {
        // Course is done - show completion modal or navigate
        if (completionData) {
          setShowCompletionModal(true);
        } else if (courseJustCompleted) {
          // Course was completed this session but modal was dismissed
          setCourseWasAlreadyComplete(true);
        } else {
          navigate('/dashboard');
        }
      } else {
        toast.warning('Please mark this section as complete to finish the course.');
      }
      return;
    }

    // Check if current section is complete before allowing navigation
    if (!completedSections.has(currentSection!.id)) {
      toast.warning('Please mark the current section as complete before moving to the next one.');
      return;
    }

    // Navigate to next section
    navigateToSection(nextSection.module, nextSection.section);
  };

  // Handle quiz completion
  const handleQuizComplete = (blockId: string, passed: boolean, score: number, maxScore: number) => {
    setQuizResults(prev => ({
      ...prev,
      [blockId]: { passed, score, maxScore }
    }));
  };

  // Render content block based on type
  const renderContentBlock = (block: ContentBlock, index: number) => {
    const key = block.id || `block-${index}`;

    switch (block.type) {
      case 'heading':
        const headingContent = block.content as any;
        const HeadingTag = `h${headingContent.level || 2}` as keyof JSX.IntrinsicElements;
        return (
          <HeadingTag key={key} className="text-gray-900 dark:text-white font-bold mb-4">
            {headingContent.text}
          </HeadingTag>
        );

      case 'text':
        const textContent = block.content as any;
        const textValue = textContent.text || textContent;
        // Use ReactMarkdown for markdown content, plain text otherwise
        if (textContent.markdown) {
          return (
            <div key={key} className="prose prose-slate dark:prose-invert max-w-none prose-headings:text-gray-900 dark:prose-headings:text-white prose-p:text-gray-700 dark:prose-p:text-gray-300 prose-strong:text-gray-900 dark:prose-strong:text-white prose-li:text-gray-700 dark:prose-li:text-gray-300">
              <ReactMarkdown>{textValue}</ReactMarkdown>
            </div>
          );
        }
        return (
          <p key={key} className="text-gray-700 dark:text-gray-300 leading-relaxed whitespace-pre-wrap">
            {textValue}
          </p>
        );

      case 'code':
        const codeContent = block.content as any;
        return (
          <pre key={key} className="bg-gray-900 dark:bg-gray-950 rounded-lg p-4 overflow-x-auto">
            <code className="text-green-400 text-sm font-mono">
              {codeContent.code || codeContent.text}
            </code>
          </pre>
        );

      case 'image':
        const imageContent = block.content as any;
        return (
          <img
            key={key}
            src={imageContent.url}
            alt={imageContent.alt || 'Content image'}
            className="rounded-lg max-w-full h-auto"
          />
        );

      case 'video':
        const videoContent = block.content as any;
        return (
          <div key={key} className="aspect-video bg-gray-100 dark:bg-gray-900 rounded-lg overflow-hidden">
            <iframe
              src={videoContent.url}
              title={videoContent.title || 'Video content'}
              className="w-full h-full"
              allowFullScreen
            />
          </div>
        );

      case 'callout':
        const calloutContent = block.content as any;
        const calloutStyles: Record<string, string> = {
          info: 'bg-blue-50 dark:bg-blue-500/10 border-blue-500 text-blue-700 dark:text-blue-300',
          warning: 'bg-yellow-50 dark:bg-yellow-500/10 border-yellow-500 text-yellow-700 dark:text-yellow-300',
          danger: 'bg-red-50 dark:bg-red-500/10 border-red-500 text-red-700 dark:text-red-300',
          success: 'bg-green-50 dark:bg-green-500/10 border-green-500 text-green-700 dark:text-green-300',
          tip: 'bg-purple-50 dark:bg-purple-500/10 border-purple-500 text-purple-700 dark:text-purple-300',
        };
        const calloutStyle = calloutStyles[calloutContent.style] || calloutStyles.info;
        return (
          <div key={key} className={`border-l-4 p-4 rounded ${calloutStyle}`}>
            {calloutContent.title && (
              <p className="font-semibold mb-1">{calloutContent.title}</p>
            )}
            <p>{calloutContent.text}</p>
          </div>
        );

      case 'divider':
        const dividerContent = block.content as any;
        const dividerStyles: Record<string, string> = {
          solid: 'border-gray-300 dark:border-gray-600',
          dashed: 'border-gray-300 dark:border-gray-600 border-dashed',
          thick: 'border-gray-400 dark:border-gray-500 border-2',
        };
        const dividerStyle = dividerStyles[dividerContent?.style] || dividerStyles.solid;
        return (
          <hr key={key} className={`my-8 border-t ${dividerStyle}`} />
        );

      case 'timeline':
        const timelineContent = block.content as any;
        const timelineItems = timelineContent?.items || [];
        return (
          <div key={key} className="relative pl-8 space-y-6 my-6">
            {/* Vertical line */}
            <div className="absolute left-3 top-2 bottom-2 w-0.5 bg-gradient-to-b from-blue-500 to-purple-500" />

            {timelineItems.map((item: any, idx: number) => (
              <div key={idx} className="relative">
                {/* Timeline dot */}
                <div className="absolute -left-5 w-4 h-4 bg-blue-500 rounded-full border-2 border-white dark:border-gray-800" />

                {/* Content */}
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                  <span className="text-sm font-semibold text-blue-600 dark:text-blue-400">
                    {item.year}
                  </span>
                  <h4 className="text-lg font-bold text-gray-900 dark:text-white mt-1">
                    {item.event}
                  </h4>
                  {item.description && (
                    <p className="text-gray-600 dark:text-gray-300 mt-2 text-sm">
                      {item.description}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        );

      case 'quiz':
        return (
          <QuizBlockPlayer
            key={key}
            blockId={key}
            content={block.content}
            onQuizComplete={handleQuizComplete}
          />
        );

      case 'interactive':
        const interactiveContent = block.content as any;
        return (
          <div key={key} className="bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-900/20 dark:to-blue-900/20 rounded-xl p-6 border border-purple-200 dark:border-purple-700 my-6">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-2xl">🎮</span>
              <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                Interactive Component
              </h3>
            </div>
            <p className="text-gray-600 dark:text-gray-300 text-sm">
              Component: <code className="bg-gray-200 dark:bg-gray-700 px-2 py-0.5 rounded">{interactiveContent?.component || 'Unknown'}</code>
            </p>
            {interactiveContent?.props && Object.keys(interactiveContent.props).length > 0 && (
              <pre className="mt-2 text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded overflow-x-auto">
                {JSON.stringify(interactiveContent.props, null, 2)}
              </pre>
            )}
            <p className="text-gray-500 dark:text-gray-400 text-xs mt-2 italic">
              Custom interactive components require specific implementation.
            </p>
          </div>
        );

      default:
        return (
          <div key={key} className="text-gray-500 dark:text-gray-400 italic">
            Unsupported content type: {block.type}
          </div>
        );
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-500 dark:text-gray-400">Loading course...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-6">
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500 rounded-lg p-6 max-w-md">
          <p className="text-red-600 dark:text-red-400 text-center">{error}</p>
          <button
            onClick={() => navigate('/courses')}
            className="mt-4 w-full px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
          >
            Back to Courses
          </button>
        </div>
      </div>
    );
  }

  // Course already complete - show completion summary
  if (courseWasAlreadyComplete && course) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/20 dark:from-slate-900 dark:via-slate-900 dark:to-slate-900 flex items-center justify-center p-6">
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="max-w-lg w-full"
        >
          {/* Certificate-style card */}
          <div className="bg-white dark:bg-slate-800 rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-700 shadow-xl">
            {/* Header banner */}
            <div className="bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 px-8 py-10 text-center relative overflow-hidden">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_50%,rgba(255,255,255,0.15),transparent_50%)]" />
              <div className="relative">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-white/20 backdrop-blur-sm mb-4">
                  <Award size={32} className="text-white" />
                </div>
                <h1 className="text-2xl font-bold text-white mb-1">Course Completed</h1>
                <p className="text-emerald-100 text-sm">{course.title}</p>
              </div>
            </div>

            <div className="px-8 py-6 space-y-5">
              {/* Progress indicator */}
              <div className="flex items-center gap-3 p-3 bg-emerald-50 dark:bg-emerald-500/10 rounded-xl border border-emerald-200 dark:border-emerald-500/20">
                <CheckCircle size={22} className="text-emerald-500 flex-shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-slate-700 dark:text-slate-200">All modules completed</span>
                    <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400">100%</span>
                  </div>
                  <div className="w-full h-1.5 bg-emerald-200 dark:bg-emerald-900/50 rounded-full">
                    <div className="h-full bg-emerald-500 rounded-full w-full" />
                  </div>
                </div>
              </div>

              {/* Certificate card */}
              <div className="p-4 bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-500/10 dark:to-indigo-500/10 rounded-xl border border-blue-200 dark:border-blue-500/20">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-gradient-to-br from-blue-500 to-indigo-500 rounded-lg shadow-sm">
                    <Award size={18} className="text-white" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-900 dark:text-white">Certificate Earned</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">View and share your certificate</p>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="space-y-2.5 pt-1">
                <button
                  onClick={() => navigate('/certifications')}
                  className="w-full px-5 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-xl font-semibold transition-all shadow-lg shadow-blue-500/25 flex items-center justify-center gap-2"
                >
                  <Award size={18} />
                  View My Certificate
                </button>

                <div className="grid grid-cols-2 gap-2.5">
                  <button
                    onClick={() => {
                      setCourseWasAlreadyComplete(false);
                      const sortedModules = course.modules?.sort((a, b) => a.order_index - b.order_index) || [];
                      if (sortedModules.length > 0) {
                        const firstModule = sortedModules[0];
                        const sortedSections = firstModule.sections?.sort((a, b) => a.order_index - b.order_index) || [];
                        if (sortedSections.length > 0) {
                          setCurrentModule(firstModule);
                          setCurrentSection(sortedSections[0]);
                        }
                      }
                    }}
                    className="px-4 py-2.5 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-xl font-medium transition-colors flex items-center justify-center gap-2 text-sm"
                  >
                    <BookOpen size={16} />
                    Review
                  </button>
                  <button
                    onClick={() => navigate('/courses')}
                    className="px-4 py-2.5 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-xl font-medium transition-colors text-sm"
                  >
                    More Courses
                  </button>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  // No content state
  if (!course || !currentModule || !currentSection) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center text-gray-500 dark:text-gray-400">
          <BookOpen size={64} className="mx-auto mb-4 opacity-50" />
          <p className="text-xl">Course content not available</p>
          <button
            onClick={() => navigate('/courses')}
            className="mt-4 px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors"
          >
            Back to Courses
          </button>
        </div>
      </div>
    );
  }

  const nextSection = getNextSection();
  const prevSection = getPreviousSection();
  const isCurrentComplete = completedSections.has(currentSection.id);
  const isLastSection = !nextSection;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex">
      {/* Completion Modal */}
      {showCompletionModal && completionData && (
        <div className="fixed inset-0 bg-black/60 dark:bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            transition={{ type: 'spring', stiffness: 200, damping: 25 }}
            className="bg-white dark:bg-slate-800 rounded-2xl max-w-md w-full overflow-hidden border border-slate-200 dark:border-slate-700 shadow-2xl"
          >
            {completionData.course_complete ? (
              <>
                {/* Course Complete Header */}
                <div className="bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 px-6 py-8 text-center relative overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_30%,rgba(255,255,255,0.2),transparent_50%)]" />
                  <div className="relative">
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
                      className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-white/20 backdrop-blur-sm mb-3"
                    >
                      <Award size={32} className="text-white" />
                    </motion.div>
                    <h2 className="text-2xl font-bold text-white mb-1">Course Complete!</h2>
                    <p className="text-emerald-100 text-sm">Congratulations on finishing the course</p>
                  </div>
                </div>

                <div className="px-6 py-5 space-y-4">
                  {/* Certificate section */}
                  {completionData.certificate ? (
                    <div className="p-4 bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-500/10 dark:to-indigo-500/10 rounded-xl border border-blue-200 dark:border-blue-500/20">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 bg-gradient-to-br from-blue-500 to-indigo-500 rounded-lg shadow-sm">
                          <Award size={18} className="text-white" />
                        </div>
                        <div>
                          <p className="text-sm font-semibold text-slate-900 dark:text-white">Certificate Earned</p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">{completionData.certificate.title}</p>
                        </div>
                      </div>

                      {completionData.certificate.verification_code && (
                        <div className="bg-white/80 dark:bg-slate-900/50 rounded-lg p-3 mb-3">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide font-medium">Verification Code</span>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(completionData.certificate.verification_code);
                                toast.success('Code copied!');
                              }}
                              className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 font-medium"
                            >
                              Copy
                            </button>
                          </div>
                          <p className="font-mono text-sm font-semibold text-blue-600 dark:text-blue-300 tracking-wider">
                            {completionData.certificate.verification_code}
                          </p>
                        </div>
                      )}

                      {completionData.certificate.skills_acquired?.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {completionData.certificate.skills_acquired.map((skill: string, idx: number) => (
                            <span key={idx} className="text-xs bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 px-2 py-0.5 rounded-full font-medium">
                              {skill}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-4 bg-gradient-to-br from-emerald-50 to-teal-50 dark:from-emerald-500/10 dark:to-teal-500/10 rounded-xl border border-emerald-200 dark:border-emerald-500/20 text-center">
                      <Award size={36} className="mx-auto mb-2 text-emerald-500" />
                      <p className="text-sm font-semibold text-slate-900 dark:text-white mb-1">Certificate Generated</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">View it anytime from your Certificates page</p>
                    </div>
                  )}

                  {completionData.achievement_awarded && (
                    <div className="flex items-center gap-3 p-3 bg-purple-50 dark:bg-purple-500/10 rounded-xl border border-purple-200 dark:border-purple-500/20">
                      <div className="p-1.5 bg-purple-500 rounded-lg">
                        <Medal size={16} className="text-white" />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-purple-700 dark:text-purple-300">Achievement Unlocked!</p>
                        <p className="text-xs text-purple-500 dark:text-purple-400">Check your achievements page</p>
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="space-y-2 pt-1">
                    <button
                      onClick={() => navigate('/certifications')}
                      className="w-full px-4 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-xl font-semibold transition-all shadow-lg shadow-blue-500/25 flex items-center justify-center gap-2"
                    >
                      <Award size={18} />
                      View My Certificate
                    </button>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => {
                          setShowCompletionModal(false);
                          setCourseJustCompleted(true);
                        }}
                        className="px-4 py-2.5 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-xl font-medium transition-colors text-sm"
                      >
                        Review Course
                      </button>
                      <button
                        onClick={() => navigate('/courses')}
                        className="px-4 py-2.5 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-xl font-medium transition-colors text-sm"
                      >
                        More Courses
                      </button>
                    </div>
                  </div>
                </div>
              </>
            ) : completionData.module_completed ? (
              <>
                {/* Module Complete Header */}
                <div className="bg-gradient-to-r from-blue-500 to-indigo-500 px-6 py-6 text-center relative overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_50%,rgba(255,255,255,0.15),transparent_50%)]" />
                  <div className="relative">
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
                      className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-white/20 backdrop-blur-sm mb-2"
                    >
                      <Medal size={24} className="text-white" />
                    </motion.div>
                    <h2 className="text-xl font-bold text-white">Module Complete!</h2>
                  </div>
                </div>
                <div className="px-6 py-5">
                  <p className="text-slate-600 dark:text-slate-300 text-sm text-center mb-4">
                    Great work completing this module. {nextSection ? 'Ready for the next one?' : ''}
                  </p>
                  <button
                    onClick={() => {
                      setShowCompletionModal(false);
                      if (nextSection) {
                        navigateToSection(nextSection.module, nextSection.section);
                      }
                    }}
                    className="w-full px-4 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-xl font-semibold transition-all shadow-lg shadow-blue-500/25 flex items-center justify-center gap-2"
                  >
                    {nextSection ? 'Continue to Next Module' : 'Close'}
                    <ChevronRight size={18} />
                  </button>
                </div>
              </>
            ) : null}
          </motion.div>
        </div>
      )}

      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? 'w-80' : 'w-0'
        } bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 transition-all duration-300 overflow-hidden flex-shrink-0`}
      >
        <div className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-bold text-gray-900 dark:text-white truncate">{course.title}</h2>
            <button
              onClick={() => setSidebarOpen(false)}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-white lg:hidden"
            >
              <X size={20} />
            </button>
          </div>

          {/* Course Completed Banner */}
          {courseJustCompleted && (
            <div className="mb-4 p-3 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/30 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <CheckCircle size={16} className="text-green-600 dark:text-green-400" />
                <span className="text-green-700 dark:text-green-400 font-semibold text-sm">Course Completed</span>
              </div>
              <button
                onClick={() => navigate('/certifications')}
                className="text-xs text-green-600 dark:text-green-400 hover:text-green-700 dark:hover:text-green-300 underline"
              >
                View Certificate
              </button>
            </div>
          )}

          {/* Module & Section Navigation */}
          <div className="space-y-4">
            {course.modules?.sort((a, b) => a.order_index - b.order_index).map((module, moduleIdx) => (
              <div key={module.id} className="bg-gray-100 dark:bg-gray-700/30 rounded-lg p-3">
                <div className="text-gray-900 dark:text-white font-semibold mb-2">
                  Module {moduleIdx + 1}: {module.title}
                </div>
                <div className="space-y-1">
                  {module.sections?.sort((a, b) => a.order_index - b.order_index).map((section, sectionIdx) => {
                    const isActive = currentSection?.id === section.id;
                    const isComplete = completedSections.has(section.id);
                    const nextAvailable = getNextSection();
                    const isNextAvailable = nextAvailable?.module.id === module.id && nextAvailable?.section.id === section.id;
                    const canAccess = isComplete || isActive || isNextAvailable;

                    return (
                      <button
                        key={section.id}
                        onClick={() => canAccess && navigateToSection(module, section)}
                        disabled={!canAccess}
                        className={`w-full text-left px-3 py-2 rounded text-sm transition-colors flex items-center gap-2 ${
                          isActive
                            ? 'bg-blue-500 text-white'
                            : canAccess
                            ? 'text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-700/50'
                            : 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                        }`}
                      >
                        {isComplete ? (
                          <CheckCircle size={14} className="text-green-500 flex-shrink-0" />
                        ) : (
                          <span className={`w-3.5 h-3.5 rounded-full border flex-shrink-0 ${canAccess ? 'border-gray-400' : 'border-gray-300 dark:border-gray-700'}`} />
                        )}
                        <span className="truncate">{section.title}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* Exit Button */}
          <button
            onClick={() => navigate(`/courses/${courseId}`)}
            className="w-full mt-6 px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors"
          >
            Exit Course
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-4xl mx-auto p-6 lg:p-12">
          {/* Mobile Sidebar Toggle */}
          {!sidebarOpen && (
            <button
              onClick={() => setSidebarOpen(true)}
              className="mb-6 lg:hidden flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors border border-gray-200 dark:border-gray-700"
            >
              <Menu size={20} />
              Course Menu
            </button>
          )}

          {/* Section Content */}
          {currentSection.content_blocks && currentSection.content_blocks.length > 0 ? (
            <motion.div
              key={currentSection.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white dark:bg-gray-800/50 rounded-2xl p-8 lg:p-12 border border-gray-200 dark:border-gray-700 shadow-sm"
            >
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-6">{currentSection.title}</h1>

              {/* Render Content Blocks */}
              <div className="space-y-6">
                {currentSection.content_blocks
                  ?.sort((a, b) => a.order - b.order)
                  .map((block, idx) => renderContentBlock(block, idx))}
              </div>

              {/* Mark Complete Button */}
              {!isCurrentComplete && (
                <button
                  onClick={markSectionComplete}
                  className="mt-8 px-6 py-3 bg-green-500 hover:bg-green-600 text-white rounded-lg font-semibold transition-colors flex items-center gap-2"
                >
                  <CheckCircle size={18} />
                  Mark as Complete
                </button>
              )}

              {/* Show completion message if at end and complete */}
              {isLastSection && isCurrentComplete && (
                guestMode ? (
                  <div className="mt-8 p-6 bg-gradient-to-br from-amber-50 to-orange-50 dark:from-amber-500/10 dark:to-orange-500/10 border border-amber-200 dark:border-amber-500 rounded-xl">
                    <div className="flex items-center gap-3 mb-3">
                      <BookOpen size={28} className="text-amber-600 dark:text-amber-400" />
                      <h3 className="text-amber-700 dark:text-amber-400 font-bold text-lg">You've reached the end!</h3>
                    </div>
                    <p className="text-gray-600 dark:text-gray-300 mb-2">
                      You've browsed through all sections of this course as a guest.
                    </p>
                    <p className="text-gray-500 dark:text-gray-400 text-sm mb-4">
                      No progress has been saved. To earn XP, receive a certificate, and track your learning, create a free account.
                    </p>
                    <div className="flex gap-3">
                      <button
                        onClick={() => navigate('/register')}
                        className="px-4 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-lg font-semibold transition-colors"
                      >
                        Sign Up Free
                      </button>
                      <button
                        onClick={() => navigate('/courses')}
                        className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors"
                      >
                        Browse More Courses
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="mt-8 p-6 bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-500/10 dark:to-emerald-500/10 border border-green-200 dark:border-green-500 rounded-xl">
                    <div className="flex items-center gap-3 mb-3">
                      <Award size={28} className="text-green-600 dark:text-green-400" />
                      <h3 className="text-green-700 dark:text-green-400 font-bold text-lg">Course Complete!</h3>
                    </div>
                    <p className="text-gray-600 dark:text-gray-300 mb-2">
                      You've completed all sections of this course.
                    </p>
                    {(earnedCertificate || courseJustCompleted) && (
                      <p className="text-gray-500 dark:text-gray-400 text-sm mb-4">
                        Your certificate has been generated. You can view it anytime from your Dashboard.
                      </p>
                    )}
                    <div className="flex gap-3">
                      <button
                        onClick={() => navigate('/certifications')}
                        className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-semibold transition-colors flex items-center gap-2"
                      >
                        <Award size={16} />
                        View Certificate
                      </button>
                      <button
                        onClick={() => navigate('/dashboard')}
                        className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors"
                      >
                        Go to Dashboard
                      </button>
                    </div>
                  </div>
                )
              )}
            </motion.div>
          ) : (
            <div className="bg-white dark:bg-gray-800/50 rounded-2xl p-8 border border-gray-200 dark:border-gray-700 text-center text-gray-500 dark:text-gray-400">
              <BookOpen size={48} className="mx-auto mb-4 opacity-50" />
              <p>No content available</p>
            </div>
          )}

          {/* Navigation Buttons */}
          <div className="flex justify-between mt-8">
            <button
              onClick={() => prevSection && navigateToSection(prevSection.module, prevSection.section)}
              disabled={!prevSection}
              className="px-6 py-3 bg-white dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed border border-gray-200 dark:border-gray-700"
            >
              <ChevronLeft size={18} />
              Previous
            </button>

            <button
              onClick={handleNext}
              disabled={!isCurrentComplete && !isLastSection}
              className="px-6 py-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLastSection ? 'Finish Course' : 'Next'}
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      </main>
    </div>
  );
};

export default CoursePlayer;
