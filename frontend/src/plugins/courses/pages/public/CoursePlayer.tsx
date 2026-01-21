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
import { coursesApi } from '../../services/coursesApi';
import type { Course as CourseDetail, CourseModule, ModuleSection, ContentBlock } from '../../types';

// Placeholder hooks until XP notification system is implemented
const useXPNotification = () => ({ showXPGain: (_xp: number, _reason: string) => {} });
const useAchievementNotification = () => ({ showAchievementUnlock: (_achievement: any) => {} });

const CoursePlayer: React.FC = () => {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();
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

          // Track if course was already complete (to prevent showing completion modal again)
          if (progressData.is_complete) {
            setCourseWasAlreadyComplete(true);
            console.log('[CoursePlayer] Course already complete - will not show completion modal');
          }

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
      alert('Please complete the previous sections in order before accessing this one.');
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
      if (result.course_complete && resultAny.xp_gains && resultAny.xp_gains.length > 0) {
        showXPGain(resultAny.total_xp_gained || 0, 'Course completed');

        // Show achievement notifications if any were unlocked
        resultAny.xp_gains.forEach((xpGain: any) => {
          if (xpGain.achievements_unlocked && xpGain.achievements_unlocked.length > 0) {
            xpGain.achievements_unlocked.forEach((achievement: any) => {
              showAchievementUnlock(achievement);
            });
          }
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
          certificate: resultAny.certificate,
          certificate_id: resultAny.certificate_id
        });
        setCompletionData(result);
        setShowCompletionModal(true);
      } else if (courseWasAlreadyComplete) {
        console.log('[CoursePlayer] Skipping completion modal - course already complete');
      }
    } catch (err: any) {
      console.error('Error marking section complete:', err);
      alert('Failed to save progress. Please try again.');

      // Rollback optimistic update on error
      setCompletedSections(prev => {
        const newSet = new Set(prev);
        newSet.delete(currentSection.id);
        return newSet;
      });
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
        // Already marked complete, course should be complete
        alert('Course Complete! Check your dashboard for your certificate and achievements.');
        setTimeout(() => navigate('/dashboard'), 1000);
      } else {
        alert('Please mark this section as complete to finish the course.');
      }
      return;
    }

    // Check if current section is complete before allowing navigation
    if (!completedSections.has(currentSection!.id)) {
      alert('Please mark the current section as complete before moving to the next one.');
      return;
    }

    // Navigate to next section
    navigateToSection(nextSection.module, nextSection.section);
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
        return (
          <p key={key} className="text-gray-700 dark:text-gray-300 leading-relaxed whitespace-pre-wrap">
            {textContent.text || textContent}
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
        const quizContent = block.content as any;
        const quizQuestions = quizContent?.questions || [];
        return (
          <div key={key} className="bg-gray-50 dark:bg-gray-800 rounded-xl p-6 border border-gray-200 dark:border-gray-700 my-6">
            {quizContent.title && (
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <span className="text-2xl">📝</span>
                {quizContent.title}
              </h3>
            )}

            <div className="space-y-6">
              {quizQuestions.map((question: any, qIdx: number) => (
                <div key={question.id || qIdx} className="bg-white dark:bg-gray-900 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                  <p className="font-medium text-gray-900 dark:text-white mb-3">
                    <span className="text-blue-600 dark:text-blue-400 mr-2">Q{qIdx + 1}.</span>
                    {question.question}
                  </p>

                  {/* Multiple choice / Multiple select / True-False options */}
                  {(question.type === 'multiple_choice' || question.type === 'multiple_select' || question.type === 'true_false') && question.options && (
                    <div className="space-y-2 ml-6">
                      {question.options.map((option: string, oIdx: number) => (
                        <label key={oIdx} className="flex items-center gap-3 p-2 rounded hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer">
                          <input
                            type={question.type === 'multiple_select' ? 'checkbox' : 'radio'}
                            name={`quiz-${key}-q${qIdx}`}
                            className="w-4 h-4 text-blue-600"
                          />
                          <span className="text-gray-700 dark:text-gray-300">{option}</span>
                        </label>
                      ))}
                    </div>
                  )}

                  {/* Short answer / Fill blank */}
                  {(question.type === 'short_answer' || question.type === 'fill_blank') && (
                    <div className="ml-6">
                      <input
                        type="text"
                        placeholder="Type your answer..."
                        className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                      />
                    </div>
                  )}

                  {/* Code challenge */}
                  {question.type === 'code_challenge' && (
                    <div className="ml-6">
                      <textarea
                        rows={4}
                        placeholder={question.code_template || '// Write your code here...'}
                        className="w-full p-3 font-mono text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-900 text-green-400"
                      />
                    </div>
                  )}

                  {/* Points indicator */}
                  {question.points && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-2 ml-6">
                      {question.points} point{question.points !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
              ))}
            </div>

            {quizQuestions.length > 0 && (
              <div className="mt-4 flex justify-end">
                <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors">
                  Check Answers
                </button>
              </div>
            )}
          </div>
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
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-6">
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="bg-white dark:bg-gray-800 rounded-2xl p-8 max-w-2xl w-full border border-gray-200 dark:border-gray-700 shadow-lg"
        >
          <div className="text-center mb-8">
            <Award size={80} className="mx-auto mb-4 text-yellow-500" />
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-3">
              Course Completed!
            </h1>
            <p className="text-gray-600 dark:text-gray-300 text-lg">
              You've already completed <span className="text-blue-600 dark:text-blue-400 font-semibold">{course.title}</span>
            </p>
          </div>

          <div className="space-y-4 mb-8">
            <div className="bg-gray-100 dark:bg-gray-700/50 rounded-lg p-4 flex items-center gap-4">
              <CheckCircle size={40} className="text-green-500 flex-shrink-0" />
              <div>
                <p className="text-gray-900 dark:text-white font-semibold">Course Progress</p>
                <p className="text-gray-500 dark:text-gray-400 text-sm">100% Complete - All modules finished</p>
              </div>
            </div>

            <div className="bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-600/20 dark:to-purple-600/20 border-2 border-blue-300 dark:border-blue-500 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-2">
                <div className="bg-gradient-to-r from-blue-500 to-purple-500 rounded-full p-2">
                  <Award size={24} className="text-white" />
                </div>
                <p className="text-gray-900 dark:text-white font-bold text-lg">Certificate Available</p>
              </div>
              <p className="text-gray-600 dark:text-gray-300 text-sm">
                Your certificate of completion is ready to view and share
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <button
              onClick={() => navigate('/certifications')}
              className="w-full px-6 py-4 bg-gradient-to-r from-blue-500 to-indigo-500 hover:from-blue-600 hover:to-indigo-600 text-white rounded-lg font-semibold transition-colors shadow-lg flex items-center justify-center gap-2 text-lg"
            >
              <Award size={22} />
              View My Certificate
            </button>

            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => {
                  // Allow reviewing by clearing the complete flag temporarily
                  setCourseWasAlreadyComplete(false);
                  // Start from first module, first section
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
                className="px-4 py-3 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors flex items-center justify-center gap-2"
              >
                <BookOpen size={18} />
                Review Course
              </button>

              <button
                onClick={() => navigate('/dashboard')}
                className="px-4 py-3 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors"
              >
                Go to Dashboard
              </button>
            </div>

            <button
              onClick={() => navigate('/courses')}
              className="w-full px-4 py-3 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-300 rounded-lg transition-colors"
            >
              Browse More Courses
            </button>
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
        <div className="fixed inset-0 bg-black/50 dark:bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-white dark:bg-gray-800 rounded-2xl p-8 max-w-md w-full border border-gray-200 dark:border-gray-700 shadow-xl"
          >
            <div className="text-center">
              {completionData.course_complete ? (
                <>
                  <Award size={64} className="mx-auto mb-4 text-yellow-500 animate-bounce" />
                  <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-3">
                    Course Complete!
                  </h2>
                  <p className="text-gray-600 dark:text-gray-300 mb-4">
                    Congratulations! You've completed the entire course!
                  </p>

                  {/* Certificate Display */}
                  <div className="space-y-3 mb-6">
                    {completionData.certificate ? (
                      <div className="bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-600/20 dark:to-purple-600/20 border-2 border-blue-300 dark:border-blue-500 rounded-xl p-5">
                        <div className="flex items-start gap-3 mb-3">
                          <div className="bg-gradient-to-r from-blue-500 to-purple-500 rounded-full p-2.5">
                            <Award size={24} className="text-white" />
                          </div>
                          <div className="text-left flex-1">
                            <p className="text-gray-900 dark:text-white font-bold text-lg mb-1">
                              {completionData.certificate.title}
                            </p>
                            <p className="text-gray-600 dark:text-gray-300 text-sm">
                              {completionData.certificate.description}
                            </p>
                          </div>
                        </div>

                        {/* Verification Code */}
                        {completionData.certificate?.verification_code && (
                          <div className="bg-gray-100 dark:bg-black/40 rounded-lg p-3 mb-3">
                            <div className="flex items-center justify-between mb-1">
                              <p className="text-gray-500 dark:text-gray-400 text-xs">Verification Code</p>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(completionData.certificate.verification_code);
                                  alert('Verification code copied!');
                                }}
                                className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs"
                              >
                                Copy
                              </button>
                            </div>
                            <p className="text-blue-600 dark:text-blue-300 font-mono text-sm font-semibold tracking-wide break-all">
                              {completionData.certificate.verification_code}
                            </p>
                          </div>
                        )}

                        {/* Fallback if no certificate object */}
                        {!completionData.certificate && completionData.certificate_id && (
                          <div className="bg-blue-50 dark:bg-blue-500/20 border border-blue-200 dark:border-blue-500 rounded-lg p-3 mb-3 text-center">
                            <p className="text-blue-700 dark:text-blue-300 text-sm">
                              Certificate ID: {completionData.certificate_id}
                            </p>
                            <p className="text-gray-500 dark:text-gray-400 text-xs mt-1">
                              View full details in your certificates page
                            </p>
                          </div>
                        )}

                        {/* Skills */}
                        {completionData.certificate.skills_acquired && completionData.certificate.skills_acquired.length > 0 && (
                          <div className="flex flex-wrap gap-2">
                            {completionData.certificate.skills_acquired.map((skill: string, idx: number) => (
                              <span
                                key={idx}
                                className="bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 text-xs px-2.5 py-1 rounded-full font-medium"
                              >
                                {skill}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : completionData.certificate_id ? (
                      <div className="bg-yellow-50 dark:bg-yellow-500/20 border-2 border-yellow-300 dark:border-yellow-500 rounded-xl p-5 text-center">
                        <Award size={48} className="mx-auto mb-3 text-yellow-500" />
                        <p className="text-gray-900 dark:text-white font-bold mb-2">Certificate Earned!</p>
                        <p className="text-gray-600 dark:text-gray-300 text-sm mb-3">
                          Your certificate has been generated and saved
                        </p>
                        <p className="text-yellow-600 dark:text-yellow-400 text-xs font-mono bg-yellow-100 dark:bg-black/40 rounded p-2 mb-3">
                          ID: {completionData.certificate_id}
                        </p>
                        <p className="text-gray-500 dark:text-gray-400 text-xs">
                          View full details in your Certificates page
                        </p>
                      </div>
                    ) : (
                      <div className="bg-blue-50 dark:bg-blue-500/20 border border-blue-200 dark:border-blue-400 rounded-xl p-4 text-center">
                        <p className="text-blue-700 dark:text-blue-300 text-sm">
                          Certificate will be available in your profile shortly
                        </p>
                      </div>
                    )}

                    {completionData.achievement_awarded && (
                      <div className="bg-gradient-to-r from-purple-50 to-pink-50 dark:from-purple-500/20 dark:to-pink-500/20 border border-purple-200 dark:border-purple-500 rounded-lg p-4">
                        <div className="flex items-center gap-3">
                          <div className="bg-purple-500 rounded-full p-2">
                            <Medal size={20} className="text-white" />
                          </div>
                          <div className="text-left">
                            <p className="text-purple-700 dark:text-purple-300 font-semibold">Achievement Unlocked!</p>
                            <p className="text-purple-600 dark:text-purple-200 text-sm">Check your achievements</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col gap-3">
                    <button
                      onClick={() => navigate('/dashboard')}
                      className="w-full px-4 py-3 bg-gradient-to-r from-blue-500 to-indigo-500 hover:from-blue-600 hover:to-indigo-600 text-white rounded-lg font-semibold transition-colors shadow-lg"
                    >
                      Go to Dashboard
                    </button>
                    <div className="flex gap-3">
                      {completionData.certificate && (
                        <button
                          onClick={() => navigate('/certifications')}
                          className="flex-1 px-4 py-3 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors flex items-center justify-center gap-2"
                        >
                          <Award size={18} />
                          View Certificates
                        </button>
                      )}
                      <button
                        onClick={() => setShowCompletionModal(false)}
                        className="flex-1 px-4 py-3 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold transition-colors"
                      >
                        Review Course
                      </button>
                    </div>
                  </div>
                </>
              ) : completionData.module_completed ? (
                <>
                  <Medal size={64} className="mx-auto mb-4 text-green-500" />
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                    Module Complete!
                  </h2>
                  <p className="text-gray-600 dark:text-gray-300 mb-4">
                    Great job! You've finished this module.
                  </p>
                  <button
                    onClick={() => {
                      setShowCompletionModal(false);
                      if (nextSection) {
                        navigateToSection(nextSection.module, nextSection.section);
                      }
                    }}
                    className="w-full px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold transition-colors"
                  >
                    {nextSection ? 'Continue to Next Module' : 'Close'}
                  </button>
                </>
              ) : null}
            </div>
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
                <div className="mt-8 p-6 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500 rounded-lg">
                  <h3 className="text-green-700 dark:text-green-400 font-semibold mb-2">Course Complete!</h3>
                  <p className="text-gray-600 dark:text-gray-300 mb-4">
                    You've completed all sections. Check your dashboard for your certificate!
                  </p>
                  <button
                    onClick={() => navigate('/dashboard')}
                    className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg font-semibold transition-colors"
                  >
                    Go to Dashboard
                  </button>
                </div>
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
