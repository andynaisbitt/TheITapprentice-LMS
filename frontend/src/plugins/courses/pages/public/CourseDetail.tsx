// src/pages/courses/CourseDetail.tsx
/**
 * Course Detail Page - Backend Connected
 * Shows detailed course information and enrollment options
 * Includes registration prompt for unauthenticated users
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  BookOpen,
  Clock,
  Users,
  Star,
  CheckCircle,
  PlayCircle,
  Award,
  Target,
  TrendingUp,
  Zap,
  Lock,
  ChevronRight,
  Calendar,
  BarChart
} from 'lucide-react';
import { coursesApi } from '../../services/coursesApi';
import { Course, CourseModule } from '../../types';
import { useAuth } from '../../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../../hooks/useRegistrationPrompt';
import { useToast } from '../../../../components/ui/Toast';

const CourseDetail: React.FC = () => {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated } = useAuth();
  const { toast } = useToast();
  const [course, setCourse] = useState<Course | null>(null);
  const [isEnrolled, setIsEnrolled] = useState(false);
  const [isCompleted, setIsCompleted] = useState(false);
  const [progressPercent, setProgressPercent] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enrolling, setEnrolling] = useState(false);

  // Registration prompt for unauthenticated users
  const {
    isPromptOpen,
    closePrompt,
    handleSkip,
    checkAuthAndProceed,
  } = useRegistrationPrompt({
    context: 'course',
    onSkip: () => {
      // User chose to continue without registration - navigate to course preview/player
      navigate(`/courses/${courseId}/learn`);
    },
  });

  // Fetch course details
  useEffect(() => {
    const fetchCourse = async () => {
      if (!courseId) return;

      try {
        setIsLoading(true);
        setError(null);

        const courseData = await coursesApi.getCourse(courseId);
        setCourse(courseData);

        // Check if user is enrolled and get progress
        try {
          const myEnrollments = await coursesApi.getMyCourses();
          const enrolled = myEnrollments.some((c: Course) => c.id === courseId);
          setIsEnrolled(enrolled);

          // If enrolled, fetch progress to check completion status
          if (enrolled) {
            try {
              const progress = await coursesApi.getProgress(courseId);
              setIsCompleted(progress.is_complete);
              setProgressPercent(progress.overall_progress);
            } catch (progressErr) {
              console.log('Could not fetch progress:', progressErr);
            }
          }
        } catch (enrollErr) {
          // User not authenticated, that's okay
          console.log('User not authenticated');
        }
      } catch (err: any) {
        console.error('Error fetching course:', err);
        setError('Failed to load course. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchCourse();
  }, [courseId, location.key]);

  // Handle enrollment - shows registration prompt if not authenticated
  const handleEnroll = async () => {
    if (!courseId) return;

    // Check if user is authenticated - if not, show registration prompt
    if (!checkAuthAndProceed()) {
      return; // Prompt is now showing
    }

    // User is authenticated, proceed with enrollment
    try {
      setEnrolling(true);
      await coursesApi.enrollInCourse({ course_id: courseId });
      setIsEnrolled(true);
      // Navigate to course player
      navigate(`/courses/${courseId}/learn`);
    } catch (err: any) {
      console.error('Error enrolling:', err);
      if (err.response?.status === 401) {
        // Session expired - show registration prompt
        checkAuthAndProceed();
      } else if (err.response?.status === 400 && err.response?.data?.detail?.toLowerCase().includes('already enrolled')) {
        // Already enrolled - just navigate to the course
        setIsEnrolled(true);
        navigate(`/courses/${courseId}/learn`);
      } else {
        const errorMsg = err.response?.data?.detail || 'Failed to enroll. Please try again.';
        toast.error(errorMsg);
      }
    } finally {
      setEnrolling(false);
    }
  };

  // Handle starting course without enrollment (preview/guest mode)
  const handleStartPreview = () => {
    if (!courseId) return;

    // Check if user wants to register for tracking
    if (!checkAuthAndProceed()) {
      return; // Prompt is now showing, will navigate on skip
    }

    // Authenticated user - enroll and start
    handleEnroll();
  };

  // Get level badge styling
  const getLevelColor = () => {
    if (!course) return '';
    switch (course.level) {
      case 'beginner': return 'bg-green-100 dark:bg-green-500/20 text-green-700 dark:text-green-400 border-green-300 dark:border-green-500/30';
      case 'intermediate': return 'bg-yellow-100 dark:bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border-yellow-300 dark:border-yellow-500/30';
      case 'advanced': return 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400 border-red-300 dark:border-red-500/30';
      default: return 'bg-gray-100 dark:bg-gray-500/20 text-gray-700 dark:text-gray-400 border-gray-300 dark:border-gray-500/30';
    }
  };

  const getLevelIcon = () => {
    if (!course) return <BookOpen size={16} />;
    switch (course.level) {
      case 'beginner': return <Target size={16} />;
      case 'intermediate': return <TrendingUp size={16} />;
      case 'advanced': return <Zap size={16} />;
      default: return <BookOpen size={16} />;
    }
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-500 dark:text-gray-400">Loading course...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error || !course) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center max-w-md">
          <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-2xl p-8">
            <p className="text-red-600 dark:text-red-400 mb-4">{error || 'Course not found'}</p>
            <button
              onClick={() => navigate('/courses')}
              className="px-6 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              Back to Courses
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 py-12">

        {/* Back Button */}
        <button
          onClick={() => navigate('/courses')}
          className="mb-6 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors flex items-center gap-2"
        >
          ← Back to Courses
        </button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            {/* Course Header */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white dark:bg-gray-800/50 shadow-lg dark:shadow-none rounded-2xl p-8 border border-gray-200 dark:border-gray-700/50"
            >
              {/* Level Badge */}
              <div className="flex items-center gap-3 mb-4">
                <span className={`px-3 py-1 rounded-full text-sm font-medium border flex items-center gap-2 ${getLevelColor()}`}>
                  {getLevelIcon()}
                  {course.level}
                </span>
                {course.is_premium && (
                  <span className="px-3 py-1 rounded-full text-sm font-medium bg-yellow-100 dark:bg-yellow-500/20 text-yellow-700 dark:text-yellow-400 border border-yellow-300 dark:border-yellow-500/30 flex items-center gap-1">
                    <Star size={14} />
                    Premium
                  </span>
                )}
                {course.is_featured && (
                  <span className="px-3 py-1 rounded-full text-sm font-medium bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-400 border border-purple-300 dark:border-purple-500/30">
                    Featured
                  </span>
                )}
                {isCompleted && (
                  <span className="px-3 py-1 rounded-full text-sm font-medium bg-green-100 dark:bg-green-500/20 text-green-700 dark:text-green-400 border border-green-300 dark:border-green-500/30 flex items-center gap-1">
                    <CheckCircle size={14} />
                    Completed
                  </span>
                )}
              </div>

              <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">{course.title}</h1>
              <p className="text-xl text-gray-600 dark:text-gray-300 mb-6">{course.short_description || course.description}</p>

              {/* Stats */}
              <div className="flex flex-wrap gap-6 text-gray-500 dark:text-gray-400">
                <div className="flex items-center gap-2">
                  <Clock size={18} className="text-blue-500 dark:text-blue-400" />
                  <span>{course.estimated_hours} hours</span>
                </div>
                <div className="flex items-center gap-2">
                  <Users size={18} className="text-purple-500 dark:text-purple-400" />
                  <span>{course.enrollment_count} enrolled</span>
                </div>
                {course.completion_count > 0 && (
                  <div className="flex items-center gap-2">
                    <Award size={18} className="text-green-500 dark:text-green-400" />
                    <span>{course.completion_count} completed</span>
                  </div>
                )}
              </div>
            </motion.div>

            {/* Course Description */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="bg-white dark:bg-gray-800/50 shadow-lg dark:shadow-none rounded-2xl p-8 border border-gray-200 dark:border-gray-700/50"
            >
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">About This Course</h2>
              <p className="text-gray-600 dark:text-gray-300 leading-relaxed whitespace-pre-line">{course.description}</p>
            </motion.div>

            {/* Learning Objectives */}
            {course.objectives && course.objectives.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="bg-white dark:bg-gray-800/50 shadow-lg dark:shadow-none rounded-2xl p-8 border border-gray-200 dark:border-gray-700/50"
              >
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">What You'll Learn</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {course.objectives.map((objective, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <CheckCircle size={18} className="text-green-500 dark:text-green-400 flex-shrink-0 mt-1" />
                      <span className="text-gray-700 dark:text-gray-300">{objective}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}

            {/* Course Modules */}
            {course.modules && course.modules.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="bg-white dark:bg-gray-800/50 shadow-lg dark:shadow-none rounded-2xl p-8 border border-gray-200 dark:border-gray-700/50"
              >
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Course Content</h2>
                <div className="space-y-3">
                  {course.modules
                    .sort((a, b) => a.order_index - b.order_index)
                    .map((module, idx) => (
                      <div
                        key={module.id}
                        className="bg-gray-50 dark:bg-gray-700/30 rounded-xl p-4 border border-gray-200 dark:border-gray-600/50 hover:border-blue-400 dark:hover:border-blue-500/50 transition-colors"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <span className="text-blue-600 dark:text-blue-400 font-semibold">Module {idx + 1}</span>
                              {module.duration && (
                                <span className="text-gray-500 dark:text-gray-400 text-sm flex items-center gap-1">
                                  <Clock size={14} />
                                  {module.duration}
                                </span>
                              )}
                            </div>
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">{module.title}</h3>
                            {module.description && (
                              <p className="text-gray-500 dark:text-gray-400 text-sm">{module.description}</p>
                            )}
                            {module.sections && module.sections.length > 0 && (
                              <div className="mt-3 text-sm text-gray-500 dark:text-gray-400">
                                {module.sections.length} sections
                              </div>
                            )}
                          </div>
                          {!isEnrolled && module.status === 'locked' && (
                            <Lock size={20} className="text-gray-400 dark:text-gray-500" />
                          )}
                        </div>
                      </div>
                    ))}
                </div>
              </motion.div>
            )}

            {/* Requirements */}
            {course.requirements && course.requirements.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="bg-white dark:bg-gray-800/50 shadow-lg dark:shadow-none rounded-2xl p-8 border border-gray-200 dark:border-gray-700/50"
              >
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Requirements</h2>
                <ul className="space-y-2">
                  {course.requirements.map((req, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-gray-700 dark:text-gray-300">
                      <span className="text-blue-600 dark:text-blue-400">•</span>
                      <span>{req}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="bg-white dark:bg-gray-800/50 shadow-lg dark:shadow-none rounded-2xl p-6 border border-gray-200 dark:border-gray-700/50 sticky top-6"
            >
              {/* Course Image */}
              {course.image && (
                <img
                  src={course.image}
                  alt={course.title}
                  className="w-full h-48 object-cover rounded-xl mb-6"
                />
              )}

              {/* Enroll Button */}
              {!isEnrolled ? (
                <button
                  onClick={handleEnroll}
                  disabled={enrolling}
                  className="w-full px-6 py-4 bg-gradient-to-r from-blue-500 to-purple-500
                           text-white font-bold rounded-xl hover:from-blue-600 hover:to-purple-600
                           transition-all flex items-center justify-center gap-2 mb-4 disabled:opacity-50"
                >
                  <PlayCircle size={20} />
                  {enrolling ? 'Enrolling...' : course.is_premium ? `Enroll for $${course.price}` : 'Enroll Now'}
                </button>
              ) : isCompleted ? (
                <>
                  <button
                    onClick={() => navigate(`/courses/${courseId}/learn`)}
                    className="w-full px-6 py-4 bg-gradient-to-r from-green-500 to-emerald-500
                             text-white font-bold rounded-xl hover:from-green-600 hover:to-emerald-600
                             transition-all flex items-center justify-center gap-2 mb-2"
                  >
                    <CheckCircle size={20} />
                    Review Course
                  </button>
                  <button
                    onClick={() => navigate('/certifications')}
                    className="w-full px-4 py-3 bg-yellow-50 dark:bg-yellow-500/10 border border-yellow-200 dark:border-yellow-500/30
                             text-yellow-700 dark:text-yellow-400 font-medium rounded-xl hover:bg-yellow-100 dark:hover:bg-yellow-500/20
                             transition-all flex items-center justify-center gap-2 mb-4"
                  >
                    <Award size={18} />
                    View Certificate
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => navigate(`/courses/${courseId}/learn`)}
                    className="w-full px-6 py-4 bg-gradient-to-r from-blue-500 to-indigo-500
                             text-white font-bold rounded-xl hover:from-blue-600 hover:to-indigo-600
                             transition-all flex items-center justify-center gap-2 mb-2"
                  >
                    <PlayCircle size={20} />
                    Continue Learning
                  </button>
                  {progressPercent > 0 && (
                    <div className="mb-4">
                      <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
                        <span>Progress</span>
                        <span>{progressPercent}%</span>
                      </div>
                      <div className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full transition-all"
                          style={{ width: `${progressPercent}%` }}
                        />
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* Course Info */}
              <div className="space-y-4 text-sm">
                {course.instructor_name && (
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">Instructor</div>
                    <div className="text-gray-900 dark:text-white font-medium">{course.instructor_name}</div>
                  </div>
                )}

                {course.category && (
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">Category</div>
                    <div className="text-gray-900 dark:text-white font-medium">{course.category}</div>
                  </div>
                )}

                {course.published_at && (
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">Published</div>
                    <div className="text-gray-900 dark:text-white font-medium">
                      {new Date(course.published_at).toLocaleDateString()}
                    </div>
                  </div>
                )}

                {course.updated_at && (
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">Last Updated</div>
                    <div className="text-gray-900 dark:text-white font-medium">
                      {new Date(course.updated_at).toLocaleDateString()}
                    </div>
                  </div>
                )}
              </div>

              {/* Skills */}
              {course.skills && course.skills.length > 0 && (
                <div className="mt-6">
                  <div className="text-gray-500 dark:text-gray-400 mb-3">Skills You'll Gain</div>
                  <div className="flex flex-wrap gap-2">
                    {course.skills.map((skill, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs rounded-lg border border-blue-200 dark:border-blue-500/20"
                      >
                        {skill}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          </div>
        </div>
      </div>

      {/* Registration Prompt Modal */}
      <RegistrationPrompt
        isOpen={isPromptOpen}
        onClose={closePrompt}
        onSkip={handleSkip}
        context="course"
      />
    </div>
  );
};

export default CourseDetail;
