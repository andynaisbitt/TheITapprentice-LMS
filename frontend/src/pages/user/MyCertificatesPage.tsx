// src/pages/user/MyCertificatesPage.tsx
/**
 * My Certificates Page
 * Displays all certificates earned by the user from completed courses
 * Shows in-progress courses when no certificates yet
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Award,
  Copy,
  CheckCircle,
  BookOpen,
  Calendar,
  Shield,
  ChevronRight,
  GraduationCap,
  Target,
  Rocket,
  Clock,
} from 'lucide-react';
import { coursesApi } from '../../plugins/courses/services/coursesApi';
import type { Certificate } from '../../plugins/courses/types';
import { useToast } from '../../components/ui/Toast';

interface CourseProgress {
  course_id: string;
  title: string;
  progress: number;
  status: string;
  total_modules: number;
  completed_modules: number;
}

const MyCertificatesPage: React.FC = () => {
  const { toast } = useToast();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [inProgressCourses, setInProgressCourses] = useState<CourseProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [certs, enrollments] = await Promise.all([
          coursesApi.getMyCertificates(),
          coursesApi.getMyCourses()
            .then((courses: any[]) =>
              courses
                .filter((c: any) => c.enrollment && c.enrollment.status === 'active' && c.enrollment.progress > 0)
                .map((c: any) => ({
                  course_id: c.id,
                  title: c.title || c.id,
                  progress: c.enrollment?.progress || 0,
                  status: c.enrollment?.status || 'active',
                  total_modules: Array.isArray(c.modules) ? c.modules.length : 0,
                  completed_modules: Array.isArray(c.enrollment?.completed_modules) ? c.enrollment.completed_modules.length : 0,
                }))
            )
            .catch(() => []),
        ]);
        setCertificates(certs);
        setInProgressCourses(enrollments);
      } catch (err: any) {
        console.error('Failed to fetch certificates:', err);
        setError(err.response?.data?.detail || 'Failed to load certificates');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(code);
    toast.success('Verification code copied!');
    setTimeout(() => setCopiedCode(null), 2000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-500 dark:text-gray-400">Loading certificates...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="max-w-4xl mx-auto px-4 py-8 sm:py-12">
        {/* Header */}
        <div className="mb-6 sm:mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-500/20 rounded-lg">
              <Award className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
                My Certificates
              </h1>
              {certificates.length > 0 && (
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {certificates.length} certificate{certificates.length !== 1 ? 's' : ''} earned
                </p>
              )}
            </div>
          </div>
          <p className="text-gray-600 dark:text-gray-400 text-sm sm:text-base">
            Complete courses to earn verifiable certificates that showcase your skills.
          </p>
        </div>

        {/* Error State */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg">
            <p className="text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        {/* Certificates Grid */}
        {certificates.length > 0 && (
          <div className="space-y-6 mb-8">
            {certificates.map((cert, index) => (
              <motion.div
                key={cert.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden"
              >
                {/* Certificate Header */}
                <div className="bg-gradient-to-r from-blue-600 to-indigo-600 px-4 sm:px-6 py-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-white/20 rounded-lg">
                        <Award className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-base sm:text-lg font-bold text-white">{cert.title}</h3>
                        <p className="text-blue-100 text-sm">{cert.course_title}</p>
                      </div>
                    </div>
                    {cert.course_level && (
                      <span className="px-3 py-1 bg-white/20 text-white text-xs font-medium rounded-full capitalize">
                        {cert.course_level}
                      </span>
                    )}
                  </div>
                </div>

                {/* Certificate Body */}
                <div className="p-4 sm:p-6">
                  {cert.description && (
                    <p className="text-gray-600 dark:text-gray-300 text-sm mb-4">
                      {cert.description}
                    </p>
                  )}

                  {/* Stats Row */}
                  <div className="flex flex-wrap gap-3 sm:gap-4 mb-4 text-sm">
                    <div className="flex items-center gap-1.5 text-gray-500 dark:text-gray-400">
                      <Calendar className="w-4 h-4" />
                      <span>Issued {new Date(cert.issued_at).toLocaleDateString()}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-gray-500 dark:text-gray-400">
                      <BookOpen className="w-4 h-4" />
                      <span>{cert.total_modules} modules, {cert.total_sections} sections</span>
                    </div>
                    {cert.instructor_name && (
                      <div className="flex items-center gap-1.5 text-gray-500 dark:text-gray-400">
                        <Shield className="w-4 h-4" />
                        <span>Instructor: {cert.instructor_name}</span>
                      </div>
                    )}
                  </div>

                  {/* Verification Code */}
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3 sm:p-4 mb-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-500 dark:text-gray-400 font-medium uppercase tracking-wide">
                        Verification Code
                      </span>
                      <button
                        onClick={() => handleCopyCode(cert.verification_code)}
                        className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
                      >
                        {copiedCode === cert.verification_code ? (
                          <>
                            <CheckCircle className="w-3.5 h-3.5" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            Copy
                          </>
                        )}
                      </button>
                    </div>
                    <p className="font-mono text-sm font-semibold text-blue-600 dark:text-blue-300 tracking-wide break-all">
                      {cert.verification_code}
                    </p>
                  </div>

                  {/* Skills */}
                  {cert.skills_acquired && cert.skills_acquired.length > 0 && (
                    <div className="mb-4">
                      <span className="text-xs text-gray-500 dark:text-gray-400 font-medium uppercase tracking-wide mb-2 block">
                        Skills Acquired
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {cert.skills_acquired.map((skill, idx) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs rounded-full border border-blue-200 dark:border-blue-500/20 font-medium"
                          >
                            {skill}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-3 pt-2">
                    <Link
                      to={`/courses/${cert.course_id}`}
                      className="flex items-center gap-1.5 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
                    >
                      View Course
                      <ChevronRight className="w-4 h-4" />
                    </Link>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}

        {/* Empty State - No certificates */}
        {!error && certificates.length === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center py-12 sm:py-16 bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm mb-8"
          >
            <div className="relative inline-block mb-4">
              <GraduationCap className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto" />
              <div className="absolute -bottom-1 -right-1 w-6 h-6 bg-yellow-400 rounded-full flex items-center justify-center">
                <Award className="w-3.5 h-3.5 text-yellow-800" />
              </div>
            </div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
              No certificates yet
            </h2>
            <p className="text-gray-500 dark:text-gray-400 mb-6 max-w-md mx-auto text-sm sm:text-base">
              Complete a course to earn your first certificate. Each certificate includes a unique verification code you can share.
            </p>
            <Link
              to="/courses"
              className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
            >
              <BookOpen className="w-5 h-5" />
              Browse Courses
            </Link>
          </motion.div>
        )}

        {/* In-Progress Courses */}
        {inProgressCourses.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5 text-blue-500" />
              Courses In Progress
            </h2>
            <div className="space-y-3">
              {inProgressCourses.map((course) => (
                <Link
                  key={course.course_id}
                  to={`/courses/${course.course_id}`}
                  className="block bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 hover:border-blue-300 dark:hover:border-blue-600 transition-colors group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-medium text-gray-900 dark:text-white text-sm sm:text-base group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                      {course.title}
                    </h3>
                    <span className="text-xs font-bold text-blue-600 dark:text-blue-400">
                      {course.progress}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mb-2">
                    <div
                      className="bg-gradient-to-r from-blue-500 to-indigo-500 h-2 rounded-full transition-all"
                      style={{ width: `${course.progress}%` }}
                    />
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {course.completed_modules} of {course.total_modules} modules completed
                    {course.progress >= 75 && ' — Almost there!'}
                  </p>
                </Link>
              ))}
            </div>
          </motion.div>
        )}

        {/* Suggested Next Steps */}
        {certificates.length === 0 && inProgressCourses.length === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              <Rocket className="w-5 h-5 text-purple-500" />
              Get Started
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <Link
                to="/courses"
                className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 hover:border-blue-300 dark:hover:border-blue-600 transition-colors text-center"
              >
                <BookOpen className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900 dark:text-white text-sm mb-1">Courses</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400">Complete structured courses to earn certificates</p>
              </Link>
              <Link
                to="/tutorials"
                className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 hover:border-green-300 dark:hover:border-green-600 transition-colors text-center"
              >
                <Target className="w-8 h-8 text-green-500 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900 dark:text-white text-sm mb-1">Tutorials</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400">Learn specific skills with step-by-step guides</p>
              </Link>
              <Link
                to="/typing-practice"
                className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 hover:border-purple-300 dark:hover:border-purple-600 transition-colors text-center"
              >
                <Award className="w-8 h-8 text-purple-500 mx-auto mb-2" />
                <h3 className="font-medium text-gray-900 dark:text-white text-sm mb-1">Typing</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400">Practice typing speed and earn skill badges</p>
              </Link>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default MyCertificatesPage;
