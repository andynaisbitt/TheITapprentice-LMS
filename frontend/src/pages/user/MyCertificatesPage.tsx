// src/pages/user/MyCertificatesPage.tsx
/**
 * My Certificates Page
 * Displays all certificates earned by the user from completed courses
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
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { coursesApi } from '../../plugins/courses/services/coursesApi';
import type { Certificate } from '../../plugins/courses/types';
import { useToast } from '../../components/ui/Toast';

const MyCertificatesPage: React.FC = () => {
  const { toast } = useToast();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  useEffect(() => {
    const fetchCertificates = async () => {
      try {
        setLoading(true);
        const data = await coursesApi.getMyCertificates();
        setCertificates(data);
      } catch (err: any) {
        console.error('Failed to fetch certificates:', err);
        setError(err.response?.data?.detail || 'Failed to load certificates');
      } finally {
        setLoading(false);
      }
    };

    fetchCertificates();
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
      <div className="max-w-4xl mx-auto px-4 py-12">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-500/20 rounded-lg">
              <Award className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              My Certificates
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Certificates earned from completed courses. Each includes a unique verification code.
          </p>
        </div>

        {/* Error State */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg">
            <p className="text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        {/* Empty State */}
        {!error && certificates.length === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center py-16 bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm"
          >
            <Award className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
              No certificates yet
            </h2>
            <p className="text-gray-500 dark:text-gray-400 mb-6 max-w-md mx-auto">
              Complete a course to earn your first certificate. Each certificate includes a unique verification code.
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

        {/* Certificates Grid */}
        {certificates.length > 0 && (
          <div className="space-y-6">
            {certificates.map((cert, index) => (
              <motion.div
                key={cert.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden"
              >
                {/* Certificate Header */}
                <div className="bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-white/20 rounded-lg">
                        <Award className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-white">{cert.title}</h3>
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
                <div className="p-6">
                  {cert.description && (
                    <p className="text-gray-600 dark:text-gray-300 text-sm mb-4">
                      {cert.description}
                    </p>
                  )}

                  {/* Stats Row */}
                  <div className="flex flex-wrap gap-4 mb-4 text-sm">
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
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 mb-4">
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
                    <p className="font-mono text-sm font-semibold text-blue-600 dark:text-blue-300 tracking-wide">
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
      </div>
    </div>
  );
};

export default MyCertificatesPage;
