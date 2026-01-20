// src/pages/admin/CourseEnrollmentsAdmin.tsx
/**
 * Course Enrollments Management
 * View and manage student enrollments across all courses
 */

import { useState, useEffect } from 'react';
import {
  GraduationCap,
  Users,
  Search,
  Filter,
  ChevronDown,
  Loader2,
  Calendar,
  TrendingUp,
  MoreVertical,
  Eye,
  Trash2,
  Mail,
} from 'lucide-react';

interface Enrollment {
  id: number;
  user: {
    id: number;
    username: string;
    email: string;
  };
  course: {
    id: string;
    title: string;
    level: string;
  };
  enrolled_at: string;
  progress_percent: number;
  last_activity: string | null;
  status: 'active' | 'completed' | 'paused';
}

interface CourseStats {
  course_id: string;
  course_title: string;
  total_enrollments: number;
  active_students: number;
  completion_rate: number;
}

export const CourseEnrollmentsAdmin: React.FC = () => {
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [courseStats, setCourseStats] = useState<CourseStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [courseFilter, setCourseFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  useEffect(() => {
    loadEnrollments();
  }, []);

  const loadEnrollments = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/admin/courses/enrollments');

      // Mock data
      setEnrollments([
        {
          id: 1,
          user: { id: 1, username: 'john_doe', email: 'john@example.com' },
          course: { id: 'web-dev-101', title: 'Web Development Fundamentals', level: 'beginner' },
          enrolled_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30).toISOString(),
          progress_percent: 75,
          last_activity: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
          status: 'active',
        },
        {
          id: 2,
          user: { id: 2, username: 'jane_smith', email: 'jane@example.com' },
          course: { id: 'web-dev-101', title: 'Web Development Fundamentals', level: 'beginner' },
          enrolled_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45).toISOString(),
          progress_percent: 100,
          last_activity: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5).toISOString(),
          status: 'completed',
        },
        {
          id: 3,
          user: { id: 3, username: 'bob_wilson', email: 'bob@example.com' },
          course: { id: 'python-basics', title: 'Python for Beginners', level: 'beginner' },
          enrolled_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15).toISOString(),
          progress_percent: 35,
          last_activity: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7).toISOString(),
          status: 'paused',
        },
        {
          id: 4,
          user: { id: 4, username: 'alice_chen', email: 'alice@example.com' },
          course: { id: 'react-advanced', title: 'Advanced React Patterns', level: 'advanced' },
          enrolled_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10).toISOString(),
          progress_percent: 50,
          last_activity: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          status: 'active',
        },
        {
          id: 5,
          user: { id: 1, username: 'john_doe', email: 'john@example.com' },
          course: { id: 'python-basics', title: 'Python for Beginners', level: 'beginner' },
          enrolled_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString(),
          progress_percent: 100,
          last_activity: new Date(Date.now() - 1000 * 60 * 60 * 24 * 20).toISOString(),
          status: 'completed',
        },
      ]);

      setCourseStats([
        { course_id: 'web-dev-101', course_title: 'Web Development Fundamentals', total_enrollments: 156, active_students: 89, completion_rate: 42 },
        { course_id: 'python-basics', course_title: 'Python for Beginners', total_enrollments: 234, active_students: 112, completion_rate: 38 },
        { course_id: 'react-advanced', course_title: 'Advanced React Patterns', total_enrollments: 67, active_students: 45, completion_rate: 28 },
      ]);
    } catch (error) {
      console.error('Failed to load enrollments:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const formatTimeAgo = (dateString: string | null) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));

    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
      case 'completed':
        return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
      case 'paused':
        return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
      default:
        return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
    }
  };

  const uniqueCourses = [...new Set(enrollments.map(e => e.course.id))].map(id => {
    const enrollment = enrollments.find(e => e.course.id === id);
    return { id, title: enrollment?.course.title || id };
  });

  const filteredEnrollments = enrollments.filter(enrollment => {
    if (courseFilter !== 'all' && enrollment.course.id !== courseFilter) return false;
    if (statusFilter !== 'all' && enrollment.status !== statusFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!enrollment.user.username.toLowerCase().includes(term) &&
          !enrollment.user.email.toLowerCase().includes(term) &&
          !enrollment.course.title.toLowerCase().includes(term)) {
        return false;
      }
    }
    return true;
  });

  const totals = {
    enrollments: enrollments.length,
    active: enrollments.filter(e => e.status === 'active').length,
    completed: enrollments.filter(e => e.status === 'completed').length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Course Enrollments
        </h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">
          View and manage student enrollments across all courses
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Users className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.enrollments}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total Enrollments</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
            <TrendingUp className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.active}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Active Students</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
            <GraduationCap className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.completed}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Completions</p>
          </div>
        </div>
      </div>

      {/* Course Stats */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Course Performance
        </h2>
        <div className="space-y-4">
          {courseStats.map((stat) => (
            <div key={stat.course_id} className="flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className="font-medium text-gray-900 dark:text-white truncate">
                  {stat.course_title}
                </p>
                <div className="flex items-center gap-4 mt-1 text-sm text-gray-500 dark:text-gray-400">
                  <span>{stat.total_enrollments} enrolled</span>
                  <span>{stat.active_students} active</span>
                </div>
              </div>
              <div className="w-32">
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-500 dark:text-gray-400">Completion</span>
                  <span className="font-medium text-gray-900 dark:text-white">{stat.completion_rate}%</span>
                </div>
                <div className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full"
                    style={{ width: `${stat.completion_rate}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by student or course..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <select
          value={courseFilter}
          onChange={(e) => setCourseFilter(e.target.value)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Courses</option>
          {uniqueCourses.map((course) => (
            <option key={course.id} value={course.id}>
              {course.title}
            </option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="completed">Completed</option>
          <option value="paused">Paused</option>
        </select>
      </div>

      {/* Enrollments Table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Student
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Course
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Enrolled
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Progress
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Last Activity
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredEnrollments.map((enrollment) => (
                <tr key={enrollment.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white text-sm font-semibold">
                        {enrollment.user.username[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {enrollment.user.username}
                        </p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {enrollment.user.email}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <p className="text-gray-900 dark:text-white">{enrollment.course.title}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 capitalize">
                      {enrollment.course.level}
                    </p>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">
                    {formatDate(enrollment.enrolled_at)}
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-20 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            enrollment.progress_percent === 100 ? 'bg-green-500' : 'bg-primary'
                          }`}
                          style={{ width: `${enrollment.progress_percent}%` }}
                        />
                      </div>
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {enrollment.progress_percent}%
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">
                    {formatTimeAgo(enrollment.last_activity)}
                  </td>
                  <td className="px-4 py-4">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(enrollment.status)}`}>
                      {enrollment.status}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <button className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                      <MoreVertical className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredEnrollments.length === 0 && (
          <div className="text-center py-12">
            <GraduationCap className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">No enrollments found</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default CourseEnrollmentsAdmin;
