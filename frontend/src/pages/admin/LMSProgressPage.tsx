// src/pages/admin/LMSProgressPage.tsx
/**
 * Student Progress Overview
 * Combined view of student progress across tutorials, courses, and games
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  TrendingUp,
  Users,
  BookOpen,
  GraduationCap,
  Keyboard,
  Trophy,
  Search,
  Filter,
  ChevronRight,
  Loader2,
  Zap,
} from 'lucide-react';

interface StudentProgress {
  id: number;
  username: string;
  email: string;
  avatar?: string;
  total_xp: number;
  level: number;
  current_streak: number;
  tutorials_completed: number;
  courses_completed: number;
  games_played: number;
  achievements_unlocked: number;
  last_active: string;
}

export const LMSProgressPage: React.FC = () => {
  const [students, setStudents] = useState<StudentProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'xp' | 'tutorials' | 'activity'>('xp');

  useEffect(() => {
    loadStudentProgress();
  }, []);

  const loadStudentProgress = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/admin/lms/progress');
      // const data = await response.json();
      // setStudents(data);

      // Mock data
      setStudents([
        { id: 1, username: 'john_doe', email: 'john@example.com', total_xp: 2450, level: 8, current_streak: 12, tutorials_completed: 15, courses_completed: 2, games_played: 45, achievements_unlocked: 8, last_active: new Date(Date.now() - 1000 * 60 * 30).toISOString() },
        { id: 2, username: 'jane_smith', email: 'jane@example.com', total_xp: 1890, level: 6, current_streak: 5, tutorials_completed: 12, courses_completed: 1, games_played: 32, achievements_unlocked: 6, last_active: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString() },
        { id: 3, username: 'bob_wilson', email: 'bob@example.com', total_xp: 3210, level: 10, current_streak: 25, tutorials_completed: 23, courses_completed: 3, games_played: 78, achievements_unlocked: 12, last_active: new Date(Date.now() - 1000 * 60 * 15).toISOString() },
        { id: 4, username: 'alice_chen', email: 'alice@example.com', total_xp: 980, level: 4, current_streak: 2, tutorials_completed: 5, courses_completed: 0, games_played: 15, achievements_unlocked: 3, last_active: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString() },
        { id: 5, username: 'mike_brown', email: 'mike@example.com', total_xp: 1560, level: 5, current_streak: 8, tutorials_completed: 9, courses_completed: 1, games_played: 28, achievements_unlocked: 5, last_active: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString() },
      ]);
    } catch (error) {
      console.error('Failed to load student progress:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatTimeAgo = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));

    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  };

  const filteredStudents = students
    .filter(s =>
      s.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.email.toLowerCase().includes(searchTerm.toLowerCase())
    )
    .sort((a, b) => {
      switch (sortBy) {
        case 'xp': return b.total_xp - a.total_xp;
        case 'tutorials': return b.tutorials_completed - a.tutorials_completed;
        case 'activity': return new Date(b.last_active).getTime() - new Date(a.last_active).getTime();
        default: return 0;
      }
    });

  const totals = {
    students: students.length,
    totalXP: students.reduce((sum, s) => sum + s.total_xp, 0),
    tutorialsCompleted: students.reduce((sum, s) => sum + s.tutorials_completed, 0),
    coursesCompleted: students.reduce((sum, s) => sum + s.courses_completed, 0),
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
          Student Progress
        </h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">
          Track student learning progress across all LMS features
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Users className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.students}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Active Students</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
            <Zap className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.totalXP.toLocaleString()}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Total XP Earned</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
            <BookOpen className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.tutorialsCompleted}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Tutorials Completed</p>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
          <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
            <GraduationCap className="w-6 h-6 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totals.coursesCompleted}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Courses Completed</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search students..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'xp' | 'tutorials' | 'activity')}
            className="pl-10 pr-8 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 appearance-none"
          >
            <option value="xp">Sort by XP</option>
            <option value="tutorials">Sort by Tutorials</option>
            <option value="activity">Sort by Activity</option>
          </select>
        </div>
      </div>

      {/* Student List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Student
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Level
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  XP
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <BookOpen className="w-4 h-4 mx-auto" />
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <GraduationCap className="w-4 h-4 mx-auto" />
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <Keyboard className="w-4 h-4 mx-auto" />
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <Trophy className="w-4 h-4 mx-auto" />
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Streak
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Last Active
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredStudents.map((student) => (
                <tr
                  key={student.id}
                  className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                >
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white font-semibold">
                        {student.username[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {student.username}
                        </p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {student.email}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-primary/10 text-primary font-bold text-sm">
                      {student.level}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-center font-medium text-gray-900 dark:text-white">
                    {student.total_xp.toLocaleString()}
                  </td>
                  <td className="px-4 py-4 text-center text-gray-600 dark:text-gray-300">
                    {student.tutorials_completed}
                  </td>
                  <td className="px-4 py-4 text-center text-gray-600 dark:text-gray-300">
                    {student.courses_completed}
                  </td>
                  <td className="px-4 py-4 text-center text-gray-600 dark:text-gray-300">
                    {student.games_played}
                  </td>
                  <td className="px-4 py-4 text-center text-gray-600 dark:text-gray-300">
                    {student.achievements_unlocked}
                  </td>
                  <td className="px-4 py-4 text-center">
                    {student.current_streak > 0 ? (
                      <span className="inline-flex items-center gap-1 text-orange-600 dark:text-orange-400">
                        <span className="text-lg">🔥</span>
                        {student.current_streak}
                      </span>
                    ) : (
                      <span className="text-gray-400">-</span>
                    )}
                  </td>
                  <td className="px-4 py-4 text-right text-sm text-gray-500 dark:text-gray-400">
                    {formatTimeAgo(student.last_active)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LMSProgressPage;
