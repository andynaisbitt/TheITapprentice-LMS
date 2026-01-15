// frontend/src/plugins/tutorials/pages/admin/UserProgressPage.tsx
/**
 * Admin User Progress Viewer
 * Shows all users' tutorial progress and engagement metrics
 */
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8100';

interface User {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
}

interface UserTutorialProgress {
  user: User;
  totalStarted: number;
  totalCompleted: number;
  totalTimeMinutes: number;
  recentActivity: string | null;
  progressRecords: Array<{
    tutorial_id: number;
    tutorial_title: string;
    status: 'in_progress' | 'completed';
    progress_percentage: number;
    time_spent_minutes: number;
    started_at: string;
    completed_at: string | null;
  }>;
}

export const UserProgressPage: React.FC = () => {
  const navigate = useNavigate();
  const [userProgress, setUserProgress] = useState<UserTutorialProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedUser, setSelectedUser] = useState<UserTutorialProgress | null>(null);

  useEffect(() => {
    fetchUserProgress();
  }, []);

  const fetchUserProgress = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch all users
      const usersResponse = await axios.get(`${API_BASE}/api/v1/admin/users`, {
        withCredentials: true,
      });
      const users: User[] = usersResponse.data;

      // For each user, fetch their tutorial progress
      // Note: In production, this should be a single backend endpoint that returns aggregated data
      const progressPromises = users.map(async (user) => {
        try {
          // This would need a backend endpoint like: /api/v1/admin/users/{user_id}/tutorial-progress
          // For now, we'll return mock data structure
          const mockProgress: UserTutorialProgress = {
            user,
            totalStarted: 0,
            totalCompleted: 0,
            totalTimeMinutes: 0,
            recentActivity: null,
            progressRecords: [],
          };
          return mockProgress;
        } catch (err) {
          console.error(`Failed to fetch progress for user ${user.id}:`, err);
          return {
            user,
            totalStarted: 0,
            totalCompleted: 0,
            totalTimeMinutes: 0,
            recentActivity: null,
            progressRecords: [],
          };
        }
      });

      const allProgress = await Promise.all(progressPromises);
      setUserProgress(allProgress);
    } catch (err: any) {
      console.error('Error fetching user progress:', err);
      setError(err.message || 'Failed to load user progress');
    } finally {
      setLoading(false);
    }
  };

  const filteredUsers = userProgress.filter((up) => {
    const fullName = `${up.user.first_name} ${up.user.last_name}`.toLowerCase();
    const email = up.user.email.toLowerCase();
    const search = searchTerm.toLowerCase();
    return fullName.includes(search) || email.includes(search);
  });

  const totalActiveUsers = userProgress.filter((up) => up.totalStarted > 0).length;
  const totalCompletedUsers = userProgress.filter((up) => up.totalCompleted > 0).length;
  const avgCompletionRate =
    userProgress.length > 0
      ? (userProgress.reduce((sum, up) => {
          const rate = up.totalStarted > 0 ? up.totalCompleted / up.totalStarted : 0;
          return sum + rate;
        }, 0) /
          userProgress.length) *
        100
      : 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 max-w-7xl mx-auto">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <p className="text-red-600 dark:text-red-400">{error}</p>
          <button
            onClick={fetchUserProgress}
            className="mt-2 text-sm text-red-700 dark:text-red-300 hover:underline"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            User Tutorial Progress
          </h1>
          <p className="mt-1 text-gray-600 dark:text-gray-400">
            Monitor all users' learning progress and engagement
          </p>
        </div>
        <button
          onClick={() => navigate('/admin/tutorials')}
          className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
        >
          Back to Management
        </button>
      </div>

      {/* Global Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Total Users
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {userProgress.length}
              </p>
            </div>
            <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-full">
              <svg
                className="w-8 h-8 text-blue-600 dark:text-blue-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Active Learners
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {totalActiveUsers}
              </p>
            </div>
            <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-full">
              <svg
                className="w-8 h-8 text-green-600 dark:text-green-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M13 10V3L4 14h7v7l9-11h-7z"
                />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-purple-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Completed Tutorials
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {userProgress.reduce((sum, up) => sum + up.totalCompleted, 0)}
              </p>
            </div>
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-full">
              <svg
                className="w-8 h-8 text-purple-600 dark:text-purple-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-orange-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Avg Completion Rate
              </p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                {avgCompletionRate.toFixed(0)}%
              </p>
            </div>
            <div className="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-full">
              <svg
                className="w-8 h-8 text-orange-600 dark:text-orange-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-4">
        <div className="flex items-center gap-3">
          <svg
            className="w-5 h-5 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="text"
            placeholder="Search by name or email..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="flex-1 px-4 py-2 border-0 bg-transparent text-gray-900 dark:text-white focus:ring-0"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="px-3 py-1 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  User
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Started
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Completed
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Time Spent
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Recent Activity
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredUsers.map((userProg) => {
                const completionRate =
                  userProg.totalStarted > 0
                    ? (userProg.totalCompleted / userProg.totalStarted) * 100
                    : 0;

                return (
                  <tr
                    key={userProg.user.id}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-full flex items-center justify-center flex-shrink-0">
                          <span className="text-white font-semibold text-sm">
                            {userProg.user.first_name?.[0]}
                            {userProg.user.last_name?.[0]}
                          </span>
                        </div>
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">
                            {userProg.user.first_name} {userProg.user.last_name}
                          </p>
                          <p className="text-sm text-gray-600 dark:text-gray-400">
                            {userProg.user.email}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className="text-gray-900 dark:text-white font-medium">
                        {userProg.totalStarted}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <div className="flex flex-col items-center gap-1">
                        <span className="text-gray-900 dark:text-white font-medium">
                          {userProg.totalCompleted}
                        </span>
                        {userProg.totalStarted > 0 && (
                          <span className="text-xs text-gray-600 dark:text-gray-400">
                            ({completionRate.toFixed(0)}%)
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center text-gray-900 dark:text-white font-medium">
                      {userProg.totalTimeMinutes > 0
                        ? `${userProg.totalTimeMinutes}m`
                        : '-'}
                    </td>
                    <td className="px-6 py-4 text-center text-sm text-gray-600 dark:text-gray-400">
                      {userProg.recentActivity
                        ? new Date(userProg.recentActivity).toLocaleDateString()
                        : 'No activity'}
                    </td>
                    <td className="px-6 py-4 text-center">
                      <button
                        onClick={() => setSelectedUser(userProg)}
                        className="px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded transition-colors"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {filteredUsers.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-600 dark:text-gray-400">
              {searchTerm
                ? 'No users found matching your search'
                : 'No user progress data available'}
            </p>
          </div>
        )}
      </div>

      {/* User Details Modal */}
      {selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6 flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {selectedUser.user.first_name} {selectedUser.user.last_name}
                </h2>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  {selectedUser.user.email}
                </p>
              </div>
              <button
                onClick={() => setSelectedUser(null)}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                <svg
                  className="w-6 h-6 text-gray-600 dark:text-gray-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Tutorials Started</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                    {selectedUser.totalStarted}
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Completed</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                    {selectedUser.totalCompleted}
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Time</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                    {selectedUser.totalTimeMinutes}m
                  </p>
                </div>
              </div>

              {/* Progress Records */}
              {selectedUser.progressRecords.length > 0 ? (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Tutorial Progress
                  </h3>
                  <div className="space-y-3">
                    {selectedUser.progressRecords.map((record, index) => (
                      <div
                        key={index}
                        className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <p className="font-medium text-gray-900 dark:text-white">
                            {record.tutorial_title}
                          </p>
                          <span
                            className={`px-2 py-1 text-xs font-medium rounded-full ${
                              record.status === 'completed'
                                ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                                : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300'
                            }`}
                          >
                            {record.status === 'completed' ? 'Completed' : 'In Progress'}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 mb-2">
                          <div className="flex-1 bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full transition-all ${
                                record.status === 'completed'
                                  ? 'bg-green-600'
                                  : 'bg-blue-600'
                              }`}
                              style={{ width: `${record.progress_percentage}%` }}
                            ></div>
                          </div>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {record.progress_percentage}%
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-sm text-gray-600 dark:text-gray-400">
                          <span>Time: {record.time_spent_minutes}m</span>
                          <span>Started: {new Date(record.started_at).toLocaleDateString()}</span>
                          {record.completed_at && (
                            <span>
                              Completed: {new Date(record.completed_at).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <p className="text-gray-600 dark:text-gray-400">
                    This user hasn't started any tutorials yet
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Note about backend integration */}
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg
            className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <div>
            <p className="text-sm font-medium text-yellow-800 dark:text-yellow-300">
              Backend Integration Required
            </p>
            <p className="text-sm text-yellow-700 dark:text-yellow-400 mt-1">
              To display real user progress data, add a backend endpoint:{' '}
              <code className="bg-yellow-100 dark:bg-yellow-900/40 px-1 rounded">
                GET /api/v1/admin/users/:user_id/tutorial-progress
              </code>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProgressPage;
