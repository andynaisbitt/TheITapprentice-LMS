// src/pages/admin/UserManagement.tsx
/**
 * Admin User Management Page
 * Allows admins to view, edit, enable/disable user accounts
 */

import { useState, useEffect } from 'react';
import { adminUserApi, User, UserAdminUpdate, UserStats } from '../../services/api/admin-user.api';
import {
  Users,
  UserCheck,
  Shield,
  TrendingUp,
  Search,
  Filter,
  Edit,
  Trash2,
  CheckSquare,
  Square,
  ChevronDown,
  Loader2,
  X,
  Eye,
  Mail,
  Calendar,
  Activity,
} from 'lucide-react';

export const UserManagement = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [stats, setStats] = useState<UserStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [verifiedFilter, setVerifiedFilter] = useState('all');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalUsers, setTotalUsers] = useState(0);
  const pageSize = 20;

  // Selection & Modals
  const [selectedUsers, setSelectedUsers] = useState<Set<number>>(new Set());
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showBulkMenu, setShowBulkMenu] = useState(false);

  // Edit form state
  const [editForm, setEditForm] = useState<UserAdminUpdate>({});

  useEffect(() => {
    loadUsers();
    loadStats();
  }, [searchQuery, roleFilter, statusFilter, verifiedFilter, sortBy, sortOrder, currentPage]);

  const loadUsers = async () => {
    setLoading(true);
    setError('');

    try {
      const filters: any = {
        page: currentPage,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
      };

      if (searchQuery) filters.search = searchQuery;
      if (roleFilter !== 'all') filters.role = roleFilter;
      if (statusFilter === 'active') filters.is_active = true;
      if (statusFilter === 'inactive') filters.is_active = false;
      if (verifiedFilter === 'verified') filters.is_verified = true;
      if (verifiedFilter === 'unverified') filters.is_verified = false;

      const response = await adminUserApi.getAllUsers(filters);

      setUsers(response.users);
      setTotalPages(response.total_pages);
      setTotalUsers(response.total);
    } catch (err: any) {
      console.error('Failed to load users:', err);
      setError(err.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const statsData = await adminUserApi.getStats();
      setStats(statsData);
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  };

  const handleSelectUser = (userId: number) => {
    const newSelected = new Set(selectedUsers);
    if (newSelected.has(userId)) {
      newSelected.delete(userId);
    } else {
      newSelected.add(userId);
    }
    setSelectedUsers(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedUsers.size === users.length) {
      setSelectedUsers(new Set());
    } else {
      setSelectedUsers(new Set(users.map((u) => u.id)));
    }
  };

  const handleEditUser = (user: User) => {
    setEditingUser(user);
    setEditForm({
      role: user.role,
      is_active: user.is_active,
      is_verified: user.is_verified,
      is_admin: user.is_admin,
      can_write_blog: user.can_write_blog,
      can_moderate: user.can_moderate,
      subscription_status: user.subscription_status,
      subscription_plan: user.subscription_plan,
    });
    setShowEditModal(true);
  };

  const handleSaveUser = async () => {
    if (!editingUser) return;

    setError('');
    setLoading(true);

    try {
      await adminUserApi.updateUser(editingUser.id, editForm);
      setSuccess(`User ${editingUser.username} updated successfully`);
      setShowEditModal(false);
      setEditingUser(null);
      loadUsers();
      loadStats();

      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update user');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (user: User) => {
    if (!confirm(`Are you sure you want to delete user "${user.username}"? This action cannot be undone.`)) {
      return;
    }

    setError('');
    setLoading(true);

    try {
      await adminUserApi.deleteUser(user.id);
      setSuccess(`User ${user.username} deleted successfully`);
      loadUsers();
      loadStats();

      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to delete user');
    } finally {
      setLoading(false);
    }
  };

  const handleBulkUpdate = async (updates: UserAdminUpdate) => {
    const userIds = Array.from(selectedUsers);

    if (userIds.length === 0) {
      alert('Please select users first');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const result = await adminUserApi.bulkUpdate(userIds, updates);
      setSuccess(result.message);
      setSelectedUsers(new Set());
      setShowBulkMenu(false);
      loadUsers();
      loadStats();

      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Bulk update failed');
    } finally {
      setLoading(false);
    }
  };

  const handleBulkDelete = async () => {
    const userIds = Array.from(selectedUsers);

    if (userIds.length === 0) {
      alert('Please select users first');
      return;
    }

    if (!confirm(`Are you sure you want to delete ${userIds.length} users? This action cannot be undone.`)) {
      return;
    }

    setError('');
    setLoading(true);

    try {
      const result = await adminUserApi.bulkDelete(userIds);
      setSuccess(result.message);
      setSelectedUsers(new Set());
      setShowBulkMenu(false);
      loadUsers();
      loadStats();

      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Bulk delete failed');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const formatDateTime = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getRoleBadgeColor = (role: string) => {
    const colors: Record<string, string> = {
      ADMIN: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
      AUTHOR: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
      TUTOR: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
      MENTOR: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400',
      CONTRIBUTOR: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
      SUPPORTER: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
      APPRENTICE: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    };
    return colors[role] || colors.APPRENTICE;
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-slate-900">
        <Loader2 className="animate-spin h-12 w-12 text-blue-600" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">User Management</h1>
          <p className="text-gray-600 dark:text-gray-400">Manage user accounts, roles, and permissions</p>
        </div>

        {/* Success/Error Messages */}
        {success && (
          <div className="mb-6 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
            <p className="text-green-600 dark:text-green-400">{success}</p>
          </div>
        )}
        {error && (
          <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-center justify-between">
            <p className="text-red-600 dark:text-red-400">{error}</p>
            <button onClick={() => setError('')} className="text-red-600 hover:text-red-700">
              <X size={18} />
            </button>
          </div>
        )}

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-gray-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Users</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">{stats.total_users}</p>
                </div>
                <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                  <Users className="w-8 h-8 text-blue-600 dark:text-blue-400" />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-gray-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Active Users</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">{stats.active_users}</p>
                </div>
                <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
                  <UserCheck className="w-8 h-8 text-green-600 dark:text-green-400" />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-gray-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Admins</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">{stats.admin_count}</p>
                </div>
                <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                  <Shield className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-gray-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">New This Month</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">{stats.new_this_month}</p>
                </div>
                <div className="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
                  <TrendingUp className="w-8 h-8 text-orange-600 dark:text-orange-400" />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-4 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={20} />
              <input
                type="text"
                placeholder="Search users..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Role Filter */}
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Roles</option>
              <option value="APPRENTICE">Apprentice</option>
              <option value="SUPPORTER">Supporter</option>
              <option value="CONTRIBUTOR">Contributor</option>
              <option value="MENTOR">Mentor</option>
              <option value="TUTOR">Tutor</option>
              <option value="AUTHOR">Author</option>
              <option value="ADMIN">Admin</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>

            {/* Verified Filter */}
            <select
              value={verifiedFilter}
              onChange={(e) => setVerifiedFilter(e.target.value)}
              className="px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Verification</option>
              <option value="verified">Verified</option>
              <option value="unverified">Unverified</option>
            </select>
          </div>

          {/* Sort & Bulk Actions */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="text-gray-400" size={18} />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Showing {users.length} of {totalUsers} users
              </span>
            </div>

            <div className="flex items-center gap-4">
              {/* Sort */}
              <select
                value={`${sortBy}_${sortOrder}`}
                onChange={(e) => {
                  const [field, order] = e.target.value.split('_');
                  setSortBy(field);
                  setSortOrder(order as 'asc' | 'desc');
                }}
                className="px-3 py-1.5 text-sm bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100"
              >
                <option value="created_at_desc">Newest First</option>
                <option value="created_at_asc">Oldest First</option>
                <option value="email_asc">Email (A-Z)</option>
                <option value="email_desc">Email (Z-A)</option>
                <option value="last_login_desc">Recently Active</option>
              </select>

              {/* Bulk Actions */}
              {selectedUsers.size > 0 && (
                <div className="relative">
                  <button
                    onClick={() => setShowBulkMenu(!showBulkMenu)}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition text-sm font-medium"
                  >
                    Bulk Actions ({selectedUsers.size})
                    <ChevronDown size={16} />
                  </button>

                  {showBulkMenu && (
                    <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-slate-800 rounded-lg shadow-xl border border-gray-200 dark:border-slate-700 z-10">
                      <button
                        onClick={() => handleBulkUpdate({ is_active: true })}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-700 dark:text-gray-300 text-sm"
                      >
                        Activate Selected
                      </button>
                      <button
                        onClick={() => handleBulkUpdate({ is_active: false })}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-700 dark:text-gray-300 text-sm"
                      >
                        Deactivate Selected
                      </button>
                      <button
                        onClick={() => handleBulkUpdate({ is_verified: true })}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-700 dark:text-gray-300 text-sm"
                      >
                        Verify Selected
                      </button>
                      <div className="border-t border-gray-200 dark:border-slate-600"></div>
                      <button
                        onClick={handleBulkDelete}
                        className="w-full text-left px-4 py-2 hover:bg-red-50 dark:hover:bg-red-900/20 text-red-600 dark:text-red-400 text-sm"
                      >
                        Delete Selected
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* User List */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="animate-spin h-8 w-8 text-blue-600" />
          </div>
        ) : users.length === 0 ? (
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-12 text-center">
            <Users className="mx-auto h-12 w-12 text-gray-400 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">No users found</h3>
            <p className="text-gray-500 dark:text-gray-400">Try adjusting your filters</p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Select All */}
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-3">
              <button
                onClick={handleSelectAll}
                className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400"
              >
                {selectedUsers.size === users.length ? (
                  <CheckSquare size={18} className="text-blue-600" />
                ) : (
                  <Square size={18} />
                )}
                <span>{selectedUsers.size === users.length ? 'Deselect All' : 'Select All'}</span>
              </button>
            </div>

            {/* User Cards */}
            {users.map((user) => (
              <div
                key={user.id}
                className="bg-white dark:bg-slate-800 rounded-lg shadow border border-gray-200 dark:border-slate-700 p-6 hover:shadow-lg transition"
              >
                <div className="flex items-start gap-4">
                  {/* Checkbox */}
                  <button
                    onClick={() => handleSelectUser(user.id)}
                    className="mt-1 text-gray-400 hover:text-blue-600"
                  >
                    {selectedUsers.has(user.id) ? (
                      <CheckSquare size={22} className="text-blue-600" />
                    ) : (
                      <Square size={22} />
                    )}
                  </button>

                  {/* Avatar */}
                  <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-white font-bold text-lg flex-shrink-0">
                    {user.first_name[0]}
                    {user.last_name[0]}
                  </div>

                  {/* User Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                          {user.first_name} {user.last_name}
                          {user.is_admin && (
                            <Shield className="inline-block ml-2 w-4 h-4 text-purple-600" />
                          )}
                        </h3>
                        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                          <Mail size={14} />
                          <span>{user.email}</span>
                          <span className="text-gray-400">•</span>
                          <span>@{user.username}</span>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleEditUser(user)}
                          className="p-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition"
                          title="Edit user"
                        >
                          <Edit size={18} />
                        </button>
                        <button
                          onClick={() => handleDeleteUser(user)}
                          className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition"
                          title="Delete user"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </div>

                    {/* Badges & Info */}
                    <div className="flex flex-wrap gap-2 mb-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRoleBadgeColor(user.role)}`}>
                        {user.role}
                      </span>
                      {user.is_active ? (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                          Active
                        </span>
                      ) : (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">
                          Inactive
                        </span>
                      )}
                      {user.is_verified && (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                          Verified
                        </span>
                      )}
                      {user.google_id && (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                          Google
                        </span>
                      )}
                    </div>

                    {/* Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs text-gray-600 dark:text-gray-400">
                      <div>
                        <Calendar size={12} className="inline mr-1" />
                        Joined: {formatDate(user.created_at)}
                      </div>
                      {user.last_login && (
                        <div>
                          <Activity size={12} className="inline mr-1" />
                          Last: {formatDateTime(user.last_login)}
                        </div>
                      )}
                      <div>Logins: {user.login_count}</div>
                      <div>Level: {user.level} ({user.total_points} pts)</div>
                    </div>

                    {/* Permissions */}
                    {(user.can_write_blog || user.can_moderate) && (
                      <div className="mt-2 flex gap-2">
                        {user.can_write_blog && (
                          <span className="text-xs text-gray-500 dark:text-gray-400">✓ Can write blog</span>
                        )}
                        {user.can_moderate && (
                          <span className="text-xs text-gray-500 dark:text-gray-400">✓ Can moderate</span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="mt-6 flex justify-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-4 py-2 bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-slate-700 transition"
            >
              Previous
            </button>
            <span className="px-4 py-2 text-gray-700 dark:text-gray-300">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-4 py-2 bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-slate-700 transition"
            >
              Next
            </button>
          </div>
        )}
      </div>

      {/* Edit User Modal */}
      {showEditModal && editingUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Edit User</h2>
                <button
                  onClick={() => setShowEditModal(false)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <X size={24} />
                </button>
              </div>

              <div className="space-y-6">
                {/* Read-only Info */}
                <div className="bg-gray-50 dark:bg-slate-700/50 rounded-lg p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Email</p>
                  <p className="font-medium text-gray-900 dark:text-gray-100">{editingUser.email}</p>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-2 mb-1">Username</p>
                  <p className="font-medium text-gray-900 dark:text-gray-100">@{editingUser.username}</p>
                </div>

                {/* Role */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Role
                  </label>
                  <select
                    value={editForm.role || ''}
                    onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                  >
                    <option value="APPRENTICE">Apprentice</option>
                    <option value="SUPPORTER">Supporter</option>
                    <option value="CONTRIBUTOR">Contributor</option>
                    <option value="MENTOR">Mentor</option>
                    <option value="TUTOR">Tutor</option>
                    <option value="AUTHOR">Author</option>
                    <option value="ADMIN">Admin</option>
                  </select>
                </div>

                {/* Status Toggles */}
                <div className="grid grid-cols-2 gap-4">
                  <label className="flex items-center gap-3 p-4 border border-gray-300 dark:border-slate-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700">
                    <input
                      type="checkbox"
                      checked={editForm.is_active ?? false}
                      onChange={(e) => setEditForm({ ...editForm, is_active: e.target.checked })}
                      className="w-5 h-5"
                    />
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Active</span>
                  </label>

                  <label className="flex items-center gap-3 p-4 border border-gray-300 dark:border-slate-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700">
                    <input
                      type="checkbox"
                      checked={editForm.is_verified ?? false}
                      onChange={(e) => setEditForm({ ...editForm, is_verified: e.target.checked })}
                      className="w-5 h-5"
                    />
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Verified</span>
                  </label>

                  <label className="flex items-center gap-3 p-4 border border-gray-300 dark:border-slate-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700">
                    <input
                      type="checkbox"
                      checked={editForm.is_admin ?? false}
                      onChange={(e) => setEditForm({ ...editForm, is_admin: e.target.checked })}
                      className="w-5 h-5"
                    />
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Admin</span>
                  </label>
                </div>

                {/* Permissions */}
                <div>
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Permissions</p>
                  <div className="space-y-2">
                    <label className="flex items-center gap-3 p-3 border border-gray-300 dark:border-slate-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700">
                      <input
                        type="checkbox"
                        checked={editForm.can_write_blog ?? false}
                        onChange={(e) => setEditForm({ ...editForm, can_write_blog: e.target.checked })}
                        className="w-4 h-4"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">Can write blog posts</span>
                    </label>

                    <label className="flex items-center gap-3 p-3 border border-gray-300 dark:border-slate-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700">
                      <input
                        type="checkbox"
                        checked={editForm.can_moderate ?? false}
                        onChange={(e) => setEditForm({ ...editForm, can_moderate: e.target.checked })}
                        className="w-4 h-4"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">Can moderate content</span>
                    </label>
                  </div>
                </div>

                {/* Subscription */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Subscription Status
                  </label>
                  <select
                    value={editForm.subscription_status || ''}
                    onChange={(e) => setEditForm({ ...editForm, subscription_status: e.target.value })}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                  >
                    <option value="FREE">Free</option>
                    <option value="ACTIVE">Active</option>
                    <option value="CANCELLED">Cancelled</option>
                    <option value="EXPIRED">Expired</option>
                    <option value="PAST_DUE">Past Due</option>
                  </select>
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-slate-600">
                  <button
                    type="button"
                    onClick={() => setShowEditModal(false)}
                    className="px-6 py-2 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleSaveUser}
                    disabled={loading}
                    className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                  >
                    {loading && <Loader2 size={16} className="animate-spin" />}
                    Save Changes
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserManagement;
