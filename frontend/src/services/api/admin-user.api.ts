// src/services/api/admin-user.api.ts
/**
 * Admin User Management API Client
 */

import { apiClient } from './client';

export interface UserRole {
  APPRENTICE: string;
  SUPPORTER: string;
  CONTRIBUTOR: string;
  MENTOR: string;
  TUTOR: string;
  AUTHOR: string;
  ADMIN: string;
}

export interface SubscriptionStatus {
  FREE: string;
  ACTIVE: string;
  CANCELLED: string;
  EXPIRED: string;
  PAST_DUE: string;
}

export interface User {
  id: number;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  is_admin: boolean;
  avatar_url?: string;
  google_id?: string;
  subscription_status?: string;
  subscription_plan?: string;
  can_write_blog: boolean;
  can_moderate: boolean;
  created_at: string;
  updated_at: string;
  last_login?: string;
  login_count: number;
  total_points: number;
  level: number;
}

export interface UserFilters {
  page?: number;
  page_size?: number;
  search?: string;
  role?: string;
  is_active?: boolean;
  is_verified?: boolean;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export interface UserListResponse {
  users: User[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface UserStats {
  total_users: number;
  active_users: number;
  admin_count: number;
  new_this_month: number;
  role_counts: Record<string, number>;
  subscription_counts: Record<string, number>;
}

export interface UserAdminUpdate {
  role?: string;
  is_active?: boolean;
  is_verified?: boolean;
  is_admin?: boolean;
  subscription_status?: string;
  subscription_plan?: string;
  can_write_blog?: boolean;
  can_moderate?: boolean;
}

export interface UserAdminCreate {
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  password?: string;  // Optional - backend generates if not provided
  role?: string;
  is_active?: boolean;
  is_verified?: boolean;
  can_write_blog?: boolean;
  can_moderate?: boolean;
}

export const adminUserApi = {
  /**
   * Create new user (admin only)
   */
  createUser: async (data: UserAdminCreate): Promise<User> => {
    const response = await apiClient.post<User>('/api/v1/admin/users', data);
    return response.data;
  },

  /**
   * Get all users with filtering and pagination
   */
  getAllUsers: async (filters?: UserFilters): Promise<UserListResponse> => {
    const response = await apiClient.get<UserListResponse>('/api/v1/admin/users', {
      params: filters,
    });
    return response.data;
  },

  /**
   * Get user statistics
   */
  getStats: async (): Promise<UserStats> => {
    const response = await apiClient.get<UserStats>('/api/v1/admin/users/stats');
    return response.data;
  },

  /**
   * Get single user by ID
   */
  getUserById: async (userId: number): Promise<User> => {
    const response = await apiClient.get<User>(`/api/v1/admin/users/${userId}`);
    return response.data;
  },

  /**
   * Update user (admin fields)
   */
  updateUser: async (userId: number, data: UserAdminUpdate): Promise<User> => {
    const response = await apiClient.put<User>(`/api/v1/admin/users/${userId}`, data);
    return response.data;
  },

  /**
   * Delete user
   */
  deleteUser: async (userId: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/users/${userId}`);
  },

  /**
   * Bulk update users
   */
  bulkUpdate: async (userIds: number[], updates: UserAdminUpdate): Promise<{ message: string; updated_count: number }> => {
    const response = await apiClient.post('/api/v1/admin/users/bulk-update', {
      user_ids: userIds,
      updates,
    });
    return response.data;
  },

  /**
   * Bulk delete users
   */
  bulkDelete: async (userIds: number[]): Promise<{ message: string; deleted_count: number }> => {
    const response = await apiClient.post('/api/v1/admin/users/bulk-delete', {
      user_ids: userIds,
    });
    return response.data;
  },
};
