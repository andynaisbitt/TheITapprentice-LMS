// src/services/api/auth.api.ts (COMPLETE VERSION)
/**
 * Authentication & User API
 * All auth and user profile endpoints
 */

import { apiClient, setCSRFToken, clearCSRFToken } from './client';
import { LoginResponse, User, ProfileUpdate, PasswordChange } from './types';

export const authApi = {
  // ==================== AUTHENTICATION ====================
  
  /**
   * Register new user
   */
  register: async (userData: {
    email: string;
    username: string;
    password: string;
    first_name: string;
    last_name: string;
  }): Promise<User> => {
    const response = await apiClient.post<User>('/auth/register', userData);
    return response.data;
  },

  /**
   * Login user - Sets HTTP-Only cookie automatically
   */
  login: async (email: string, password: string): Promise<LoginResponse> => {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);

    const response = await apiClient.post<LoginResponse>('/auth/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    // Store CSRF token for future requests
    if (response.data.csrf_token) {
      setCSRFToken(response.data.csrf_token);
    }

    // Store access token for WebSocket authentication
    if (response.data.access_token) {
      sessionStorage.setItem('ws_token', response.data.access_token);
    }

    return response.data;
  },

  /**
   * Logout user - Clears cookies and WebSocket token
   */
  logout: async (): Promise<void> => {
    await apiClient.post('/auth/logout');
    clearCSRFToken();
    // Clear WebSocket authentication token
    sessionStorage.removeItem('ws_token');
  },

  /**
   * Get current user info
   */
  getCurrentUser: async (): Promise<User> => {
    const response = await apiClient.get<User>('/auth/me');
    return response.data;
  },

  /**
   * Refresh JWT token
   */
  refreshToken: async (): Promise<string> => {
    const response = await apiClient.post<{ message: string; csrf_token: string }>('/auth/refresh');
    
    if (response.data.csrf_token) {
      setCSRFToken(response.data.csrf_token);
    }
    
    return response.data.csrf_token;
  },

  /**
   * Check if username is available
   */
  checkUsername: async (username: string): Promise<{ username: string; available: boolean }> => {
    const response = await apiClient.get(`/auth/check-username/${username}`);
    return response.data;
  },

  /**
   * Check if email is available
   */
  checkEmail: async (email: string): Promise<{ email: string; available: boolean }> => {
    const response = await apiClient.get(`/auth/check-email/${email}`);
    return response.data;
  },

  // ==================== EMAIL VERIFICATION ====================

  /**
   * Verify email with code or token
   */
  verifyEmail: async (token: string): Promise<{
    message: string;
    email: string;
    verified_at: string;
  }> => {
    const response = await apiClient.post('/auth/verification/verify', { token });
    return response.data;
  },

  /**
   * Resend verification email
   */
  resendVerificationEmail: async (email: string): Promise<{ message: string }> => {
    const response = await apiClient.post('/auth/verification/resend', { email });
    return response.data;
  },

  /**
   * Check verification status
   */
  checkVerificationStatus: async (email: string): Promise<{
    is_verified: boolean;
    verified_at: string | null;
  }> => {
    const response = await apiClient.get(`/auth/verification/status/${email}`);
    return response.data;
  },

  // ==================== USER PROFILE ====================

  /**
   * Update current user profile
   */
  updateProfile: async (profileData: ProfileUpdate): Promise<User> => {
    const response = await apiClient.put<User>('/auth/me', profileData);
    return response.data;
  },

  /**
   * Change password
   */
  changePassword: async (passwordData: PasswordChange): Promise<void> => {
    await apiClient.post('/auth/change-password', passwordData);
  },
};

// Export user-specific methods separately if needed
export const userApi = {
  /**
   * Get current user (alias for getCurrentUser)
   */
  getProfile: async (): Promise<User> => {
    return authApi.getCurrentUser();
  },

  /**
   * Update profile (alias for updateProfile)
   */
  updateProfile: async (data: ProfileUpdate): Promise<User> => {
    return authApi.updateProfile(data);
  },

  /**
   * Change password (alias)
   */
  changePassword: async (data: PasswordChange): Promise<void> => {
    return authApi.changePassword(data);
  },

  /**
   * Get user statistics
   * TODO: Implement backend endpoint /users/stats
   */
  getStats: async (): Promise<{
    total_points: number;
    level: number;
    courses_enrolled: number;
    courses_completed: number;
    quizzes_taken: number;
    achievements_earned: number;
    current_streak: number;
    total_time_minutes: number;
  }> => {
    // For now, return basic stats from user profile
    const user = await authApi.getCurrentUser();
    return {
      total_points: user.total_points,
      level: user.level,
      courses_enrolled: 0,
      courses_completed: 0,
      quizzes_taken: 0,
      achievements_earned: 0,
      current_streak: 0,
      total_time_minutes: 0,
    };
  },
};