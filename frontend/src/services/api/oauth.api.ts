// src/services/api/oauth.api.ts
/**
 * OAuth API Client (Google OAuth)
 */

import { apiClient } from './client';

export interface GoogleOAuthData {
  email: string;
  google_id: string;
  first_name: string;
  last_name: string;
  avatar_url?: string;
}

export interface UserResponse {
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
  created_at: string;
}

export const oauthApi = {
  /**
   * Google OAuth login/registration
   */
  googleLogin: async (data: GoogleOAuthData): Promise<UserResponse> => {
    const response = await apiClient.post<UserResponse>('/api/v1/auth/oauth/google', data);
    return response.data;
  },

  /**
   * Unlink Google account from user
   */
  unlinkGoogle: async (): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>('/api/v1/auth/oauth/google/unlink');
    return response.data;
  },
};
