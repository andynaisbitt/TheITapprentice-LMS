// src/services/api/client.ts
/**
 * Axios HTTP Client Configuration
 * Handles authentication, CSRF tokens, and API communication
 */

import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios';

// Get API URL from environment variable
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8100';

/**
 * Main Axios instance for API communication
 * - Automatically includes credentials (HTTP-Only cookies)
 * - Adds CSRF token to all non-GET requests
 * - Handles errors globally
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_URL,
  withCredentials: true, // Required for HTTP-Only cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Store CSRF token in sessionStorage
 */
export const setCSRFToken = (token: string): void => {
  sessionStorage.setItem('csrf_token', token);
};

/**
 * Get CSRF token from sessionStorage
 */
export const getCSRFToken = (): string | null => {
  return sessionStorage.getItem('csrf_token');
};

/**
 * Clear CSRF token from sessionStorage
 */
export const clearCSRFToken = (): void => {
  sessionStorage.removeItem('csrf_token');
};

/**
 * Request interceptor - Add CSRF token to non-GET requests
 */
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    // Add CSRF token to all non-GET requests
    if (config.method && config.method.toLowerCase() !== 'get') {
      const csrfToken = getCSRFToken();
      if (csrfToken && config.headers) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

/**
 * Response interceptor - Handle errors globally
 */
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    // Handle 401 Unauthorized - Clear auth state
    if (error.response?.status === 401) {
      clearCSRFToken();
      // Optionally redirect to login page
      // window.location.href = '/login';
    }

    // Handle 403 Forbidden - CSRF token might be invalid
    if (error.response?.status === 403) {
      const errorMessage = error.response?.data?.detail || '';
      if (errorMessage.includes('CSRF')) {
        clearCSRFToken();
        // Optionally refresh the page to get a new CSRF token
        console.error('CSRF token invalid. Please refresh the page.');
      }
    }

    return Promise.reject(error);
  }
);

export default apiClient;
