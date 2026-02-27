// src/pages/auth/Login.tsx (UNIFIED LOGIN FOR ALL USERS)
/**
 * Unified Login Page
 * Works for all user types: Student, Volunteer, Instructor, Admin
 */

import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../state/contexts/AuthContext';
import { GoogleOAuthButton } from '../components/auth/GoogleOAuthButton';
import { useSiteSettingsStore } from '../store/useSiteSettingsStore';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isLoading, user } = useAuth();

  // Get registration settings from site settings store
  const registrationEnabled = useSiteSettingsStore((state) => state.settings.registrationEnabled);
  const loadSettings = useSiteSettingsStore((state) => state.loadSettings);

  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isVerificationError, setIsVerificationError] = useState(false);

  // Get success message from registration redirect
  const successMessage = location.state?.message;
  const prefilledEmail = location.state?.email;

  // Load site settings (includes registration status) on mount
  React.useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  // Prefill email if coming from registration
  React.useEffect(() => {
    if (prefilledEmail) {
      setFormData(prev => ({ ...prev, email: prefilledEmail }));
    }
  }, [prefilledEmail]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      const response = await login(formData.email, formData.password);

      // Redirect based on where they came from or user role
      const searchParams = new URLSearchParams(location.search);
      const returnUrl = searchParams.get('returnUrl');

      if (location.state?.from?.pathname) {
        navigate(location.state.from.pathname, { replace: true });
      } else if (returnUrl) {
        navigate(returnUrl, { replace: true });
      } else if (response.user.role === 'admin' || response.user.is_admin) {
        navigate('/admin', { replace: true });
      } else {
        navigate('/dashboard', { replace: true });
      }
    } catch (err: any) {
      console.error('Login error:', err);
      const errorMessage = err.message || 'Invalid email or password';

      // Check if error is related to email verification
      const isVerificationIssue = errorMessage.toLowerCase().includes('verify') ||
                                  errorMessage.toLowerCase().includes('verification') ||
                                  errorMessage.toLowerCase().includes('not verified');

      setIsVerificationError(isVerificationIssue);
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Welcome Back
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Sign in to continue your learning journey
          </p>
        </div>

        {/* Login Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
          {/* Success Message from Registration */}
          {successMessage && (
            <div className="mb-6 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
              <p className="text-sm text-green-600 dark:text-green-400">{successMessage}</p>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              {isVerificationError && (
                <Link
                  to="/verify-email"
                  state={{ email: formData.email }}
                  className="mt-2 inline-block text-sm text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Click here to verify your email →
                </Link>
              )}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Email Address
              </label>
              <input
                type="email"
                id="email"
                name="email"
                required
                autoComplete="email"
                value={formData.email}
                onChange={handleChange}
                className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="you@example.com"
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Password
              </label>
              <input
                type="password"
                id="password"
                name="password"
                required
                autoComplete="current-password"
                value={formData.password}
                onChange={handleChange}
                className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="••••••••"
              />
            </div>

            {/* Forgot Password Link */}
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                  Remember me
                </label>
              </div>
              <div className="text-sm">
                <Link
                  to="/forgot-password"
                  className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium"
                >
                  Forgot password?
                </Link>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full px-6 py-3 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition disabled:opacity-50 disabled:cursor-not-allowed font-medium"
            >
              {isSubmitting ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          {/* Registration Status */}
          <div className="mt-6">
            {registrationEnabled ? (
              <div className="text-center">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Don't have an account?{' '}
                  <Link
                    to="/register"
                    className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium"
                  >
                    Sign up
                  </Link>
                </p>
              </div>
            ) : (
              <div className="bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/60 rounded-lg p-4">
                <div className="flex items-start gap-3 mb-3">
                  <svg className="flex-shrink-0 w-4 h-4 text-blue-500 dark:text-blue-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                  </svg>
                  <div className="flex-1">
                    <h4 className="font-semibold text-blue-900 dark:text-blue-200 text-sm mb-1">
                      Closed Beta — Access by Invite
                    </h4>
                    <p className="text-sm text-blue-800 dark:text-blue-300 leading-relaxed">
                      New registrations are currently paused while we shape the next version of the platform. Existing members, welcome back.
                    </p>
                  </div>
                </div>
                <a
                  href="https://theitapprentice.com"
                  className="flex items-center justify-center gap-2 w-full px-4 py-2.5 rounded-lg bg-white dark:bg-gray-700 border border-blue-200 dark:border-blue-700/60 text-blue-700 dark:text-blue-300 text-sm font-medium hover:bg-blue-50 dark:hover:bg-blue-900/30 transition-colors"
                >
                  <span>←</span>
                  <span>Back to TheITApprentice.com</span>
                </a>
                <p className="mt-2.5 text-center text-xs text-blue-600/70 dark:text-blue-400/60">
                  A learning platform for IT apprentices and self-taught developers.
                </p>
              </div>
            )}
          </div>

          {/* Divider */}
          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300 dark:border-gray-600"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400">
                  Or continue with
                </span>
              </div>
            </div>

            {/* OAuth Buttons */}
            <div className="mt-6">
              <GoogleOAuthButton
                mode="login"
                onSuccess={() => {
                  // Handled by GoogleOAuthButton (navigates to /admin)
                }}
                onError={(error) => {
                  setError(error);
                }}
              />
            </div>

            {/* Google-only notice */}
            <p className="mt-4 text-center text-xs text-gray-500 dark:text-gray-400">
              Note: Google Sign-In is the only supported login method for now. Email/password login coming soon!
            </p>
          </div>
        </div>

        {/* Info Text */}
        <p className="mt-6 text-center text-xs text-gray-500 dark:text-gray-400">
          By signing in, you agree to our{' '}
          <a href="/terms" className="text-blue-600 dark:text-blue-400 hover:underline">
            Terms of Service
          </a>{' '}
          and{' '}
          <a href="/privacy" className="text-blue-600 dark:text-blue-400 hover:underline">
            Privacy Policy
          </a>
        </p>
      </div>
    </div>
  );
};

export default Login;