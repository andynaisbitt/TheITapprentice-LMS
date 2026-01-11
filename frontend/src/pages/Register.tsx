// src/pages/Register.tsx
/**
 * User Registration Page
 * Allows new users to create an account
 */

import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../state/contexts/AuthContext';
import { GoogleOAuthButton } from '../components/auth/GoogleOAuthButton';
import { Eye, EyeOff, CheckCircle, XCircle, Loader } from 'lucide-react';

export const Register: React.FC = () => {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
    first_name: '',
    last_name: '',
  });

  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [validations, setValidations] = useState({
    minLength: false,
    hasUppercase: false,
    hasLowercase: false,
    hasNumber: false,
  });

  // Real-time password validation
  const validatePassword = (password: string) => {
    setValidations({
      minLength: password.length >= 8,
      hasUppercase: /[A-Z]/.test(password),
      hasLowercase: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
    });
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setError('');
    setFieldErrors(prev => ({ ...prev, [name]: '' }));

    // Real-time password validation
    if (name === 'password') {
      validatePassword(value);
    }

    // Real-time confirm password validation
    if (name === 'confirmPassword' && value !== formData.password) {
      setFieldErrors(prev => ({ ...prev, confirmPassword: 'Passwords do not match' }));
    } else if (name === 'confirmPassword' && value === formData.password) {
      setFieldErrors(prev => ({ ...prev, confirmPassword: '' }));
    }
  };

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    // Email validation
    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errors.email = 'Invalid email format';
    }

    // Username validation
    if (!formData.username) {
      errors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      errors.username = 'Username must be at least 3 characters';
    } else if (!/^[a-zA-Z0-9_-]+$/.test(formData.username)) {
      errors.username = 'Username can only contain letters, numbers, hyphens, and underscores';
    }

    // Password validation
    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (!Object.values(validations).every(v => v)) {
      errors.password = 'Password does not meet all requirements';
    }

    // Confirm password validation
    if (formData.password !== formData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    // Name validation
    if (!formData.first_name?.trim()) {
      errors.first_name = 'First name is required';
    }
    if (!formData.last_name?.trim()) {
      errors.last_name = 'Last name is required';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);

    try {
      await register({
        email: formData.email.trim(),
        username: formData.username.trim(),
        password: formData.password,
        first_name: formData.first_name.trim(),
        last_name: formData.last_name.trim(),
      });

      // Redirect to verify-email page with instructions
      navigate('/verify-email', {
        state: {
          email: formData.email,
          message: 'Registration successful! Please check your email for a verification code.',
        },
      });
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(err.message || 'Registration failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Create Your Account
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Join our community and start your learning journey
          </p>
        </div>

        {/* Registration Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
          {/* Global Error Message */}
          {error && (
            <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Name Fields */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="first_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  First Name
                </label>
                <input
                  type="text"
                  id="first_name"
                  name="first_name"
                  required
                  autoComplete="given-name"
                  value={formData.first_name}
                  onChange={handleChange}
                  className={`w-full px-4 py-2 bg-white dark:bg-gray-700 border ${
                    fieldErrors.first_name ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                  } text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition`}
                  placeholder="John"
                />
                {fieldErrors.first_name && (
                  <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.first_name}</p>
                )}
              </div>

              <div>
                <label htmlFor="last_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Last Name
                </label>
                <input
                  type="text"
                  id="last_name"
                  name="last_name"
                  required
                  autoComplete="family-name"
                  value={formData.last_name}
                  onChange={handleChange}
                  className={`w-full px-4 py-2 bg-white dark:bg-gray-700 border ${
                    fieldErrors.last_name ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                  } text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition`}
                  placeholder="Doe"
                />
                {fieldErrors.last_name && (
                  <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.last_name}</p>
                )}
              </div>
            </div>

            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
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
                className={`w-full px-4 py-2 bg-white dark:bg-gray-700 border ${
                  fieldErrors.email ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                } text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition`}
                placeholder="you@example.com"
              />
              {fieldErrors.email && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.email}</p>
              )}
            </div>

            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Username
              </label>
              <input
                type="text"
                id="username"
                name="username"
                required
                autoComplete="username"
                value={formData.username}
                onChange={handleChange}
                className={`w-full px-4 py-2 bg-white dark:bg-gray-700 border ${
                  fieldErrors.username ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                } text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition`}
                placeholder="johndoe"
              />
              {fieldErrors.username && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.username}</p>
              )}
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Letters, numbers, hyphens, and underscores only
              </p>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  name="password"
                  required
                  autoComplete="new-password"
                  value={formData.password}
                  onChange={handleChange}
                  className={`w-full px-4 py-2 pr-10 bg-white dark:bg-gray-700 border ${
                    fieldErrors.password ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                  } text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition`}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>

              {/* Password Requirements */}
              {formData.password && (
                <div className="mt-2 space-y-1">
                  <ValidationItem valid={validations.minLength} text="At least 8 characters" />
                  <ValidationItem valid={validations.hasUppercase} text="One uppercase letter" />
                  <ValidationItem valid={validations.hasLowercase} text="One lowercase letter" />
                  <ValidationItem valid={validations.hasNumber} text="One number" />
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Confirm Password
              </label>
              <div className="relative">
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  id="confirmPassword"
                  name="confirmPassword"
                  required
                  autoComplete="new-password"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className={`w-full px-4 py-2 pr-10 bg-white dark:bg-gray-700 border ${
                    fieldErrors.confirmPassword ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'
                  } text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition`}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                >
                  {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              {fieldErrors.confirmPassword && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">{fieldErrors.confirmPassword}</p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full px-6 py-3 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition disabled:opacity-50 disabled:cursor-not-allowed font-medium flex items-center justify-center gap-2"
            >
              {isSubmitting ? (
                <>
                  <Loader size={18} className="animate-spin" />
                  Creating Account...
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {/* Login Link */}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Already have an account?{' '}
              <Link
                to="/login"
                className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium"
              >
                Sign in
              </Link>
            </p>
          </div>

          {/* Divider */}
          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300 dark:border-gray-600"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400">
                  Or sign up with
                </span>
              </div>
            </div>

            {/* OAuth Buttons */}
            <div className="mt-6">
              <GoogleOAuthButton
                mode="register"
                onSuccess={() => {
                  // Handled by GoogleOAuthButton (navigates to /admin)
                }}
                onError={(error) => {
                  setError(error);
                }}
              />
            </div>
          </div>
        </div>

        {/* Info Text */}
        <p className="mt-6 text-center text-xs text-gray-500 dark:text-gray-400">
          By creating an account, you agree to our{' '}
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

// Validation Item Component
const ValidationItem: React.FC<{ valid: boolean; text: string }> = ({ valid, text }) => (
  <div className="flex items-center gap-2 text-xs">
    {valid ? (
      <CheckCircle size={14} className="text-green-600 dark:text-green-400" />
    ) : (
      <XCircle size={14} className="text-gray-400 dark:text-gray-500" />
    )}
    <span className={valid ? 'text-green-600 dark:text-green-400' : 'text-gray-500 dark:text-gray-400'}>
      {text}
    </span>
  </div>
);

export default Register;
