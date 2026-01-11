// frontend/src/pages/VerifyEmail.tsx
/**
 * Email Verification Page
 * Supports both URL token (one-click) and manual 6-digit code entry
 */

import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { authApi } from '../services/api/auth.api';

export default function VerifyEmail() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const tokenFromUrl = searchParams.get('token');

  const [verificationCode, setVerificationCode] = useState('');
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [verifiedEmail, setVerifiedEmail] = useState('');
  const [autoVerifying, setAutoVerifying] = useState(false);

  // Auto-verify if token is in URL
  useEffect(() => {
    if (tokenFromUrl && !autoVerifying) {
      setAutoVerifying(true);
      handleVerify(tokenFromUrl);
    }
  }, [tokenFromUrl]);

  const handleVerify = async (token?: string) => {
    const codeToVerify = token || verificationCode.trim();

    if (!codeToVerify) {
      setError('Please enter a verification code');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await authApi.verifyEmail(codeToVerify);
      setSuccess(true);
      setVerifiedEmail(response.email);

      // Redirect to login after 3 seconds
      setTimeout(() => {
        navigate('/login?verified=true');
      }, 3000);
    } catch (err: any) {
      console.error('Verification error:', err);
      setError(
        err.response?.data?.detail ||
        'Invalid or expired verification code. Please try again or request a new code.'
      );
    } finally {
      setLoading(false);
      setAutoVerifying(false);
    }
  };

  const handleResendEmail = async () => {
    if (!email.trim()) {
      setError('Please enter your email address');
      return;
    }

    setResendLoading(true);
    setError('');

    try {
      await authApi.resendVerificationEmail(email.trim());
      alert('Verification email sent! Please check your inbox.');
    } catch (err: any) {
      console.error('Resend error:', err);
      setError(err.response?.data?.detail || 'Failed to resend verification email');
    } finally {
      setResendLoading(false);
    }
  };

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, 6); // Only digits, max 6
    setVerificationCode(value);
    setError('');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleVerify();
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900">
            <svg
              className="h-6 w-6 text-blue-600 dark:text-blue-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
              />
            </svg>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
            {success ? 'Email Verified!' : 'Verify Your Email'}
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
            {success
              ? `Your email ${verifiedEmail} has been verified successfully.`
              : 'Enter the 6-digit code sent to your email address'}
          </p>
        </div>

        {!success ? (
          <>
            {/* Verification Code Form */}
            <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
              <div className="rounded-md shadow-sm space-y-4">
                {/* Code Input */}
                <div>
                  <label htmlFor="code" className="sr-only">
                    Verification Code
                  </label>
                  <input
                    id="code"
                    name="code"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={verificationCode}
                    onChange={handleCodeChange}
                    className="appearance-none relative block w-full px-3 py-3 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm bg-white dark:bg-gray-800 text-center tracking-widest text-2xl font-mono"
                    placeholder="000000"
                    disabled={loading || autoVerifying}
                  />
                  <p className="mt-2 text-xs text-gray-500 dark:text-gray-400 text-center">
                    Enter the 6-digit code from your email
                  </p>
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg
                        className="h-5 w-5 text-red-400"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fillRule="evenodd"
                          d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                          clipRule="evenodd"
                        />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Verify Button */}
              <div>
                <button
                  type="submit"
                  disabled={loading || autoVerifying || verificationCode.length !== 6}
                  className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                >
                  {loading || autoVerifying ? (
                    <>
                      <svg
                        className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        />
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        />
                      </svg>
                      Verifying...
                    </>
                  ) : (
                    'Verify Email'
                  )}
                </button>
              </div>
            </form>

            {/* Divider */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300 dark:border-gray-600" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">
                  Didn't receive the code?
                </span>
              </div>
            </div>

            {/* Resend Email Section */}
            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="sr-only">
                  Email address
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    setError('');
                  }}
                  className="appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm bg-white dark:bg-gray-800"
                  placeholder="Enter your email address"
                  disabled={resendLoading}
                />
              </div>

              <button
                type="button"
                onClick={handleResendEmail}
                disabled={resendLoading || !email.trim()}
                className="w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-lg text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-100 dark:disabled:bg-gray-800 disabled:cursor-not-allowed transition-colors"
              >
                {resendLoading ? (
                  <>
                    <svg
                      className="animate-spin -ml-1 mr-3 h-5 w-5 text-gray-700 dark:text-gray-300"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    Sending...
                  </>
                ) : (
                  'Resend Verification Email'
                )}
              </button>
            </div>
          </>
        ) : (
          /* Success State */
          <div className="rounded-md bg-green-50 dark:bg-green-900/20 p-6">
            <div className="flex flex-col items-center">
              <div className="flex-shrink-0">
                <svg
                  className="h-12 w-12 text-green-400"
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
              <div className="mt-3 text-center">
                <h3 className="text-lg font-medium text-green-800 dark:text-green-200">
                  Verification Successful!
                </h3>
                <p className="mt-2 text-sm text-green-700 dark:text-green-300">
                  Redirecting you to login page...
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Back to Login Link */}
        <div className="text-center">
          <Link
            to="/login"
            className="font-medium text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300"
          >
            Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
}
