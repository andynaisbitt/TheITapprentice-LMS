// src/pages/Unsubscribe.tsx
/**
 * Newsletter Unsubscribe Page
 * Public page for users to unsubscribe from newsletter
 */

import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { CheckCircle, XCircle, Mail, Loader2 } from 'lucide-react';

export const Unsubscribe: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Get email from URL if provided
  useEffect(() => {
    const emailParam = searchParams.get('email');
    if (emailParam) {
      setEmail(emailParam);
    }
  }, [searchParams]);

  const handleUnsubscribe = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) {
      setError('Please enter your email address');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`/api/v1/newsletter/unsubscribe/${encodeURIComponent(email)}`, {
        method: 'GET',
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess(true);
      } else {
        setError(data.detail || 'Failed to unsubscribe. Please try again.');
      }
    } catch (err) {
      console.error('Unsubscribe error:', err);
      setError('Failed to unsubscribe. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {success ? (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl border border-gray-200 dark:border-slate-700 p-8 text-center"
          >
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.2, type: 'spring' }}
              className="w-16 h-16 mx-auto mb-4 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center"
            >
              <CheckCircle className="text-green-600 dark:text-green-400" size={32} />
            </motion.div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
              Successfully Unsubscribed
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              You've been removed from our newsletter list. We're sorry to see you go!
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-500">
              You can re-subscribe at any time from our website.
            </p>
          </motion.div>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl border border-gray-200 dark:border-slate-700 overflow-hidden"
          >
            {/* Header */}
            <div className="bg-gradient-to-br from-gray-600 to-gray-700 dark:from-gray-700 dark:to-gray-800 p-8 text-center">
              <div className="w-16 h-16 mx-auto mb-4 bg-white/20 backdrop-blur-sm rounded-full flex items-center justify-center">
                <Mail className="text-white" size={32} />
              </div>
              <h1 className="text-2xl font-bold text-white mb-2">
                Unsubscribe from Newsletter
              </h1>
              <p className="text-gray-200">
                We're sorry to see you go
              </p>
            </div>

            {/* Form */}
            <div className="p-8">
              <form onSubmit={handleUnsubscribe} className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Email Address
                  </label>
                  <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    required
                    className="w-full px-4 py-3 bg-gray-50 dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:border-transparent transition"
                  />
                </div>

                {error && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-start gap-3"
                  >
                    <XCircle className="text-red-600 dark:text-red-400 flex-shrink-0" size={20} />
                    <p className="text-sm text-red-800 dark:text-red-300">
                      {error}
                    </p>
                  </motion.div>
                )}

                <button
                  type="submit"
                  disabled={loading || !email}
                  className="w-full px-6 py-3 bg-gray-600 dark:bg-gray-700 text-white rounded-lg hover:bg-gray-700 dark:hover:bg-gray-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <Loader2 className="animate-spin" size={20} />
                      Unsubscribing...
                    </>
                  ) : (
                    'Unsubscribe'
                  )}
                </button>
              </form>

              <p className="mt-6 text-xs text-center text-gray-500 dark:text-gray-400">
                Changed your mind? You can always re-subscribe from our website.
              </p>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default Unsubscribe;
