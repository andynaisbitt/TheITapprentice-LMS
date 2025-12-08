// src/components/NewsletterModal.tsx
/**
 * Newsletter Subscription Modal
 * Can be triggered anywhere in the app
 */

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Mail, Check } from 'lucide-react';

interface NewsletterModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NewsletterModal: React.FC<NewsletterModalProps> = ({ isOpen, onClose }) => {
  const [email, setEmail] = useState('');
  const [subscribed, setSubscribed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) return;

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/v1/newsletter/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        setSubscribed(true);
        setEmail('');
        // Auto-close after 3 seconds
        setTimeout(() => {
          onClose();
          // Reset state for next open
          setTimeout(() => {
            setSubscribed(false);
          }, 300);
        }, 3000);
      } else {
        setError(data.detail || 'Subscription failed. Please try again.');
      }
    } catch (error) {
      console.error('Newsletter subscription error:', error);
      setError('Failed to subscribe. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ type: 'spring', duration: 0.3 }}
            className="relative bg-white dark:bg-slate-800 rounded-2xl shadow-2xl max-w-md w-full overflow-hidden"
          >
            {/* Close Button */}
            <button
              onClick={onClose}
              className="absolute top-4 right-4 p-2 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 transition z-10"
              aria-label="Close"
            >
              <X size={20} />
            </button>

            {/* Success State */}
            {subscribed ? (
              <div className="p-8 text-center">
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', delay: 0.1 }}
                  className="w-16 h-16 mx-auto mb-4 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center"
                >
                  <Check className="text-green-600 dark:text-green-400" size={32} />
                </motion.div>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
                  You're Subscribed!
                </h3>
                <p className="text-gray-600 dark:text-gray-400">
                  Thank you for subscribing to our newsletter. You'll receive our latest posts directly in your inbox.
                </p>
              </div>
            ) : (
              <>
                {/* Header with Icon */}
                <div className="bg-gradient-to-br from-blue-600 to-indigo-600 dark:from-blue-700 dark:to-indigo-700 p-8 text-center">
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: 'spring', delay: 0.1 }}
                    className="w-16 h-16 mx-auto mb-4 bg-white/20 backdrop-blur-sm rounded-full flex items-center justify-center"
                  >
                    <Mail className="text-white" size={32} />
                  </motion.div>
                  <h2 className="text-2xl font-bold text-white mb-2">
                    Subscribe to Our Newsletter
                  </h2>
                  <p className="text-blue-100">
                    Get the latest articles delivered straight to your inbox
                  </p>
                </div>

                {/* Form */}
                <div className="p-8">
                  <form onSubmit={handleSubmit} className="space-y-4">
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
                        className="w-full px-4 py-3 bg-gray-50 dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                      />
                    </div>

                    {error && (
                      <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3"
                      >
                        <p className="text-sm text-red-800 dark:text-red-300">
                          {error}
                        </p>
                      </motion.div>
                    )}

                    <button
                      type="submit"
                      disabled={loading || !email}
                      className="w-full px-6 py-3 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    >
                      {loading ? (
                        <>
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                          Subscribing...
                        </>
                      ) : (
                        <>
                          <Mail size={20} />
                          Subscribe Now
                        </>
                      )}
                    </button>
                  </form>

                  <p className="mt-4 text-xs text-center text-gray-500 dark:text-gray-400">
                    No spam, unsubscribe anytime. We respect your privacy.
                  </p>
                </div>
              </>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default NewsletterModal;
