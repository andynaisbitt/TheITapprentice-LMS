// src/pages/admin/Newsletter.tsx
/**
 * Newsletter Subscribers Management Page
 * View, manage, and send newsletters to subscribers
 * Mobile-optimized with search and compact layout
 */

import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { Search, X } from 'lucide-react';

interface Subscriber {
  id: number;
  email: string;
  is_active: boolean;
  subscribed_at: string;
}

export const Newsletter: React.FC = () => {
  const navigate = useNavigate();
  const [subscribers, setSubscribers] = useState<Subscriber[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showSendModal, setShowSendModal] = useState(false);
  const [newsletter, setNewsletter] = useState({ subject: '', body: '' });
  const [sending, setSending] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch subscribers on mount
  useEffect(() => {
    fetchSubscribers();
  }, []);

  const fetchSubscribers = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/v1/admin/newsletter/subscribers', {
        credentials: 'include'
      });

      if (!response.ok) {
        throw new Error('Failed to fetch subscribers');
      }

      const data = await response.json();

      // Ensure data is an array
      if (Array.isArray(data)) {
        setSubscribers(data);
      } else if (data && Array.isArray(data.subscribers)) {
        setSubscribers(data.subscribers);
      } else {
        console.error('Unexpected data format:', data);
        setSubscribers([]);
      }
    } catch (err) {
      console.error('Error fetching subscribers:', err);
      setError('Failed to load subscribers. Please try again.');
      setSubscribers([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: number, email: string) => {
    if (!confirm(`Remove ${email}?`)) {
      return;
    }

    try {
      const response = await fetch(`/api/v1/admin/newsletter/subscribers/${id}`, {
        method: 'DELETE',
        credentials: 'include'
      });

      if (!response.ok) {
        throw new Error('Failed to remove subscriber');
      }

      setSubscribers(subscribers.filter(s => s.id !== id));
      setSuccess(`${email} removed`);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      console.error('Error removing subscriber:', err);
      setError('Failed to remove subscriber');
      setTimeout(() => setError(null), 3000);
    }
  };

  const handleSendNewsletter = async () => {
    if (!newsletter.subject.trim() || !newsletter.body.trim()) {
      setError('Please fill in both subject and body');
      return;
    }

    try {
      setSending(true);
      setError(null);

      const response = await fetch('/api/v1/admin/newsletter/send-to-all', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          subject: newsletter.subject,
          body: newsletter.body
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to send newsletter');
      }

      setSuccess(`Sent to ${data.sent} subscribers!`);
      setShowSendModal(false);
      setNewsletter({ subject: '', body: '' });
      setTimeout(() => setSuccess(null), 5000);
    } catch (err: any) {
      console.error('Error sending newsletter:', err);
      setError(err.message || 'Failed to send. Check SMTP settings.');
    } finally {
      setSending(false);
    }
  };

  // Filtered subscribers based on search
  const filteredSubscribers = useMemo(() => {
    if (!searchQuery.trim()) return subscribers;
    const query = searchQuery.toLowerCase();
    return subscribers.filter(s => s.email.toLowerCase().includes(query));
  }, [subscribers, searchQuery]);

  const activeSubscribers = Array.isArray(subscribers) ? subscribers.filter(s => s.is_active) : [];

  if (loading && subscribers.length === 0) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-3 sm:py-6">
      <div className="max-w-6xl mx-auto px-3 sm:px-6">
        {/* Compact Header */}
        <div className="mb-3 sm:mb-6">
          <h1 className="text-xl sm:text-3xl font-bold text-gray-900 dark:text-gray-100 mb-1">
            Newsletter
          </h1>
          <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">
            {subscribers.length} subscriber{subscribers.length !== 1 ? 's' : ''}
          </p>
        </div>

        {/* Error/Success Alerts - Compact */}
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mb-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-2 sm:p-3"
            >
              <p className="text-xs sm:text-sm text-red-800 dark:text-red-300">
                ⚠️ {error}
              </p>
            </motion.div>
          )}

          {success && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mb-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-2 sm:p-3"
            >
              <p className="text-xs sm:text-sm text-green-800 dark:text-green-300">
                ✓ {success}
              </p>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Ultra-Compact Stats + Actions Row */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 p-2 sm:p-3 mb-3">
          {/* Stats - Single Row */}
          <div className="grid grid-cols-3 gap-2 sm:gap-3 mb-3">
            <div className="text-center py-1">
              <p className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-gray-100">{subscribers.length}</p>
              <p className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Total</p>
            </div>
            <div className="text-center py-1 border-l border-r border-gray-200 dark:border-slate-600">
              <p className="text-lg sm:text-2xl font-bold text-green-600 dark:text-green-400">{activeSubscribers.length}</p>
              <p className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Active</p>
            </div>
            <div className="text-center py-1">
              <p className="text-lg sm:text-2xl font-bold text-gray-500 dark:text-gray-400">
                {subscribers.length - activeSubscribers.length}
              </p>
              <p className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Inactive</p>
            </div>
          </div>

          {/* Actions - Compact Row */}
          <div className="flex gap-1.5 sm:gap-2">
            <button
              onClick={() => setShowSendModal(true)}
              disabled={activeSubscribers.length === 0}
              className="flex-1 px-2 sm:px-3 py-1.5 sm:py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-md hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed text-xs sm:text-sm"
            >
              <span className="hidden xs:inline">📧 </span>Send
            </button>
            <button
              onClick={fetchSubscribers}
              className="px-2 sm:px-3 py-1.5 sm:py-2 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-slate-600 rounded-md hover:bg-gray-100 dark:hover:bg-slate-700 transition text-xs sm:text-sm"
              title="Refresh"
            >
              🔄
            </button>
            <button
              onClick={() => navigate('/admin/settings')}
              className="px-2 sm:px-3 py-1.5 sm:py-2 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-slate-600 rounded-md hover:bg-gray-100 dark:hover:bg-slate-700 transition text-xs sm:text-sm"
              title="Settings"
            >
              ⚙️
            </button>
          </div>
        </div>

        {/* Search Bar - Sticky on Mobile */}
        <div className="sticky top-0 z-10 bg-gray-50 dark:bg-slate-900 pb-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search subscribers..."
              className="w-full pl-9 pr-9 py-2 sm:py-2.5 bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 rounded-lg text-sm text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-gray-200 dark:hover:bg-slate-700 rounded"
              >
                <X size={14} className="text-gray-400" />
              </button>
            )}
          </div>
          {searchQuery && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1.5">
              {filteredSubscribers.length} of {subscribers.length} shown
            </p>
          )}
        </div>

        {/* Subscribers List - Ultra Compact Cards */}
        <div className="space-y-1.5 sm:space-y-2">
          {filteredSubscribers.length === 0 ? (
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 p-8 sm:p-12 text-center">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {searchQuery ? 'No subscribers found' : 'No subscribers yet'}
              </p>
            </div>
          ) : (
            filteredSubscribers.map((subscriber) => (
              <div
                key={subscriber.id}
                className="bg-white dark:bg-slate-800 rounded-md shadow-sm border border-gray-200 dark:border-slate-700 p-2 sm:p-3 hover:shadow transition"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs sm:text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                      {subscriber.email}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      <span
                        className={`inline-flex px-1.5 py-0.5 text-[10px] sm:text-xs font-medium rounded ${
                          subscriber.is_active
                            ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                            : 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300'
                        }`}
                      >
                        {subscriber.is_active ? 'Active' : 'Inactive'}
                      </span>
                      <span className="text-[10px] sm:text-xs text-gray-500 dark:text-gray-400">
                        {new Date(subscriber.subscribed_at).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          year: '2-digit'
                        })}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDelete(subscriber.id, subscriber.email)}
                    className="flex-shrink-0 px-2 sm:px-3 py-1 sm:py-1.5 text-[10px] sm:text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition"
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Back Button - Compact */}
        <div className="mt-4 sm:mt-6">
          <button
            onClick={() => navigate('/admin')}
            className="px-3 sm:px-4 py-1.5 sm:py-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-slate-600 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 transition"
          >
            ← Back
          </button>
        </div>
      </div>

      {/* Send Newsletter Modal */}
      <AnimatePresence>
        {showSendModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-3 sm:p-4 z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white dark:bg-slate-800 rounded-lg shadow-xl border border-gray-200 dark:border-slate-700 max-w-2xl w-full p-4 sm:p-6 max-h-[90vh] overflow-y-auto"
            >
              <h2 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2 sm:mb-4">
                Send Newsletter
              </h2>
              <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mb-4 sm:mb-6">
                Send to {activeSubscribers.length} active subscriber{activeSubscribers.length !== 1 ? 's' : ''}
              </p>

              <div className="space-y-3 sm:space-y-4 mb-4 sm:mb-6">
                <div>
                  <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5 sm:mb-2">
                    Subject
                  </label>
                  <input
                    type="text"
                    value={newsletter.subject}
                    onChange={(e) => setNewsletter({ ...newsletter, subject: e.target.value })}
                    placeholder="Newsletter subject..."
                    className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5 sm:mb-2">
                    Body <span className="text-gray-500">(HTML supported)</span>
                  </label>
                  <textarea
                    value={newsletter.body}
                    onChange={(e) => setNewsletter({ ...newsletter, body: e.target.value })}
                    rows={8}
                    placeholder="Newsletter content... (HTML is supported)"
                    className="w-full px-3 sm:px-4 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-slate-600 rounded-lg text-sm text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono"
                  />
                </div>
              </div>

              <div className="flex gap-2 sm:gap-3">
                <button
                  onClick={() => setShowSendModal(false)}
                  disabled={sending}
                  className="flex-1 px-3 sm:px-4 py-2 text-sm sm:text-base text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-slate-600 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSendNewsletter}
                  disabled={sending || !newsletter.subject.trim() || !newsletter.body.trim()}
                  className="flex-1 px-3 sm:px-4 py-2 text-sm sm:text-base bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {sending ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                      Sending...
                    </>
                  ) : (
                    <>
                      📧 <span className="hidden xs:inline">Send to</span> {activeSubscribers.length}
                    </>
                  )}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default Newsletter;
