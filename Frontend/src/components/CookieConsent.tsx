// src/components/CookieConsent.tsx
/**
 * GDPR Cookie Consent Banner
 * UK GDPR Compliant - Requires explicit consent before tracking
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Cookie, X, Settings, Check } from 'lucide-react';
import { useCookieConsent } from '../hooks/useCookieConsent';

export const CookieConsent: React.FC = () => {
  const {
    hasConsent,
    preferences,
    acceptAll,
    rejectAll,
    savePreferences,
  } = useCookieConsent();

  const [showBanner, setShowBanner] = useState(false);
  const [showCustomize, setShowCustomize] = useState(false);
  const [customPrefs, setCustomPrefs] = useState({
    necessary: true, // Always required
    analytics: false,
    marketing: false,
    functional: false,
  });

  useEffect(() => {
    // Show banner if no consent decision made, hide if consent exists
    if (hasConsent === null) {
      setShowBanner(true);
    } else if (hasConsent === true) {
      setShowBanner(false);
    }
  }, [hasConsent]);

  const handleAcceptAll = () => {
    acceptAll();
    setShowBanner(false);
    setShowCustomize(false);
  };

  const handleRejectAll = () => {
    rejectAll();
    setShowBanner(false);
    setShowCustomize(false);
  };

  const handleSaveCustom = () => {
    savePreferences(customPrefs);
    setShowBanner(false);
    setShowCustomize(false);
  };

  const handleCustomize = () => {
    setCustomPrefs({
      necessary: true,
      analytics: preferences?.analytics || false,
      marketing: preferences?.marketing || false,
      functional: preferences?.functional || false,
    });
    setShowCustomize(true);
  };

  // Don't show banner if consent already given
  if (!showBanner) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ y: 100, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: 100, opacity: 0 }}
        className="fixed bottom-0 left-0 right-0 z-50 p-4 sm:p-6"
      >
        <div className="max-w-6xl mx-auto bg-white dark:bg-gray-800 rounded-2xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          {!showCustomize ? (
            // Main Banner
            <div className="p-6 sm:p-8">
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">
                  <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center">
                    <Cookie className="text-blue-600 dark:text-blue-400" size={24} />
                  </div>
                </div>
                <div className="flex-1">
                  <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                    We Value Your Privacy
                  </h3>
                  <p className="text-gray-600 dark:text-gray-300 text-sm sm:text-base mb-4">
                    We use cookies to enhance your browsing experience, analyse site traffic, and provide personalised content.
                    By clicking "Accept All", you consent to our use of cookies. You can customise your preferences or reject
                    non-essential cookies.{' '}
                    <a
                      href="/privacy"
                      className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Privacy Policy
                    </a>
                  </p>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <button
                      onClick={handleAcceptAll}
                      className="px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
                    >
                      <Check size={20} />
                      Accept All
                    </button>
                    <button
                      onClick={handleRejectAll}
                      className="px-6 py-3 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg font-semibold hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                    >
                      Reject All
                    </button>
                    <button
                      onClick={handleCustomize}
                      className="px-6 py-3 border-2 border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg font-semibold hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center justify-center gap-2"
                    >
                      <Settings size={20} />
                      Customise
                    </button>
                  </div>
                </div>
                <button
                  onClick={() => setShowBanner(false)}
                  className="flex-shrink-0 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                  aria-label="Close banner"
                >
                  <X size={24} />
                </button>
              </div>
            </div>
          ) : (
            // Customize Panel
            <div className="p-6 sm:p-8">
              <div className="mb-6">
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                  Cookie Preferences
                </h3>
                <p className="text-gray-600 dark:text-gray-300 text-sm">
                  Choose which cookies you want to allow. You can change your preferences at any time.
                </p>
              </div>

              <div className="space-y-4 mb-6">
                {/* Necessary Cookies */}
                <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-semibold text-gray-900 dark:text-white mb-1">
                        Necessary Cookies
                      </h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Required for the website to function properly. Cannot be disabled.
                      </p>
                    </div>
                    <div className="ml-4 flex-shrink-0">
                      <input
                        type="checkbox"
                        checked={true}
                        disabled
                        className="w-5 h-5 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 opacity-50 cursor-not-allowed"
                      />
                    </div>
                  </div>
                </div>

                {/* Analytics Cookies */}
                <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-semibold text-gray-900 dark:text-white mb-1">
                        Analytics Cookies
                      </h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Help us understand how visitors interact with our website by collecting anonymous data.
                      </p>
                    </div>
                    <div className="ml-4 flex-shrink-0">
                      <input
                        type="checkbox"
                        checked={customPrefs.analytics}
                        onChange={(e) =>
                          setCustomPrefs({ ...customPrefs, analytics: e.target.checked })
                        }
                        className="w-5 h-5 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
                      />
                    </div>
                  </div>
                </div>

                {/* Functional Cookies */}
                <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-semibold text-gray-900 dark:text-white mb-1">
                        Functional Cookies
                      </h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Enable enhanced functionality and personalisation, such as remembering your preferences.
                      </p>
                    </div>
                    <div className="ml-4 flex-shrink-0">
                      <input
                        type="checkbox"
                        checked={customPrefs.functional}
                        onChange={(e) =>
                          setCustomPrefs({ ...customPrefs, functional: e.target.checked })
                        }
                        className="w-5 h-5 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
                      />
                    </div>
                  </div>
                </div>

                {/* Marketing Cookies */}
                <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-semibold text-gray-900 dark:text-white mb-1">
                        Marketing Cookies
                      </h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Used to track visitors across websites to display relevant advertisements.
                      </p>
                    </div>
                    <div className="ml-4 flex-shrink-0">
                      <input
                        type="checkbox"
                        checked={customPrefs.marketing}
                        onChange={(e) =>
                          setCustomPrefs({ ...customPrefs, marketing: e.target.checked })
                        }
                        className="w-5 h-5 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <button
                  onClick={handleSaveCustom}
                  className="flex-1 px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
                >
                  <Check size={20} />
                  Save Preferences
                </button>
                <button
                  onClick={() => setShowCustomize(false)}
                  className="px-6 py-3 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg font-semibold hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default CookieConsent;
