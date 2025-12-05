// src/hooks/useCookieConsent.ts
/**
 * Custom hook for managing GDPR cookie consent
 * Stores preferences in localStorage
 */

import { useState, useEffect } from 'react';

export interface CookiePreferences {
  necessary: boolean; // Always true
  analytics: boolean;
  marketing: boolean;
  functional: boolean;
}

interface ConsentData {
  preferences: CookiePreferences;
  timestamp: string;
  version: string; // For tracking policy changes
}

const STORAGE_KEY = 'cookie_consent';
const CONSENT_VERSION = '1.0'; // Increment when privacy policy changes

export const useCookieConsent = () => {
  const [hasConsent, setHasConsent] = useState<boolean | null>(null);
  const [preferences, setPreferences] = useState<CookiePreferences>({
    necessary: true,
    analytics: false,
    marketing: false,
    functional: false,
  });

  useEffect(() => {
    // Load existing consent on mount
    loadConsent();
  }, []);

  const loadConsent = () => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) {
        setHasConsent(null);
        return;
      }

      const data: ConsentData = JSON.parse(stored);

      // Check if consent is for current policy version
      if (data.version !== CONSENT_VERSION) {
        // Policy changed, require new consent
        setHasConsent(null);
        localStorage.removeItem(STORAGE_KEY);
        return;
      }

      setPreferences(data.preferences);
      setHasConsent(true);
    } catch (error) {
      console.error('Error loading cookie consent:', error);
      setHasConsent(null);
    }
  };

  const saveConsent = (prefs: CookiePreferences) => {
    const data: ConsentData = {
      preferences: prefs,
      timestamp: new Date().toISOString(),
      version: CONSENT_VERSION,
    };

    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
      setPreferences(prefs);
      setHasConsent(true);

      // Trigger consent update event for analytics/tracking scripts
      window.dispatchEvent(
        new CustomEvent('cookieConsentUpdated', { detail: prefs })
      );
    } catch (error) {
      console.error('Error saving cookie consent:', error);
    }
  };

  const acceptAll = () => {
    saveConsent({
      necessary: true,
      analytics: true,
      marketing: true,
      functional: true,
    });
  };

  const rejectAll = () => {
    saveConsent({
      necessary: true,
      analytics: false,
      marketing: false,
      functional: false,
    });
  };

  const savePreferences = (prefs: CookiePreferences) => {
    // Necessary cookies always required
    saveConsent({
      ...prefs,
      necessary: true,
    });
  };

  const revokeConsent = () => {
    localStorage.removeItem(STORAGE_KEY);
    setHasConsent(null);
    setPreferences({
      necessary: true,
      analytics: false,
      marketing: false,
      functional: false,
    });
  };

  return {
    hasConsent,
    preferences,
    acceptAll,
    rejectAll,
    savePreferences,
    revokeConsent,
    canUseAnalytics: preferences.analytics,
    canUseMarketing: preferences.marketing,
    canUseFunctional: preferences.functional,
  };
};

export default useCookieConsent;
