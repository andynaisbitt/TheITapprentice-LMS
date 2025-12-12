// src/hooks/useCookieConsent.ts
/**
 * Custom hook for managing GDPR cookie consent
 * Stores preferences in localStorage
 * Integrates with Google Consent Mode v2 for AdSense compliance
 */

import { useState, useEffect } from 'react';
import { updateConsentMode } from '../utils/googleConsentMode';

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

// Initialize state from localStorage immediately (before component renders)
const getInitialConsent = (): { hasConsent: boolean | null; preferences: CookiePreferences } => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) {
      return {
        hasConsent: null,
        preferences: {
          necessary: true,
          analytics: false,
          marketing: false,
          functional: false,
        },
      };
    }

    const data: ConsentData = JSON.parse(stored);

    // Check if consent is for current policy version
    if (data.version !== CONSENT_VERSION) {
      localStorage.removeItem(STORAGE_KEY);
      return {
        hasConsent: null,
        preferences: {
          necessary: true,
          analytics: false,
          marketing: false,
          functional: false,
        },
      };
    }

    return {
      hasConsent: true,
      preferences: data.preferences,
    };
  } catch (error) {
    console.error('Error loading cookie consent:', error);
    return {
      hasConsent: null,
      preferences: {
        necessary: true,
        analytics: false,
        marketing: false,
        functional: false,
      },
    };
  }
};

export const useCookieConsent = () => {
  const initialState = getInitialConsent();
  const [hasConsent, setHasConsent] = useState<boolean | null>(initialState.hasConsent);
  const [preferences, setPreferences] = useState<CookiePreferences>(initialState.preferences);

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

      // Update Google Consent Mode v2 (for AdSense compliance)
      updateConsentMode(prefs);

      // Trigger consent update event for analytics/tracking scripts
      window.dispatchEvent(
        new CustomEvent('cookieConsentUpdated', { detail: prefs })
      );

      console.log('[Cookie Consent] Saved preferences:', prefs);
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
