/**
 * Google Consent Mode v2 Integration
 * Communicates consent status to Google Analytics and AdSense
 *
 * Required for AdSense EU User Consent Policy compliance
 * Integrates with existing CookieConsent component
 */

declare global {
  interface Window {
    dataLayer?: any[];
    gtag?: (...args: any[]) => void;
  }
}

/**
 * Initialize Google Consent Mode v2 with default deny state
 * MUST be called BEFORE any Google scripts load
 */
export const initializeConsentMode = () => {
  // Initialize dataLayer if not exists
  window.dataLayer = window.dataLayer || [];

  function gtag(...args: any[]) {
    window.dataLayer!.push(arguments);
  }

  // Set default consent state (denied until user accepts)
  gtag('consent', 'default', {
    'ad_storage': 'denied',          // AdSense ads
    'ad_user_data': 'denied',        // Ad personalization
    'ad_personalization': 'denied',  // Ad targeting
    'analytics_storage': 'denied',   // Google Analytics
    'functionality_storage': 'denied', // Functional cookies
    'personalization_storage': 'denied', // Personalization cookies
    'security_storage': 'granted',   // Security cookies (always allowed)
    'wait_for_update': 500,          // Wait 500ms for user consent
  });

  // EU/UK/CH region targeting (for GDPR)
  gtag('set', 'ads_data_redaction', true);
  gtag('set', 'url_passthrough', true);

  console.log('[Consent Mode] Initialized with default deny state');
};

/**
 * Update consent based on user preferences
 * Called when user accepts/rejects cookies
 */
export interface ConsentPreferences {
  necessary: boolean;
  analytics: boolean;
  marketing: boolean;
  functional: boolean;
}

export const updateConsentMode = (preferences: ConsentPreferences) => {
  if (!window.dataLayer) {
    console.warn('[Consent Mode] dataLayer not initialized');
    return;
  }

  function gtag(...args: any[]) {
    window.dataLayer!.push(arguments);
  }

  // Map our cookie preferences to Google Consent Mode signals
  gtag('consent', 'update', {
    'ad_storage': preferences.marketing ? 'granted' : 'denied',
    'ad_user_data': preferences.marketing ? 'granted' : 'denied',
    'ad_personalization': preferences.marketing ? 'granted' : 'denied',
    'analytics_storage': preferences.analytics ? 'granted' : 'denied',
    'functionality_storage': preferences.functional ? 'granted' : 'denied',
    'personalization_storage': preferences.functional ? 'granted' : 'denied',
  });

  console.log('[Consent Mode] Updated consent:', {
    ads: preferences.marketing ? 'granted' : 'denied',
    analytics: preferences.analytics ? 'granted' : 'denied',
    functional: preferences.functional ? 'granted' : 'denied',
  });
};

/**
 * Get current consent status
 * Useful for debugging
 */
export const getConsentStatus = () => {
  if (!window.dataLayer) {
    return null;
  }

  // Try to read from localStorage (our cookie consent storage)
  try {
    const stored = localStorage.getItem('cookie_consent');
    if (!stored) return null;

    const data = JSON.parse(stored);
    return data.preferences;
  } catch (error) {
    console.error('[Consent Mode] Error reading consent:', error);
    return null;
  }
};

/**
 * Initialize consent mode from stored preferences
 * Called on page load
 */
export const initializeFromStorage = () => {
  const preferences = getConsentStatus();

  if (preferences) {
    // User has already made a choice - update consent
    updateConsentMode(preferences);
    console.log('[Consent Mode] Restored from storage');
  } else {
    // No stored preferences - wait for user to interact with banner
    console.log('[Consent Mode] Waiting for user consent');
  }
};
