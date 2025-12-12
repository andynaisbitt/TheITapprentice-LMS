// src/utils/analytics.ts
/**
 * Analytics and AdSense Utilities
 * Validates and sanitizes analytics/ads IDs for security
 */

/**
 * Validate Google Analytics 4 Measurement ID format
 * Must match: G-XXXXXXXXXX (G- followed by 10 alphanumeric characters)
 */
export const validateAnalyticsId = (id: string): boolean => {
  if (!id || typeof id !== 'string') return false;
  const GA4_REGEX = /^G-[A-Z0-9]{10}$/;
  return GA4_REGEX.test(id);
};

/**
 * Validate Google AdSense Client ID format
 * Must match: ca-pub-XXXXXXXXXXXXXXXX (ca-pub- followed by 16 digits)
 */
export const validateAdSenseId = (id: string): boolean => {
  if (!id || typeof id !== 'string') return false;
  const ADSENSE_REGEX = /^ca-pub-\d{16}$/;
  return ADSENSE_REGEX.test(id);
};

/**
 * Sanitize ID by removing any potentially dangerous characters
 * Only allows alphanumeric, hyphens, and underscores
 */
export const sanitizeId = (id: string): string => {
  if (!id || typeof id !== 'string') return '';
  return id.replace(/[^a-zA-Z0-9\-_]/g, '');
};

/**
 * Check if analytics should be loaded (based on environment and consent)
 */
export const shouldLoadAnalytics = (): boolean => {
  // Don't load in development unless explicitly enabled
  if (import.meta.env.DEV && !import.meta.env.VITE_ANALYTICS_DEV) {
    return false;
  }

  // Don't load if user has DNT (Do Not Track) enabled
  if (navigator.doNotTrack === '1') {
    return false;
  }

  return true;
};

/**
 * Get nonce for CSP (if available from meta tag)
 * Used for inline scripts with Content Security Policy
 */
export const getCSPNonce = (): string | undefined => {
  const metaTag = document.querySelector('meta[property="csp-nonce"]');
  return metaTag?.getAttribute('content') || undefined;
};
