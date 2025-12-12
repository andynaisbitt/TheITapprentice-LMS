// src/components/analytics/GoogleAdSense.tsx
/**
 * Google AdSense Auto Ads Component - SECURE VERSION
 * Implements CSP-compliant Auto Ads with validation
 *
 * Security Features:
 * - Client ID validation (prevents injection attacks)
 * - No innerHTML usage (CSP compliant)
 * - Environment-based loading
 * - Integrates with Google Consent Mode v2
 */

import { useEffect } from 'react';
import { useSiteSettings } from '../../hooks/useSiteSettings';
import { validateAdSenseId, sanitizeId, shouldLoadAnalytics } from '../../utils/analytics';

declare global {
  interface Window {
    adsbygoogle?: any[];
  }
}

/**
 * GoogleAdSense Component
 * Loads Auto Ads script globally for automatic ad placement
 * Configure client ID in Admin → Site Settings → Analytics & Ads
 */
export const GoogleAdSense: React.FC = () => {
  const { settings } = useSiteSettings();

  // Initialize AdSense Auto Ads once
  useEffect(() => {
    if (!shouldLoadAnalytics()) {
      console.log('[AdSense] Auto Ads disabled (dev mode)');
      return;
    }

    const clientId = settings.googleAdsenseClientId;
    if (!clientId) {
      console.log('[AdSense] No client ID configured - Auto Ads disabled');
      return;
    }

    // SECURITY: Validate client ID format (ca-pub-XXXXXXXXXXXXXXXX)
    if (!validateAdSenseId(clientId)) {
      console.error('[AdSense] Invalid client ID format:', clientId);
      return;
    }

    const safeClientId = sanitizeId(clientId);

    // Check if already loaded (either by index.html or previous component mount)
    if (document.querySelector('[src*="adsbygoogle.js"]')) {
      console.log('[AdSense] Auto Ads script already present in HTML');
      return;
    }

    console.log('[AdSense] Dynamically loading Auto Ads:', safeClientId);

    // Initialize adsbygoogle array
    window.adsbygoogle = window.adsbygoogle || [];

    // SECURITY: Load script via createElement (no innerHTML)
    const script = document.createElement('script');
    script.async = true;
    script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${encodeURIComponent(safeClientId)}`;
    script.crossOrigin = 'anonymous'; // Additional security

    script.onerror = () => {
      console.error('[AdSense] Failed to load Auto Ads script');
    };

    script.onload = () => {
      console.log('[AdSense] Auto Ads loaded successfully');
      console.log('[AdSense] Auto Ads will be placed automatically by Google');
    };

    document.head.appendChild(script);
  }, [settings.googleAdsenseClientId]);

  return null; // Silent background component
};

export default GoogleAdSense;
