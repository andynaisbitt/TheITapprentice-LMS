// src/components/analytics/GoogleAnalytics.tsx
/**
 * Google Analytics 4 Component - SECURE VERSION
 * Implements CSP-compliant analytics with validation
 *
 * Security Features:
 * - ID validation (prevents injection attacks)
 * - No innerHTML usage (CSP compliant)
 * - DNT (Do Not Track) respect
 * - Environment-based loading
 */

import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useSiteSettings } from '../../hooks/useSiteSettings';
import { validateAnalyticsId, shouldLoadAnalytics, sanitizeId } from '../../utils/analytics';

declare global {
  interface Window {
    dataLayer?: any[];
    gtag?: (...args: any[]) => void;
  }
}

/**
 * GoogleAnalytics Component
 * Tracks page views and handles GA4 initialization
 */
export const GoogleAnalytics: React.FC = () => {
  const { settings } = useSiteSettings();
  const location = useLocation();

  // Initialize GA4 once
  useEffect(() => {
    if (!shouldLoadAnalytics()) {
      console.log('[GA] Analytics disabled (dev mode or DNT)');
      return;
    }

    const measurementId = settings.googleAnalyticsId;
    if (!measurementId) return;

    // SECURITY: Validate measurement ID format
    if (!validateAnalyticsId(measurementId)) {
      console.error('[GA] Invalid measurement ID format:', measurementId);
      return;
    }

    const safeId = sanitizeId(measurementId);

    // Check if already loaded
    if (window.gtag) {
      return;
    }

    console.log('[GA] Initializing Google Analytics:', safeId);

    // SECURITY: Initialize dataLayer without innerHTML
    window.dataLayer = window.dataLayer || [];
    window.gtag = function gtag(...args: any[]) {
      window.dataLayer!.push(arguments);
    };

    // Configure with privacy settings
    window.gtag('js', new Date());
    window.gtag('config', safeId, {
      anonymize_ip: true, // GDPR compliance
      cookie_flags: 'SameSite=None;Secure',
      send_page_view: true,
    });

    // SECURITY: Load script via createElement (no innerHTML)
    const script = document.createElement('script');
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(safeId)}`;
    script.crossOrigin = 'anonymous'; // Additional security

    script.onerror = () => {
      console.error('[GA] Failed to load script');
    };

    script.onload = () => {
      console.log('[GA] Loaded successfully');
    };

    document.head.appendChild(script);
  }, [settings.googleAnalyticsId]);

  // Track page views on route change
  useEffect(() => {
    if (!settings.googleAnalyticsId || !window.gtag) {
      return;
    }

    const safeId = sanitizeId(settings.googleAnalyticsId);

    // Track page view
    window.gtag('config', safeId, {
      page_path: location.pathname + location.search,
      page_title: document.title,
    });

    console.log('[GA] Page view:', location.pathname);
  }, [location, settings.googleAnalyticsId]);

  return null;
};

/**
 * Track custom events
 * Usage: trackEvent('button_click', { button_name: 'subscribe' })
 */
export const trackEvent = (
  eventName: string,
  parameters?: Record<string, any>
) => {
  if (!window.gtag) {
    console.warn('[GA] Not initialized');
    return;
  }

  window.gtag('event', eventName, parameters);
  console.log('[GA] Event:', eventName, parameters);
};

/**
 * Track blog post views
 */
export const trackBlogView = (postTitle: string, postSlug: string) => {
  trackEvent('blog_post_view', {
    post_title: postTitle,
    post_slug: postSlug,
  });
};

/**
 * Track search queries
 */
export const trackSearch = (searchTerm: string) => {
  trackEvent('search', {
    search_term: searchTerm,
  });
};

/**
 * Track newsletter subscriptions
 */
export const trackNewsletterSubscribe = (email: string) => {
  trackEvent('newsletter_subscribe', {
    email_domain: email.split('@')[1],
  });
};

/**
 * Track social media shares
 */
export const trackShare = (platform: string, postSlug: string) => {
  trackEvent('share', {
    platform,
    post_slug: postSlug,
  });
};

export default GoogleAnalytics;
