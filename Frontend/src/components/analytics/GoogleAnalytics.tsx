// src/components/analytics/GoogleAnalytics.tsx
/**
 * Google Analytics Integration
 * Add this component to App.tsx to enable GA tracking
 */

import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

// Get GA Measurement ID from environment variable
const GA_MEASUREMENT_ID = import.meta.env.VITE_GA_MEASUREMENT_ID || '';

/**
 * Initialize Google Analytics
 * Call this once in App.tsx
 */
export const initGA = () => {
  if (!GA_MEASUREMENT_ID) {
    console.warn('Google Analytics: VITE_GA_MEASUREMENT_ID not set in .env file');
    return;
  }

  // Load GA script
  const script1 = document.createElement('script');
  script1.async = true;
  script1.src = `https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`;
  document.head.appendChild(script1);

  // Initialize GA
  const script2 = document.createElement('script');
  script2.innerHTML = `
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', '${GA_MEASUREMENT_ID}', {
      page_path: window.location.pathname,
      page_title: document.title,
    });
  `;
  document.head.appendChild(script2);

  console.log('Google Analytics initialized:', GA_MEASUREMENT_ID);
};

/**
 * Track page views
 * Use this component in App.tsx to track route changes
 */
export const GoogleAnalytics = () => {
  const location = useLocation();

  useEffect(() => {
    if (!GA_MEASUREMENT_ID || typeof window.gtag === 'undefined') {
      return;
    }

    // Track page view
    window.gtag('config', GA_MEASUREMENT_ID, {
      page_path: location.pathname + location.search,
      page_title: document.title,
    });

    console.log('GA Page View:', location.pathname);
  }, [location]);

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
  if (!GA_MEASUREMENT_ID || typeof window.gtag === 'undefined') {
    console.warn('Google Analytics not initialized');
    return;
  }

  window.gtag('event', eventName, parameters);
  console.log('GA Event:', eventName, parameters);
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

// TypeScript declarations
declare global {
  interface Window {
    dataLayer: any[];
    gtag: (
      command: string,
      targetId: string,
      config?: Record<string, any>
    ) => void;
  }
}

export default GoogleAnalytics;
