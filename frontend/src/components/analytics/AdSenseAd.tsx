// src/components/analytics/AdSenseAd.tsx
/**
 * Google AdSense Component - SECURE VERSION
 * Implements CSP-compliant ads with validation
 *
 * Security Features:
 * - Client ID validation (prevents injection attacks)
 * - CSP-compliant implementation
 * - Lazy loading for performance
 * - Error handling
 */

import { useEffect, useRef, useState } from 'react';
import { useSiteSettings } from '../../hooks/useSiteSettings';
import { validateAdSenseId, sanitizeId } from '../../utils/analytics';

declare global {
  interface Window {
    adsbygoogle?: any[];
  }
}

export interface AdSenseAdProps {
  slot: string; // Ad unit slot ID
  format?: 'auto' | 'rectangle' | 'vertical' | 'horizontal';
  responsive?: boolean;
  style?: React.CSSProperties;
  className?: string;
}

/**
 * AdSense Ad Component
 * Displays Google AdSense ads with security and performance optimization
 */
export const AdSenseAd: React.FC<AdSenseAdProps> = ({
  slot,
  format = 'auto',
  responsive = true,
  style,
  className = '',
}) => {
  const { settings } = useSiteSettings();
  const adRef = useRef<HTMLModElement>(null);
  const [adLoaded, setAdLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const clientId = settings.googleAdsenseClientId;

    // Don't load if no client ID
    if (!clientId) {
      console.log('[AdSense] No client ID configured');
      return;
    }

    // SECURITY: Validate client ID format
    if (!validateAdSenseId(clientId)) {
      const err = 'Invalid AdSense client ID format';
      console.error('[AdSense]', err, clientId);
      setError(err);
      return;
    }

    const safeClientId = sanitizeId(clientId);
    const safeSlot = sanitizeId(slot);

    // Load AdSense script if not already loaded
    if (!window.adsbygoogle && !document.querySelector('[src*="adsbygoogle.js"]')) {
      console.log('[AdSense] Loading script');

      // SECURITY: Load script via createElement (no innerHTML)
      const script = document.createElement('script');
      script.async = true;
      script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${encodeURIComponent(safeClientId)}`;
      script.crossOrigin = 'anonymous'; // Additional security

      script.onerror = () => {
        const err = 'Failed to load AdSense script';
        console.error('[AdSense]', err);
        setError(err);
      };

      script.onload = () => {
        console.log('[AdSense] Script loaded');
        window.adsbygoogle = window.adsbygoogle || [];
        setAdLoaded(true);
      };

      document.head.appendChild(script);
    } else {
      setAdLoaded(true);
    }
  }, [settings.googleAdsenseClientId, slot]);

  // Push ad when script is loaded
  useEffect(() => {
    if (!adLoaded || !adRef.current || error) {
      return;
    }

    try {
      // Initialize adsbygoogle array
      window.adsbygoogle = window.adsbygoogle || [];

      // Push ad
      (window.adsbygoogle as any[]).push({});
      console.log('[AdSense] Ad initialized:', slot);
    } catch (err) {
      console.error('[AdSense] Error initializing ad:', err);
      setError('Failed to initialize ad');
    }
  }, [adLoaded, slot, error]);

  // Don't render if no client ID or error
  if (!settings.googleAdsenseClientId || error) {
    return null;
  }

  const safeClientId = sanitizeId(settings.googleAdsenseClientId);
  const safeSlot = sanitizeId(slot);

  return (
    <div className={`adsense-container ${className}`} style={style}>
      <ins
        ref={adRef}
        className="adsbygoogle"
        style={{
          display: 'block',
          ...style,
        }}
        data-ad-client={safeClientId}
        data-ad-slot={safeSlot}
        data-ad-format={format}
        data-full-width-responsive={responsive ? 'true' : 'false'}
      />
    </div>
  );
};

/**
 * Predefined Ad Layouts
 */

// Article Ad (rectangle - in-article)
export const ArticleAd: React.FC<{ slot: string }> = ({ slot }) => (
  <AdSenseAd
    slot={slot}
    format="rectangle"
    style={{ marginTop: '20px', marginBottom: '20px' }}
    className="article-ad"
  />
);

// Sidebar Ad (vertical)
export const SidebarAd: React.FC<{ slot: string }> = ({ slot }) => (
  <AdSenseAd
    slot={slot}
    format="vertical"
    style={{ marginBottom: '20px' }}
    className="sidebar-ad"
  />
);

// Banner Ad (horizontal - top/bottom)
export const BannerAd: React.FC<{ slot: string }> = ({ slot }) => (
  <AdSenseAd
    slot={slot}
    format="horizontal"
    responsive={true}
    className="banner-ad"
  />
);

export default AdSenseAd;
