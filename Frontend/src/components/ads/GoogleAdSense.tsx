// src/components/ads/GoogleAdSense.tsx
/**
 * Google AdSense Integration
 * Displays ads throughout the blog
 */

import { useEffect } from 'react';

// Get AdSense Publisher ID from environment variable
const ADSENSE_CLIENT_ID = import.meta.env.VITE_ADSENSE_CLIENT_ID || '';

/**
 * Initialize Google AdSense
 * Call this once in App.tsx
 */
export const initAdSense = () => {
  if (!ADSENSE_CLIENT_ID) {
    console.warn('Google AdSense: VITE_ADSENSE_CLIENT_ID not set in .env file');
    return;
  }

  // Load AdSense script
  const script = document.createElement('script');
  script.async = true;
  script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${ADSENSE_CLIENT_ID}`;
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);

  console.log('Google AdSense initialized:', ADSENSE_CLIENT_ID);
};

interface AdSenseProps {
  /**
   * Ad slot ID from Google AdSense
   */
  slot: string;
  /**
   * Ad format: auto, rectangle, vertical, horizontal
   */
  format?: 'auto' | 'rectangle' | 'vertical' | 'horizontal';
  /**
   * Responsive or fixed size
   */
  responsive?: boolean;
  /**
   * Custom className for styling
   */
  className?: string;
  /**
   * Ad style (width/height for fixed ads)
   */
  style?: React.CSSProperties;
}

/**
 * Google AdSense Ad Component
 *
 * Usage:
 * <GoogleAdSense slot="1234567890" format="auto" responsive />
 */
export const GoogleAdSense: React.FC<AdSenseProps> = ({
  slot,
  format = 'auto',
  responsive = true,
  className = '',
  style = {},
}) => {
  useEffect(() => {
    if (!ADSENSE_CLIENT_ID) {
      return;
    }

    try {
      // Push ad to AdSense
      ((window as any).adsbygoogle = (window as any).adsbygoogle || []).push({});
    } catch (error) {
      console.error('AdSense error:', error);
    }
  }, []);

  // Don't render anything if AdSense is not configured
  // Google's script will handle the ad rendering automatically
  if (!ADSENSE_CLIENT_ID) {
    return null;
  }

  return (
    <div className={className}>
      <ins
        className="adsbygoogle"
        style={{ display: 'block', ...style }}
        data-ad-client={ADSENSE_CLIENT_ID}
        data-ad-slot={slot}
        data-ad-format={format}
        data-full-width-responsive={responsive ? 'true' : 'false'}
      />
    </div>
  );
};

/**
 * Banner Ad (728x90)
 * Perfect for header/footer placement
 */
export const BannerAd: React.FC<{ slot: string; className?: string }> = ({
  slot,
  className = '',
}) => {
  return (
    <GoogleAdSense
      slot={slot}
      format="horizontal"
      responsive
      className={className}
    />
  );
};

/**
 * Sidebar Ad (300x250)
 * Perfect for sidebar placement
 */
export const SidebarAd: React.FC<{ slot?: string; className?: string }> = ({
  slot = 'auto',
  className = '',
}) => {
  return (
    <GoogleAdSense
      slot={slot}
      format="rectangle"
      style={{ width: '300px', height: '250px' }}
      responsive={false}
      className={className}
    />
  );
};

/**
 * In-Article Ad
 * Perfect for placement between paragraphs
 */
export const InArticleAd: React.FC<{ slot?: string; className?: string }> = ({
  slot = 'auto',
  className = '',
}) => {
  return (
    <GoogleAdSense
      slot={slot}
      format="auto"
      responsive
      className={`my-8 ${className}`}
    />
  );
};

/**
 * Multiplex Ad (for related articles)
 */
export const MultiplexAd: React.FC<{ slot: string; className?: string }> = ({
  slot,
  className = '',
}) => {
  if (!ADSENSE_CLIENT_ID) {
    return null;
  }

  return (
    <div className={className}>
      <ins
        className="adsbygoogle"
        style={{ display: 'block' }}
        data-ad-format="autorelaxed"
        data-ad-client={ADSENSE_CLIENT_ID}
        data-ad-slot={slot}
      />
    </div>
  );
};

/**
 * Responsive Display Ad (auto-sized)
 * Works everywhere, adapts to container
 */
export const ResponsiveAd: React.FC<{ slot: string; className?: string }> = ({
  slot,
  className = '',
}) => {
  return (
    <GoogleAdSense
      slot={slot}
      format="auto"
      responsive
      className={className}
    />
  );
};

export default GoogleAdSense;
