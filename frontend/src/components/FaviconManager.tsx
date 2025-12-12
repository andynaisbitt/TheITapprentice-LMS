/**
 * Favicon Manager Component
 * Loads favicons from site settings and updates based on theme changes
 */

import { useEffect, useState } from 'react';
import { setupFaviconThemeListener } from '../utils/favicon';

interface SiteSettings {
  favicon_url?: string;
  favicon_dark_url?: string;
}

export const FaviconManager: React.FC = () => {
  const [faviconConfig, setFaviconConfig] = useState<{
    light: string | null;
    dark: string | null;
  }>({
    light: null,
    dark: null,
  });

  // Fetch site settings on mount
  useEffect(() => {
    const loadFavicons = async () => {
      try {
        const response = await fetch('/api/v1/site-settings');
        if (response.ok) {
          const settings: SiteSettings = await response.json();

          setFaviconConfig({
            light: settings.favicon_url || '/apprentice.svg',
            dark: settings.favicon_dark_url || '/apprentice-dark.svg',
          });
        } else {
          // Use defaults if API fails
          setFaviconConfig({
            light: '/apprentice.svg',
            dark: '/apprentice-dark.svg',
          });
        }
      } catch (error) {
        console.error('Failed to load favicon settings:', error);
        // Use defaults on error
        setFaviconConfig({
          light: '/apprentice.svg',
          dark: '/apprentice-dark.svg',
        });
      }
    };

    loadFavicons();
  }, []);

  // Setup favicon theme listener when config is loaded
  useEffect(() => {
    if (!faviconConfig.light && !faviconConfig.dark) return;

    // Setup listener and get cleanup function
    const cleanup = setupFaviconThemeListener(faviconConfig);

    return cleanup;
  }, [faviconConfig]);

  // This component doesn't render anything
  return null;
};
