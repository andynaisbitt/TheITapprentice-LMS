// src/store/StoreInitializer.tsx
/**
 * Component that initializes all Zustand stores on app startup
 *
 * Place this component at the root of your app (in App.tsx):
 * <StoreInitializer />
 */

import { useEffect } from 'react';
import { useSiteSettingsStore } from './useSiteSettingsStore';

export const StoreInitializer: React.FC = () => {
  const loadSettings = useSiteSettingsStore((state) => state.loadSettings);

  useEffect(() => {
    // Load site settings on app startup
    loadSettings();
  }, [loadSettings]);

  return null; // This component doesn't render anything
};
