// src/hooks/usePublicNavigation.ts
/**
 * Hook for accessing public navigation with plugin filtering
 * Provides categorized navigation items filtered by enabled plugins and auth status
 */

import { useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import { usePlugins } from '../state/contexts/PluginsContext';
import { useAuth } from '../state/contexts/AuthContext';
import {
  getFilteredPublicNavigation,
  getItemsByCategory,
  isPublicPathActive,
  type PublicNavItem,
  type PublicNavSection,
} from '../config/publicNavigation';

interface UsePublicNavigationReturn {
  /** All filtered sections */
  sections: PublicNavSection[];
  /** Items in the 'learn' category */
  learnItems: PublicNavItem[];
  /** Items in the 'practice' category */
  practiceItems: PublicNavItem[];
  /** Items in the 'overview' category */
  overviewItems: PublicNavItem[];
  /** Items in the 'account' category */
  accountItems: PublicNavItem[];
  /** All items flattened */
  allItems: PublicNavItem[];
  /** Check if a path is currently active */
  isActive: (path: string) => boolean;
  /** Loading state from plugins context */
  loading: boolean;
}

export const usePublicNavigation = (): UsePublicNavigationReturn => {
  const location = useLocation();
  const { isPluginEnabled, loading: pluginsLoading } = usePlugins();
  const { isAuthenticated, user } = useAuth();

  // Get filtered navigation sections
  const sections = useMemo(() => {
    return getFilteredPublicNavigation(
      isPluginEnabled,
      isAuthenticated,
      user?.is_admin
    );
  }, [isPluginEnabled, isAuthenticated, user?.is_admin]);

  // Get items by category
  const learnItems = useMemo(
    () => getItemsByCategory(sections, 'learn'),
    [sections]
  );

  const practiceItems = useMemo(
    () => getItemsByCategory(sections, 'practice'),
    [sections]
  );

  const overviewItems = useMemo(
    () => getItemsByCategory(sections, 'overview'),
    [sections]
  );

  const accountItems = useMemo(
    () => getItemsByCategory(sections, 'account'),
    [sections]
  );

  // All items flattened
  const allItems = useMemo(
    () => sections.flatMap((section) => section.items),
    [sections]
  );

  // Check if a path is active
  const isActive = useMemo(() => {
    return (path: string) => isPublicPathActive(path, location.pathname);
  }, [location.pathname]);

  return {
    sections,
    learnItems,
    practiceItems,
    overviewItems,
    accountItems,
    allItems,
    isActive,
    loading: pluginsLoading,
  };
};

export default usePublicNavigation;
