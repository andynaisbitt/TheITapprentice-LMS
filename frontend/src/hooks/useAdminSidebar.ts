// src/hooks/useAdminSidebar.ts
/**
 * Hook for managing admin sidebar state
 * Handles expanded sections, collapsed sidebar, and localStorage persistence
 */

import { useState, useEffect, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { findActiveSection } from '../config/adminNavigation';

const STORAGE_KEY = 'admin-sidebar-state';
const COLLAPSED_KEY = 'admin-sidebar-collapsed';

interface SidebarState {
  expandedSections: string[];
  expandedSubmenus: string[];
}

interface UseAdminSidebarReturn {
  // Sidebar collapse state (for mobile/tablet)
  isCollapsed: boolean;
  toggleCollapsed: () => void;
  setCollapsed: (collapsed: boolean) => void;

  // Section expand/collapse
  expandedSections: string[];
  toggleSection: (sectionId: string) => void;
  isSectionExpanded: (sectionId: string) => boolean;

  // Submenu expand/collapse (for nested items)
  expandedSubmenus: string[];
  toggleSubmenu: (submenuLabel: string) => void;
  isSubmenuExpanded: (submenuLabel: string) => boolean;

  // Mobile drawer
  isMobileOpen: boolean;
  openMobile: () => void;
  closeMobile: () => void;
}

export const useAdminSidebar = (): UseAdminSidebarReturn => {
  const location = useLocation();

  // Sidebar collapsed state (icons only)
  const [isCollapsed, setIsCollapsed] = useState(() => {
    if (typeof window === 'undefined') return false;
    const saved = localStorage.getItem(COLLAPSED_KEY);
    return saved === 'true';
  });

  // Mobile drawer state
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  // Expanded sections and submenus
  const [state, setState] = useState<SidebarState>(() => {
    if (typeof window === 'undefined') {
      return { expandedSections: ['dashboard'], expandedSubmenus: [] };
    }

    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.error('Failed to parse sidebar state:', e);
    }

    // Default: expand the section containing current path
    const activeSection = findActiveSection(location.pathname);
    return {
      expandedSections: activeSection ? [activeSection] : ['dashboard'],
      expandedSubmenus: [],
    };
  });

  // Persist state to localStorage
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }, [state]);

  // Persist collapsed state
  useEffect(() => {
    localStorage.setItem(COLLAPSED_KEY, String(isCollapsed));
  }, [isCollapsed]);

  // Auto-expand section when navigating
  useEffect(() => {
    const activeSection = findActiveSection(location.pathname);
    if (activeSection && !state.expandedSections.includes(activeSection)) {
      setState((prev) => ({
        ...prev,
        expandedSections: [...prev.expandedSections, activeSection],
      }));
    }
  }, [location.pathname]);

  // Close mobile drawer on navigation
  useEffect(() => {
    setIsMobileOpen(false);
  }, [location.pathname]);

  const toggleCollapsed = useCallback(() => {
    setIsCollapsed((prev) => !prev);
  }, []);

  const setCollapsed = useCallback((collapsed: boolean) => {
    setIsCollapsed(collapsed);
  }, []);

  const toggleSection = useCallback((sectionId: string) => {
    setState((prev) => {
      const isExpanded = prev.expandedSections.includes(sectionId);
      return {
        ...prev,
        expandedSections: isExpanded
          ? prev.expandedSections.filter((id) => id !== sectionId)
          : [...prev.expandedSections, sectionId],
      };
    });
  }, []);

  const isSectionExpanded = useCallback(
    (sectionId: string) => state.expandedSections.includes(sectionId),
    [state.expandedSections]
  );

  const toggleSubmenu = useCallback((submenuLabel: string) => {
    setState((prev) => {
      const isExpanded = prev.expandedSubmenus.includes(submenuLabel);
      return {
        ...prev,
        expandedSubmenus: isExpanded
          ? prev.expandedSubmenus.filter((label) => label !== submenuLabel)
          : [...prev.expandedSubmenus, submenuLabel],
      };
    });
  }, []);

  const isSubmenuExpanded = useCallback(
    (submenuLabel: string) => state.expandedSubmenus.includes(submenuLabel),
    [state.expandedSubmenus]
  );

  const openMobile = useCallback(() => setIsMobileOpen(true), []);
  const closeMobile = useCallback(() => setIsMobileOpen(false), []);

  return {
    isCollapsed,
    toggleCollapsed,
    setCollapsed,
    expandedSections: state.expandedSections,
    toggleSection,
    isSectionExpanded,
    expandedSubmenus: state.expandedSubmenus,
    toggleSubmenu,
    isSubmenuExpanded,
    isMobileOpen,
    openMobile,
    closeMobile,
  };
};

export default useAdminSidebar;
