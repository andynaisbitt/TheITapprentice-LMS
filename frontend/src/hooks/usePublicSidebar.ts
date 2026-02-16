// src/hooks/usePublicSidebar.ts
/**
 * Hook for managing public sidebar state
 * Handles open/close state, expanded sections, and localStorage persistence
 */

import { useState, useEffect, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { findActivePublicSection } from '../config/publicNavigation';

const STORAGE_KEY = 'public-sidebar-state';
const OPEN_KEY = 'public-sidebar-open';

interface SidebarState {
  expandedSections: string[];
}

interface UsePublicSidebarReturn {
  // Sidebar open/close state (drawer visibility)
  isOpen: boolean;
  openSidebar: () => void;
  closeSidebar: () => void;
  toggleSidebar: () => void;

  // Section expand/collapse
  expandedSections: string[];
  toggleSection: (sectionId: string) => void;
  isSectionExpanded: (sectionId: string) => boolean;
  expandSection: (sectionId: string) => void;
  collapseSection: (sectionId: string) => void;
}

export const usePublicSidebar = (): UsePublicSidebarReturn => {
  const location = useLocation();

  // Sidebar open state (drawer visibility) - default closed
  const [isOpen, setIsOpen] = useState(false);

  // Expanded sections state
  const [state, setState] = useState<SidebarState>(() => {
    if (typeof window === 'undefined') {
      return { expandedSections: ['overview'] };
    }

    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.error('Failed to parse public sidebar state:', e);
    }

    // Default: expand the section containing current path
    const activeSection = findActivePublicSection(location.pathname);
    return {
      expandedSections: activeSection ? [activeSection] : ['overview'],
    };
  });

  // Persist state to localStorage
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }, [state]);

  // Auto-expand section when navigating
  useEffect(() => {
    const activeSection = findActivePublicSection(location.pathname);
    if (activeSection && !state.expandedSections.includes(activeSection)) {
      setState((prev) => ({
        ...prev,
        expandedSections: [...prev.expandedSections, activeSection],
      }));
    }
  }, [location.pathname]);

  // Close sidebar on any navigation (pathname or search changes)
  useEffect(() => {
    setIsOpen(false);
  }, [location.pathname, location.search]);

  // Handle ESC key to close sidebar
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  // Prevent body scroll when sidebar is open (only on md+ where sidebar is visible)
  useEffect(() => {
    if (isOpen) {
      const isMdScreen = window.matchMedia('(min-width: 768px)').matches;
      if (isMdScreen) {
        document.body.style.overflow = 'hidden';
      }
    } else {
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // Close sidebar if window resizes below md breakpoint while open
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 768px)');
    const handler = (e: MediaQueryListEvent) => {
      if (!e.matches && isOpen) {
        setIsOpen(false);
        document.body.style.overflow = '';
      }
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [isOpen]);

  const openSidebar = useCallback(() => setIsOpen(true), []);
  const closeSidebar = useCallback(() => {
    setIsOpen(false);
    // Immediately unlock scroll to avoid race with exit animation
    document.body.style.overflow = '';
  }, []);
  const toggleSidebar = useCallback(() => setIsOpen((prev) => !prev), []);

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

  const expandSection = useCallback((sectionId: string) => {
    setState((prev) => {
      if (prev.expandedSections.includes(sectionId)) {
        return prev;
      }
      return {
        ...prev,
        expandedSections: [...prev.expandedSections, sectionId],
      };
    });
  }, []);

  const collapseSection = useCallback((sectionId: string) => {
    setState((prev) => ({
      ...prev,
      expandedSections: prev.expandedSections.filter((id) => id !== sectionId),
    }));
  }, []);

  return {
    isOpen,
    openSidebar,
    closeSidebar,
    toggleSidebar,
    expandedSections: state.expandedSections,
    toggleSection,
    isSectionExpanded,
    expandSection,
    collapseSection,
  };
};

export default usePublicSidebar;
