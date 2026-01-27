// src/components/layout/MobileNav/hooks/useMobileNav.ts
import { useState, useEffect, useCallback } from 'react';

export type MobileNavTab = 'overview' | 'learn' | 'practice' | 'account';

interface UseMobileNavReturn {
  isOpen: boolean;
  activeTab: MobileNavTab;
  open: () => void;
  close: () => void;
  toggle: () => void;
  setTab: (tab: MobileNavTab) => void;
}

export const useMobileNav = (): UseMobileNavReturn => {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<MobileNavTab>(() => {
    // Restore last active tab from localStorage
    const saved = localStorage.getItem('mobileNavActiveTab');
    return (saved as MobileNavTab) || 'overview';
  });

  // Body scroll lock
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  // ESC key handler
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen]);

  // Persist active tab
  useEffect(() => {
    localStorage.setItem('mobileNavActiveTab', activeTab);
  }, [activeTab]);

  const open = useCallback(() => setIsOpen(true), []);
  const close = useCallback(() => setIsOpen(false), []);
  const toggle = useCallback(() => setIsOpen(prev => !prev), []);
  const setTab = useCallback((tab: MobileNavTab) => setActiveTab(tab), []);

  return {
    isOpen,
    activeTab,
    open,
    close,
    toggle,
    setTab,
  };
};
