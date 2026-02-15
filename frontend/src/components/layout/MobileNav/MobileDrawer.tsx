// src/components/layout/MobileNav/MobileDrawer.tsx
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Home,
  BookOpen,
  Target,
  User,
  X,
  Crown,
  Settings,
  Bell,
} from 'lucide-react';

import { OverviewSection } from './sections/OverviewSection';
import { LearnSection } from './sections/LearnSection';
import { PracticeSection } from './sections/PracticeSection';
import { AccountSection } from './sections/AccountSection';

import type { MenuItem } from '../../../services/api/navigation.api';

type TabType = 'overview' | 'learn' | 'practice' | 'account';

interface MobileDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  user?: {
    first_name?: string;
    last_name?: string;
    email?: string;
    role?: string;
    is_admin?: boolean;
    can_write_blog?: boolean;
    level?: number;
  } | null;
  isAuthenticated: boolean;
  onLogout: () => void;
  navItems?: MenuItem[];
}

const navTabs = [
  { id: 'overview' as TabType, icon: Home, label: 'Overview' },
  { id: 'learn' as TabType, icon: BookOpen, label: 'Learn' },
  { id: 'practice' as TabType, icon: Target, label: 'Practice' },
  { id: 'account' as TabType, icon: User, label: 'Account' },
];

export const MobileDrawer: React.FC<MobileDrawerProps> = ({
  isOpen,
  onClose,
  user,
  isAuthenticated,
  onLogout,
  navItems,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [activeTab, setActiveTab] = useState<TabType>(() => {
    const saved = localStorage.getItem('mobileNavActiveTab');
    return (saved as TabType) || 'overview';
  });
  const sidebarRef = useRef<HTMLDivElement>(null);
  const touchStartX = useRef<number | null>(null);
  const prevPathRef = useRef(location.pathname);

  // Close drawer on route change — compare against previous path to avoid firing on mount
  useEffect(() => {
    if (prevPathRef.current !== location.pathname) {
      prevPathRef.current = location.pathname;
      if (isOpen) {
        onClose();
      }
    }
  }, [location.pathname, isOpen, onClose]);

  // Body scroll lock
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // ESC key handler
  useEffect(() => {
    if (!isOpen) return;
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  // Swipe-to-close: left swipe on sidebar
  useEffect(() => {
    if (!isOpen) return;
    const sidebar = sidebarRef.current;
    if (!sidebar) return;

    const onTouchStart = (e: TouchEvent) => {
      touchStartX.current = e.touches[0].clientX;
    };
    const onTouchEnd = (e: TouchEvent) => {
      if (touchStartX.current === null) return;
      const delta = e.changedTouches[0].clientX - touchStartX.current;
      if (delta < -80) onClose();
      touchStartX.current = null;
    };

    sidebar.addEventListener('touchstart', onTouchStart, { passive: true });
    sidebar.addEventListener('touchend', onTouchEnd, { passive: true });
    return () => {
      sidebar.removeEventListener('touchstart', onTouchStart);
      sidebar.removeEventListener('touchend', onTouchEnd);
    };
  }, [isOpen, onClose]);

  // Persist active tab
  useEffect(() => {
    localStorage.setItem('mobileNavActiveTab', activeTab);
  }, [activeTab]);

  const handleClose = useCallback(() => {
    onClose();
  }, [onClose]);

  const handleNavigate = useCallback((path: string) => {
    onClose();
    navigate(path);
  }, [navigate, onClose]);

  const handleLogout = useCallback(async () => {
    onClose();
    await onLogout();
    navigate('/login');
  }, [onLogout, onClose, navigate]);

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewSection onNavigate={handleNavigate} />;
      case 'learn':
        return <LearnSection onNavigate={handleNavigate} />;
      case 'practice':
        return <PracticeSection onNavigate={handleNavigate} />;
      case 'account':
        return (
          <AccountSection
            user={user}
            isAuthenticated={isAuthenticated}
            onNavigate={handleNavigate}
            onLogout={handleLogout}
          />
        );
      default:
        return <OverviewSection onNavigate={handleNavigate} />;
    }
  };

  // ── Render ──
  // Uses pure CSS transitions instead of AnimatePresence.
  // The backdrop + sidebar are always in the DOM; pointer-events / visibility
  // controlled by isOpen. This avoids any Framer-motion stale-animation bugs.
  const drawerContent = (
    <>
      {/* Backdrop */}
      <div
        className={`fixed inset-0 bg-black/50 backdrop-blur-sm z-[9998] transition-opacity duration-300 ${
          isOpen
            ? 'opacity-100'
            : 'opacity-0 pointer-events-none'
        }`}
        onClick={handleClose}
        aria-hidden={!isOpen}
      />

      {/* Sidebar panel */}
      <div
        ref={sidebarRef}
        className={`fixed top-0 left-0 h-full w-80 bg-white dark:bg-slate-900 shadow-2xl z-[9999] flex flex-col transition-transform duration-300 ease-in-out ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-hidden={!isOpen}
      >
        {/* ─── Header (inline, not a sub-component) ─── */}
        {(!isAuthenticated || !user) ? (
          <div className="bg-gradient-to-r from-slate-700 to-slate-800 text-white p-4 relative flex-shrink-0">
            <button
              onClick={handleClose}
              className="absolute top-4 right-4 p-2 hover:bg-white/10 rounded-lg transition-colors z-10"
              aria-label="Close menu"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-3 mb-4">
              <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center">
                <User className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h2 className="font-semibold">Guest User</h2>
                <p className="text-white/70 text-sm">Not signed in</p>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => handleNavigate('/login')}
                className="flex-1 px-4 py-2 bg-white/10 hover:bg-white/20 rounded-lg font-medium text-sm transition-colors"
              >
                Sign In
              </button>
              <button
                onClick={() => handleNavigate('/register')}
                className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium text-sm transition-colors"
              >
                Sign Up
              </button>
            </div>
          </div>
        ) : (
          <div className="bg-gradient-to-r from-blue-600 to-indigo-700 text-white p-4 relative flex-shrink-0">
            <button
              onClick={handleClose}
              className="absolute top-4 right-4 p-2 hover:bg-white/10 rounded-lg transition-colors z-10"
              aria-label="Close menu"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-3 mb-3">
              <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center relative">
                <span className="text-lg font-bold">
                  {user.first_name?.[0]}{user.last_name?.[0]}
                </span>
                {user.is_admin && (
                  <div className="absolute -top-1 -right-1 w-5 h-5 bg-yellow-500 rounded-full flex items-center justify-center">
                    <Crown className="w-3 h-3 text-white" />
                  </div>
                )}
              </div>
              <div className="flex-1">
                <h2 className="font-semibold">{user.first_name || 'User'}</h2>
                <p className="text-white/70 text-sm">Level {user.level || 1}</p>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <button className="p-2 bg-white/10 rounded-lg hover:bg-white/20 transition-colors">
                <Bell className="w-4 h-4" />
              </button>
              <button
                onClick={() => handleNavigate('/settings')}
                className="p-2 bg-white/10 rounded-lg hover:bg-white/20 transition-colors"
              >
                <Settings className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* ─── Navigation Tabs ─── */}
        <div className="flex border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 flex-shrink-0">
          {navTabs.map((tab) => {
            const IconComponent = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex-1 flex flex-col items-center py-3 px-2 transition-colors relative ${
                  isActive
                    ? 'text-blue-600 dark:text-blue-400 bg-white dark:bg-slate-900'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
              >
                <IconComponent className="w-5 h-5 mb-1" />
                <span className="text-xs font-medium">{tab.label}</span>
                {isActive && (
                  <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 dark:bg-blue-400" />
                )}
              </button>
            );
          })}
        </div>

        {/* ─── Content Area ─── */}
        <div className="flex-1 overflow-y-auto p-4">
          {renderTabContent()}
        </div>
      </div>
    </>
  );

  return drawerContent;
};

export default MobileDrawer;
