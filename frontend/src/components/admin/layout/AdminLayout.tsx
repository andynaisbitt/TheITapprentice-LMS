// src/components/admin/layout/AdminLayout.tsx
/**
 * Admin Panel Layout Wrapper
 * Provides the sidebar and header structure for all admin pages
 * Supports swipe-to-close gesture on mobile
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { X } from 'lucide-react';
import { AdminSidebar } from './AdminSidebar';
import { AdminHeader } from './AdminHeader';
import { useAdminSidebar } from '../../../hooks/useAdminSidebar';

interface AdminLayoutProps {
  children: React.ReactNode;
}

// Swipe threshold in pixels - how far to swipe before closing
const SWIPE_THRESHOLD = 50;

export const AdminLayout: React.FC<AdminLayoutProps> = ({ children }) => {
  const {
    isCollapsed,
    toggleCollapsed,
    expandedSections,
    toggleSection,
    isSectionExpanded,
    expandedSubmenus,
    toggleSubmenu,
    isMobileOpen,
    openMobile,
    closeMobile,
  } = useAdminSidebar();

  // Swipe gesture state
  const touchStartX = useRef<number>(0);
  const touchCurrentX = useRef<number>(0);
  const [swipeOffset, setSwipeOffset] = useState(0);
  const isDragging = useRef(false);

  // Handle touch start
  const handleTouchStart = useCallback((e: React.TouchEvent) => {
    touchStartX.current = e.touches[0].clientX;
    touchCurrentX.current = e.touches[0].clientX;
    isDragging.current = true;
  }, []);

  // Handle touch move
  const handleTouchMove = useCallback((e: React.TouchEvent) => {
    if (!isDragging.current) return;

    touchCurrentX.current = e.touches[0].clientX;
    const diff = touchCurrentX.current - touchStartX.current;

    // Only allow swiping left (negative diff) to close
    if (diff < 0) {
      setSwipeOffset(diff);
    }
  }, []);

  // Handle touch end
  const handleTouchEnd = useCallback(() => {
    if (!isDragging.current) return;

    isDragging.current = false;
    const diff = touchCurrentX.current - touchStartX.current;

    // If swiped left past threshold, close the sidebar
    if (diff < -SWIPE_THRESHOLD) {
      closeMobile();
    }

    // Reset swipe offset
    setSwipeOffset(0);
  }, [closeMobile]);

  // Initialize dark mode from localStorage on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else if (savedTheme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      // Default to system preference
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (prefersDark) {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      }
    }
  }, []);

  // Close mobile sidebar on escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isMobileOpen) {
        closeMobile();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isMobileOpen, closeMobile]);

  // Prevent body scroll when mobile sidebar is open
  useEffect(() => {
    if (isMobileOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isMobileOpen]);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900">
      {/* Desktop Sidebar */}
      <div className="hidden lg:block">
        <AdminSidebar
          isCollapsed={isCollapsed}
          onToggleCollapse={toggleCollapsed}
          expandedSections={expandedSections}
          onToggleSection={toggleSection}
          isSectionExpanded={isSectionExpanded}
          expandedSubmenus={expandedSubmenus}
          onToggleSubmenu={toggleSubmenu}
        />
      </div>

      {/* Mobile Sidebar Overlay */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={closeMobile}
        />
      )}

      {/* Mobile Sidebar - with swipe-to-close support */}
      <div
        className={`
          fixed inset-y-0 left-0 z-50
          transform lg:hidden
          ${isMobileOpen ? 'translate-x-0' : '-translate-x-full'}
          ${swipeOffset === 0 ? 'transition-transform duration-300 ease-in-out' : ''}
        `}
        style={{
          transform: isMobileOpen
            ? `translateX(${Math.min(0, swipeOffset)}px)`
            : 'translateX(-100%)',
        }}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        <div className="flex h-full">
          {/* Sidebar Content */}
          <div className="w-60 h-full overflow-hidden">
            <AdminSidebar
              isCollapsed={false}
              onToggleCollapse={closeMobile}
              expandedSections={expandedSections}
              onToggleSection={toggleSection}
              isSectionExpanded={isSectionExpanded}
              expandedSubmenus={expandedSubmenus}
              onToggleSubmenu={toggleSubmenu}
            />
          </div>
          {/* Close button - positioned OUTSIDE sidebar for visibility */}
          <button
            onClick={closeMobile}
            className="
              flex-shrink-0 mt-4 ml-2
              w-10 h-10 rounded-full
              bg-white dark:bg-gray-800
              shadow-lg border border-gray-200 dark:border-gray-700
              hover:bg-gray-100 dark:hover:bg-gray-700
              transition-colors
              flex items-center justify-center
            "
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          </button>
        </div>
      </div>

      {/* Header */}
      <AdminHeader
        onMenuClick={openMobile}
        sidebarCollapsed={isCollapsed}
      />

      {/* Main Content */}
      <main
        className={`
          pt-16 min-h-screen
          transition-all duration-300
          ${isCollapsed ? 'lg:pl-16' : 'lg:pl-60'}
        `}
      >
        <div className="p-6">
          {children}
        </div>
      </main>
    </div>
  );
};

export default AdminLayout;
