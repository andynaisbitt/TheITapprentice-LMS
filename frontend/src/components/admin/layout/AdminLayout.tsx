// src/components/admin/layout/AdminLayout.tsx
/**
 * Admin Panel Layout Wrapper
 * Provides the sidebar and header structure for all admin pages
 */

import { useEffect } from 'react';
import { X } from 'lucide-react';
import { AdminSidebar } from './AdminSidebar';
import { AdminHeader } from './AdminHeader';
import { useAdminSidebar } from '../../../hooks/useAdminSidebar';

interface AdminLayoutProps {
  children: React.ReactNode;
}

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

      {/* Mobile Sidebar */}
      <div
        className={`
          fixed inset-y-0 left-0 z-50
          transform transition-transform duration-300 ease-in-out
          lg:hidden
          ${isMobileOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        <div className="relative h-full">
          <AdminSidebar
            isCollapsed={false}
            onToggleCollapse={() => {}}
            expandedSections={expandedSections}
            onToggleSection={toggleSection}
            isSectionExpanded={isSectionExpanded}
            expandedSubmenus={expandedSubmenus}
            onToggleSubmenu={toggleSubmenu}
          />
          {/* Close button */}
          <button
            onClick={closeMobile}
            className="
              absolute top-4 right-4
              p-2 rounded-lg
              bg-gray-100 dark:bg-gray-800
              hover:bg-gray-200 dark:hover:bg-gray-700
              transition-colors
            "
          >
            <X className="w-5 h-5 text-gray-500" />
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
