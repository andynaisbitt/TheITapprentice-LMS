// src/components/layout/PublicSidebar/PublicSidebar.tsx
/**
 * Public Navigation Sidebar
 * Drawer-style sidebar that slides in from the left
 * Available on all pages, hidden by default
 */

import { Link } from 'react-router-dom';
import { X, Home, Crown, ChevronRight } from 'lucide-react';
import { PublicSidebarSection } from './PublicSidebarSection';
import { usePublicNavigation } from '../../../hooks/usePublicNavigation';
import { useSiteSettings } from '../../../store/useSiteSettingsStore';
import { useAuth } from '../../../state/contexts/AuthContext';

interface PublicSidebarProps {
  isOpen: boolean;
  onClose: () => void;
  expandedSections: string[];
  onToggleSection: (sectionId: string) => void;
  isSectionExpanded: (sectionId: string) => boolean;
}

export const PublicSidebar: React.FC<PublicSidebarProps> = ({
  isOpen,
  onClose,
  expandedSections,
  onToggleSection,
  isSectionExpanded,
}) => {
  const { sections, loading } = usePublicNavigation();
  const { settings } = useSiteSettings();
  const { user, isAuthenticated } = useAuth();

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop — desktop only */}
      <div
        className="fixed inset-0 bg-black/50 z-[60] hidden md:block"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Sidebar Drawer */}
      <aside
        className="
          fixed left-0 top-0 h-screen w-72
          bg-white dark:bg-gray-900
          border-r border-gray-200 dark:border-gray-800
          flex-col z-[70] shadow-xl
          hidden md:flex
        "
      >
        {/* Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-800 flex-shrink-0">
          <Link
            to="/"
            className="flex items-center gap-2"
            onClick={onClose}
          >
            {settings.logoUrl ? (
              <img
                src={settings.logoUrl}
                alt={settings.siteTitle}
                className="h-8 w-auto"
              />
            ) : (
              <>
                <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-white font-bold text-sm">
                    {settings.siteTitle.charAt(0).toUpperCase()}
                  </span>
                </div>
                <span className="font-bold text-gray-900 dark:text-white">
                  {settings.siteTitle}
                </span>
              </>
            )}
          </Link>

          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* User Profile Section */}
        {isAuthenticated && user ? (
          <Link
            to="/profile"
            onClick={onClose}
            className="mx-3 mt-3 p-3 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:from-blue-700 hover:to-indigo-700 transition-all group flex-shrink-0"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center relative flex-shrink-0">
                <span className="font-bold text-sm">
                  {user.first_name?.[0]}{user.last_name?.[0]}
                </span>
                {user.is_admin && (
                  <div className="absolute -top-1 -right-1 w-4 h-4 bg-yellow-500 rounded-full flex items-center justify-center">
                    <Crown className="w-2.5 h-2.5 text-white" />
                  </div>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-sm truncate">
                  {user.first_name} {user.last_name}
                </p>
                <p className="text-white/70 text-xs">
                  Level {(user as any).level || 1}
                </p>
              </div>
              <ChevronRight className="w-4 h-4 text-white/50 group-hover:text-white/80 transition-colors" />
            </div>
          </Link>
        ) : (
          <div className="mx-3 mt-3 p-3 rounded-xl bg-gray-100 dark:bg-gray-800 flex-shrink-0">
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
              Sign in to track progress
            </p>
            <Link
              to="/login"
              onClick={onClose}
              className="block w-full text-center py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Sign In
            </Link>
          </div>
        )}

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 px-3">
          {/* Home Link */}
          <Link
            to="/"
            onClick={onClose}
            className="
              flex items-center gap-3 px-3 py-2.5 mb-4 rounded-lg
              text-sm font-medium text-gray-700 dark:text-gray-300
              hover:bg-gray-100 dark:hover:bg-gray-800
              transition-colors duration-200
            "
          >
            <Home className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <span>Home</span>
          </Link>

          {/* Loading State */}
          {loading ? (
            <div className="space-y-4 animate-pulse">
              {[1, 2, 3].map((i) => (
                <div key={i} className="space-y-2">
                  <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded-lg" />
                  <div className="ml-4 space-y-1">
                    <div className="h-8 bg-gray-100 dark:bg-gray-800 rounded" />
                    <div className="h-8 bg-gray-100 dark:bg-gray-800 rounded" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            sections.map((section) => (
              <PublicSidebarSection
                key={section.id}
                id={section.id}
                label={section.label}
                icon={section.icon}
                items={section.items}
                isExpanded={isSectionExpanded(section.id)}
                onToggle={() => onToggleSection(section.id)}
                onItemClick={onClose}
              />
            ))
          )}
        </nav>

        {/* Footer */}
        <div className="border-t border-gray-200 dark:border-gray-800 px-4 py-2 flex-shrink-0">
          <p className="text-[10px] text-gray-400 dark:text-gray-500 text-center">
            <kbd className="px-1 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-[10px]">ESC</kbd> to close
          </p>
        </div>
      </aside>
    </>
  );
};

export default PublicSidebar;
