// src/components/admin/layout/AdminSidebar.tsx
/**
 * Admin Panel Sidebar Navigation
 * WordPress-style collapsible sidebar with sections
 * Dynamically shows/hides items based on enabled plugins
 */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  PanelLeftClose,
  PanelLeft,
  ExternalLink,
  LogOut,
} from 'lucide-react';
import { SidebarSection } from './SidebarSection';
import { getFilteredNavigation } from '../../../config/adminNavigation';
import { useAuth } from '../../../state/contexts/AuthContext';
import { usePlugins } from '../../../state/contexts/PluginsContext';

interface AdminSidebarProps {
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  expandedSections: string[];
  onToggleSection: (sectionId: string) => void;
  isSectionExpanded: (sectionId: string) => boolean;
  expandedSubmenus: string[];
  onToggleSubmenu: (label: string) => void;
}

export const AdminSidebar: React.FC<AdminSidebarProps> = ({
  isCollapsed,
  onToggleCollapse,
  expandedSections,
  onToggleSection,
  isSectionExpanded,
  expandedSubmenus,
  onToggleSubmenu,
}) => {
  const { user, logout } = useAuth();
  const { isPluginEnabled, loading: pluginsLoading } = usePlugins();

  // Get filtered navigation based on enabled plugins
  const navigation = useMemo(() => {
    return getFilteredNavigation(isPluginEnabled);
  }, [isPluginEnabled]);

  return (
    <aside
      className={`
        fixed left-0 top-0 h-screen
        bg-white dark:bg-gray-900
        border-r border-gray-200 dark:border-gray-800
        transition-all duration-300 ease-in-out
        flex flex-col
        z-40
        ${isCollapsed ? 'w-16' : 'w-60'}
      `}
    >
      {/* Logo / Brand */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-800">
        {!isCollapsed && (
          <Link to="/admin" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center">
              <span className="text-white font-bold text-sm">A</span>
            </div>
            <span className="font-bold text-gray-900 dark:text-white">Admin</span>
          </Link>
        )}
        <button
          onClick={onToggleCollapse}
          className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? (
            <PanelLeft className="w-5 h-5 text-gray-500" />
          ) : (
            <PanelLeftClose className="w-5 h-5 text-gray-500" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2">
        {navigation.map((section) => (
          <SidebarSection
            key={section.id}
            id={section.id}
            label={section.label}
            icon={section.icon}
            items={section.items}
            isExpanded={isSectionExpanded(section.id)}
            isCollapsed={isCollapsed}
            onToggle={() => onToggleSection(section.id)}
            expandedSubmenus={expandedSubmenus}
            onToggleSubmenu={onToggleSubmenu}
            badge={section.badge}
          />
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-gray-200 dark:border-gray-800 p-2">
        {/* View Site Link */}
        <a
          href="/"
          target="_blank"
          rel="noopener noreferrer"
          className={`
            flex items-center gap-3 px-3 py-2 rounded-lg
            text-sm font-medium text-gray-600 dark:text-gray-400
            hover:bg-gray-100 dark:hover:bg-gray-800
            transition-colors duration-200
            group relative
          `}
        >
          <ExternalLink className="w-5 h-5 flex-shrink-0" />
          {!isCollapsed && <span>View Site</span>}
          {isCollapsed && (
            <div
              className="
                absolute left-full ml-2 px-2 py-1
                bg-gray-900 dark:bg-gray-700 text-white text-sm rounded
                opacity-0 invisible group-hover:opacity-100 group-hover:visible
                transition-all duration-200 whitespace-nowrap z-50
              "
            >
              View Site
            </div>
          )}
        </a>

        {/* User Info & Logout */}
        {!isCollapsed && user && (
          <div className="mt-2 px-3 py-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white font-semibold text-sm">
                {user.first_name?.[0] || user.username?.[0] || 'A'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                  {user.first_name || user.username}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                  {user.email}
                </p>
              </div>
            </div>
          </div>
        )}

        <button
          onClick={() => logout()}
          className={`
            w-full flex items-center gap-3 px-3 py-2 mt-2 rounded-lg
            text-sm font-medium text-red-600 dark:text-red-400
            hover:bg-red-50 dark:hover:bg-red-900/20
            transition-colors duration-200
            group relative
          `}
        >
          <LogOut className="w-5 h-5 flex-shrink-0" />
          {!isCollapsed && <span>Logout</span>}
          {isCollapsed && (
            <div
              className="
                absolute left-full ml-2 px-2 py-1
                bg-gray-900 dark:bg-gray-700 text-white text-sm rounded
                opacity-0 invisible group-hover:opacity-100 group-hover:visible
                transition-all duration-200 whitespace-nowrap z-50
              "
            >
              Logout
            </div>
          )}
        </button>
      </div>
    </aside>
  );
};

export default AdminSidebar;
