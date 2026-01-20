// src/components/admin/layout/SidebarItem.tsx
/**
 * Individual sidebar navigation item
 * Handles active state, icons, and navigation
 */

import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, type LucideIcon } from 'lucide-react';
import { isPathActive } from '../../../config/adminNavigation';

interface SidebarItemProps {
  label: string;
  path?: string;
  icon?: LucideIcon;
  isCollapsed?: boolean;
  hasChildren?: boolean;
  isExpanded?: boolean;
  onClick?: () => void;
  depth?: number;
  badge?: string | number;
}

export const SidebarItem: React.FC<SidebarItemProps> = ({
  label,
  path,
  icon: Icon,
  isCollapsed = false,
  hasChildren = false,
  isExpanded = false,
  onClick,
  depth = 0,
  badge,
}) => {
  const location = useLocation();
  const isActive = path ? isPathActive(path, location.pathname) : false;

  const baseClasses = `
    flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium
    transition-all duration-200 cursor-pointer
    group relative
  `;

  const activeClasses = isActive
    ? 'bg-primary/10 text-primary dark:bg-primary/20 dark:text-primary-light'
    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800';

  const depthPadding = depth > 0 ? `pl-${4 + depth * 4}` : '';

  const content = (
    <>
      {Icon && (
        <Icon
          className={`w-5 h-5 flex-shrink-0 ${
            isActive ? 'text-primary dark:text-primary-light' : 'text-gray-500 dark:text-gray-400'
          }`}
        />
      )}
      {!isCollapsed && (
        <>
          <span className="flex-1 truncate">{label}</span>
          {badge !== undefined && (
            <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-primary/10 text-primary dark:bg-primary/20">
              {badge}
            </span>
          )}
          {hasChildren && (
            <ChevronRight
              className={`w-4 h-4 text-gray-400 transition-transform duration-200 ${
                isExpanded ? 'rotate-90' : ''
              }`}
            />
          )}
        </>
      )}

      {/* Tooltip for collapsed state */}
      {isCollapsed && (
        <div
          className="
            absolute left-full ml-2 px-2 py-1
            bg-gray-900 dark:bg-gray-700 text-white text-sm rounded
            opacity-0 invisible group-hover:opacity-100 group-hover:visible
            transition-all duration-200 whitespace-nowrap z-50
          "
        >
          {label}
        </div>
      )}
    </>
  );

  if (path && !hasChildren) {
    return (
      <Link to={path} className={`${baseClasses} ${activeClasses} ${depthPadding}`}>
        {content}
      </Link>
    );
  }

  return (
    <button
      onClick={onClick}
      className={`${baseClasses} ${activeClasses} ${depthPadding} w-full`}
    >
      {content}
    </button>
  );
};

export default SidebarItem;
