// src/components/layout/PublicSidebar/PublicSidebarItem.tsx
/**
 * Individual public sidebar navigation item
 * Handles active state, icons, badges, and navigation
 */

import { Link, useLocation } from 'react-router-dom';
import { type LucideIcon } from 'lucide-react';
import { isPublicPathActive } from '../../../config/publicNavigation';

interface PublicSidebarItemProps {
  label: string;
  path: string;
  icon: LucideIcon;
  subtitle?: string;
  isPopular?: boolean;
  isNew?: boolean;
  onClick?: () => void;
  depth?: number;
}

export const PublicSidebarItem: React.FC<PublicSidebarItemProps> = ({
  label,
  path,
  icon: Icon,
  subtitle,
  isPopular = false,
  isNew = false,
  onClick,
  depth = 0,
}) => {
  const location = useLocation();
  const isActive = isPublicPathActive(path, location.pathname);

  const baseClasses = `
    flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
    transition-all duration-200 cursor-pointer
    group relative w-full
  `;

  const activeClasses = isActive
    ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-l-3 border-blue-500'
    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800';

  const depthPadding = depth > 0 ? 'ml-4' : '';

  return (
    <Link
      to={path}
      onClick={onClick}
      className={`${baseClasses} ${activeClasses} ${depthPadding}`}
    >
      <Icon
        className={`w-5 h-5 flex-shrink-0 ${
          isActive
            ? 'text-blue-600 dark:text-blue-400'
            : 'text-gray-500 dark:text-gray-400'
        }`}
      />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="truncate">{label}</span>
          {isPopular && (
            <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-amber-100 dark:bg-amber-900/50 text-amber-700 dark:text-amber-300">
              Popular
            </span>
          )}
          {isNew && (
            <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300">
              New
            </span>
          )}
        </div>
        {subtitle && (
          <span className="text-xs text-gray-500 dark:text-gray-400 truncate block">
            {subtitle}
          </span>
        )}
      </div>
    </Link>
  );
};

export default PublicSidebarItem;
