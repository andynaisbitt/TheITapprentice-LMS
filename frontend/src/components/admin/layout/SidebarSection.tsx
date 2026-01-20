// src/components/admin/layout/SidebarSection.tsx
/**
 * Collapsible sidebar section with nested items
 */

import { ChevronDown, type LucideIcon } from 'lucide-react';
import { SidebarItem } from './SidebarItem';
import type { NavItem } from '../../../config/adminNavigation';

interface SidebarSectionProps {
  id: string;
  label: string;
  icon: LucideIcon;
  items: NavItem[];
  isExpanded: boolean;
  isCollapsed: boolean;
  onToggle: () => void;
  expandedSubmenus: string[];
  onToggleSubmenu: (label: string) => void;
  badge?: string | number;
}

export const SidebarSection: React.FC<SidebarSectionProps> = ({
  id,
  label,
  icon: Icon,
  items,
  isExpanded,
  isCollapsed,
  onToggle,
  expandedSubmenus,
  onToggleSubmenu,
  badge,
}) => {
  return (
    <div className="mb-1">
      {/* Section Header */}
      <button
        onClick={onToggle}
        className={`
          w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
          text-sm font-semibold uppercase tracking-wider
          text-gray-500 dark:text-gray-400
          hover:bg-gray-100 dark:hover:bg-gray-800
          transition-colors duration-200
          group relative
        `}
      >
        <Icon className="w-5 h-5 flex-shrink-0" />
        {!isCollapsed && (
          <>
            <span className="flex-1 text-left">{label}</span>
            {badge !== undefined && (
              <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-primary/10 text-primary">
                {badge}
              </span>
            )}
            <ChevronDown
              className={`w-4 h-4 transition-transform duration-200 ${
                isExpanded ? '' : '-rotate-90'
              }`}
            />
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
              normal-case tracking-normal font-medium
            "
          >
            {label}
          </div>
        )}
      </button>

      {/* Section Items */}
      {isExpanded && !isCollapsed && (
        <div className="mt-1 ml-2 space-y-0.5">
          {items.map((item) => (
            <div key={item.label}>
              {item.children ? (
                // Nested submenu
                <div>
                  <SidebarItem
                    label={item.label}
                    icon={item.icon}
                    hasChildren
                    isExpanded={expandedSubmenus.includes(item.label)}
                    onClick={() => onToggleSubmenu(item.label)}
                    depth={1}
                  />
                  {expandedSubmenus.includes(item.label) && (
                    <div className="ml-4 mt-0.5 space-y-0.5 border-l-2 border-gray-200 dark:border-gray-700 pl-2">
                      {item.children.map((child) => (
                        <SidebarItem
                          key={child.label}
                          label={child.label}
                          path={child.path}
                          icon={child.icon}
                          depth={2}
                        />
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                // Regular item
                <SidebarItem
                  label={item.label}
                  path={item.path}
                  icon={item.icon}
                  badge={item.badge}
                  depth={1}
                />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SidebarSection;
