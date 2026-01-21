// src/components/admin/layout/SidebarSection.tsx
/**
 * Collapsible sidebar section with nested items
 * Shows flyout menu when sidebar is collapsed
 */

import { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, type LucideIcon } from 'lucide-react';
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
  const [showFlyout, setShowFlyout] = useState(false);
  const flyoutRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close flyout when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        flyoutRef.current &&
        buttonRef.current &&
        !flyoutRef.current.contains(event.target as Node) &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setShowFlyout(false);
      }
    };

    if (showFlyout) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showFlyout]);

  const handleClick = () => {
    if (isCollapsed) {
      setShowFlyout(!showFlyout);
    } else {
      onToggle();
    }
  };

  // Render flyout menu item
  const renderFlyoutItem = (item: NavItem) => {
    const ItemIcon = item.icon;

    if (item.children) {
      return (
        <div key={item.label} className="py-1">
          <div className="px-3 py-1.5 text-xs font-semibold text-gray-400 uppercase tracking-wider">
            {item.label}
          </div>
          {item.children.map((child) => (
            <Link
              key={child.label}
              to={child.path || '#'}
              onClick={() => setShowFlyout(false)}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
              {child.icon && <child.icon className="w-4 h-4 text-gray-500" />}
              {child.label}
            </Link>
          ))}
        </div>
      );
    }

    return (
      <Link
        key={item.label}
        to={item.path || '#'}
        onClick={() => setShowFlyout(false)}
        className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
      >
        {ItemIcon && <ItemIcon className="w-4 h-4 text-gray-500" />}
        {item.label}
        {item.badge !== undefined && (
          <span className="ml-auto px-2 py-0.5 text-xs font-semibold rounded-full bg-primary/10 text-primary">
            {item.badge}
          </span>
        )}
      </Link>
    );
  };

  return (
    <div className="mb-1 relative">
      {/* Section Header */}
      <button
        ref={buttonRef}
        onClick={handleClick}
        className={`
          w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
          text-sm font-semibold uppercase tracking-wider
          text-gray-500 dark:text-gray-400
          hover:bg-gray-100 dark:hover:bg-gray-800
          transition-colors duration-200
          group
          ${isCollapsed && showFlyout ? 'bg-gray-100 dark:bg-gray-800' : ''}
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

        {/* Tooltip for collapsed state (only show if flyout not open) */}
        {isCollapsed && !showFlyout && (
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

      {/* Flyout Menu for Collapsed State */}
      {isCollapsed && showFlyout && (
        <div
          ref={flyoutRef}
          className="
            absolute left-full top-0 ml-2 min-w-48
            bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700
            z-50 py-2
          "
        >
          {/* Flyout Header */}
          <div className="px-3 py-2 border-b border-gray-200 dark:border-gray-700 mb-1">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-900 dark:text-white">
              <Icon className="w-4 h-4" />
              {label}
            </div>
          </div>

          {/* Flyout Items */}
          <div className="max-h-80 overflow-y-auto">
            {items.map(renderFlyoutItem)}
          </div>
        </div>
      )}

      {/* Section Items (Expanded State) */}
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
