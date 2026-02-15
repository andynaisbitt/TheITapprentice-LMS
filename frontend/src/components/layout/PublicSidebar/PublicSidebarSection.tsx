// src/components/layout/PublicSidebar/PublicSidebarSection.tsx
/**
 * Collapsible public sidebar section
 * Shows a group of navigation items with expand/collapse functionality
 */

import { ChevronDown, type LucideIcon } from 'lucide-react';
import { PublicSidebarItem } from './PublicSidebarItem';
import type { PublicNavItem } from '../../../config/publicNavigation';

interface PublicSidebarSectionProps {
  id: string;
  label: string;
  icon: LucideIcon;
  items: PublicNavItem[];
  isExpanded: boolean;
  onToggle: () => void;
  onItemClick?: () => void;
}

export const PublicSidebarSection: React.FC<PublicSidebarSectionProps> = ({
  id,
  label,
  icon: Icon,
  items,
  isExpanded,
  onToggle,
  onItemClick,
}) => {
  return (
    <div className="mb-2">
      {/* Section Header */}
      <button
        onClick={onToggle}
        className={`
          w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
          text-sm font-semibold uppercase tracking-wider
          text-gray-600 dark:text-gray-400
          hover:bg-gray-100 dark:hover:bg-gray-800
          transition-colors duration-200
        `}
      >
        <Icon className="w-5 h-5 flex-shrink-0 text-gray-500 dark:text-gray-400" />
        <span className="flex-1 text-left">{label}</span>
        <ChevronDown
          className={`w-4 h-4 transition-transform duration-200 ${
            isExpanded ? '' : '-rotate-90'
          }`}
        />
      </button>

      {/* Section Items */}
      {isExpanded && (
        <div className="mt-1 ml-2 space-y-0.5">
          {items.map((item) => (
            <PublicSidebarItem
              key={item.id}
              label={item.label}
              path={item.path}
              icon={item.icon}
              subtitle={item.subtitle}
              isPopular={item.isPopular}
              isNew={item.isNew}
              onClick={onItemClick}
              depth={1}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default PublicSidebarSection;
