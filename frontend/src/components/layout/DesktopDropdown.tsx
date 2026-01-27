// src/components/layout/DesktopDropdown.tsx
/**
 * Rich Desktop Dropdown Menu
 * Displays navigation items with icons, descriptions, and gradient backgrounds
 * Uses Framer Motion for smooth animations
 */

import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ChevronRight } from 'lucide-react';
import { MenuItem } from '../../services/api/navigation.api';
import { getIconForUrl, getSubtitleForUrl, getGradientForUrl } from '../../utils/navUtils';

interface DesktopDropdownProps {
  items: MenuItem[];
  onClose: () => void;
}

// Animation variants
const dropdownVariants = {
  hidden: {
    opacity: 0,
    y: -10,
    scale: 0.95,
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.15,
      ease: 'easeOut' as const,
      staggerChildren: 0.03,
    },
  },
  exit: {
    opacity: 0,
    y: -10,
    scale: 0.95,
    transition: {
      duration: 0.1,
      ease: 'easeIn' as const,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0 },
};

export const DesktopDropdown: React.FC<DesktopDropdownProps> = ({ items, onClose }) => {
  return (
    <motion.div
      variants={dropdownVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="absolute left-0 mt-2 w-72 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-200 dark:border-slate-700 py-2 z-50 overflow-hidden"
    >
      {items.map((item) => {
        const Icon = getIconForUrl(item.url);
        const subtitle = getSubtitleForUrl(item.url);
        const gradient = getGradientForUrl(item.url);

        // Handle external links
        if (item.target_blank) {
          return (
            <motion.a
              key={item.id}
              variants={itemVariants}
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={onClose}
              className="flex items-start gap-3 px-4 py-3 hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors group"
            >
              <DropdownItemContent
                Icon={Icon}
                gradient={gradient}
                label={item.label}
                subtitle={subtitle}
                isExternal
              />
            </motion.a>
          );
        }

        // Internal links
        return (
          <motion.div key={item.id} variants={itemVariants}>
            <Link
              to={item.url}
              onClick={onClose}
              className="flex items-start gap-3 px-4 py-3 hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors group"
            >
              <DropdownItemContent
                Icon={Icon}
                gradient={gradient}
                label={item.label}
                subtitle={subtitle}
              />
            </Link>
          </motion.div>
        );
      })}
    </motion.div>
  );
};

// Extracted component for dropdown item content
interface DropdownItemContentProps {
  Icon: React.ComponentType<{ className?: string }>;
  gradient: string;
  label: string;
  subtitle: string;
  isExternal?: boolean;
}

const DropdownItemContent: React.FC<DropdownItemContentProps> = ({
  Icon,
  gradient,
  label,
  subtitle,
  isExternal,
}) => (
  <>
    {/* Icon with gradient background */}
    <div
      className={`w-10 h-10 rounded-lg ${gradient} flex items-center justify-center flex-shrink-0 shadow-sm group-hover:shadow-md transition-shadow`}
    >
      <Icon className="w-5 h-5 text-white" />
    </div>

    {/* Text content */}
    <div className="flex-1 min-w-0">
      <div className="flex items-center gap-2">
        <span className="font-medium text-gray-900 dark:text-white">
          {label}
        </span>
        {isExternal ? (
          <svg
            className="w-3.5 h-3.5 text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
            />
          </svg>
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity" />
        )}
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
        {subtitle}
      </p>
    </div>
  </>
);

export default DesktopDropdown;
