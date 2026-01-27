// src/components/layout/MobileNav/components/QuickAccessGrid.tsx
import React from 'react';
import { motion } from 'framer-motion';
import {
  GraduationCap,
  BookOpen,
  ClipboardCheck,
  Keyboard,
  Trophy,
  Gamepad2,
  FileText,
  Brain,
  HelpCircle,
  type LucideIcon,
} from 'lucide-react';

interface QuickAccessItem {
  id: string;
  label: string;
  icon: LucideIcon;
  color: string;
  path: string;
  count?: number;
  isNew?: boolean;
}

const defaultQuickAccessItems: QuickAccessItem[] = [
  {
    id: 'courses',
    label: 'Courses',
    icon: GraduationCap,
    color: 'text-blue-600 dark:text-blue-400',
    path: '/courses',
  },
  {
    id: 'tutorials',
    label: 'Tutorials',
    icon: BookOpen,
    color: 'text-green-600 dark:text-green-400',
    path: '/tutorials',
  },
  {
    id: 'quizzes',
    label: 'Quizzes',
    icon: ClipboardCheck,
    color: 'text-purple-600 dark:text-purple-400',
    path: '/quizzes',
  },
  {
    id: 'typing',
    label: 'Typing',
    icon: Keyboard,
    color: 'text-orange-600 dark:text-orange-400',
    path: '/typing',
  },
  {
    id: 'achievements',
    label: 'Awards',
    icon: Trophy,
    color: 'text-yellow-600 dark:text-yellow-400',
    path: '/achievements',
  },
  {
    id: 'games',
    label: 'Games',
    icon: Gamepad2,
    color: 'text-rose-600 dark:text-rose-400',
    path: '/games',
  },
  {
    id: 'blog',
    label: 'Blog',
    icon: FileText,
    color: 'text-emerald-600 dark:text-emerald-400',
    path: '/blog',
  },
  {
    id: 'challenges',
    label: 'Challenges',
    icon: Brain,
    color: 'text-pink-600 dark:text-pink-400',
    path: '/challenges',
  },
  {
    id: 'help',
    label: 'Help',
    icon: HelpCircle,
    color: 'text-slate-600 dark:text-slate-400',
    path: '/help',
  },
];

interface QuickAccessGridProps {
  onItemClick: (path: string) => void;
  items?: QuickAccessItem[];
}

export const QuickAccessGrid: React.FC<QuickAccessGridProps> = ({
  onItemClick,
  items = defaultQuickAccessItems,
}) => {
  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
          Quick Access
        </h3>
        <span className="text-xs text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full">
          {items.length} items
        </span>
      </div>

      {/* Grid - 3 columns */}
      <div className="grid grid-cols-3 gap-2">
        {items.map((item, index) => {
          const IconComponent = item.icon;

          return (
            <motion.button
              key={item.id}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.04, duration: 0.2 }}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => onItemClick(item.path)}
              className="relative flex flex-col items-center p-3 bg-slate-50 dark:bg-slate-800 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors border border-slate-200/50 dark:border-slate-700/50"
            >
              {/* New Badge */}
              {item.isNew && (
                <div className="absolute -top-1 -right-1 bg-green-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
                  NEW
                </div>
              )}

              {/* Count Badge */}
              {item.count !== undefined && item.count > 0 && (
                <div className="absolute -top-1 -right-1 bg-blue-500 text-white text-[10px] font-bold min-w-[18px] h-[18px] rounded-full flex items-center justify-center px-1">
                  {item.count > 99 ? '99+' : item.count}
                </div>
              )}

              {/* Icon */}
              <div className="w-8 h-8 bg-white dark:bg-slate-900 rounded-lg flex items-center justify-center mb-1.5 shadow-sm">
                <IconComponent className={`w-4 h-4 ${item.color}`} />
              </div>

              {/* Label */}
              <span className="text-xs font-medium text-slate-700 dark:text-slate-300 text-center leading-tight">
                {item.label}
              </span>
            </motion.button>
          );
        })}
      </div>
    </div>
  );
};
