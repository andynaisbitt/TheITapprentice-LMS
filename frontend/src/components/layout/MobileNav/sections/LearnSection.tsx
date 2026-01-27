// src/components/layout/MobileNav/sections/LearnSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { MenuCard } from '../components/MenuCard';
import { GraduationCap, BookOpen, ClipboardCheck, Award } from 'lucide-react';
import type { MenuItem } from '../../../../services/api/navigation.api';
import { getGradientForUrl, getSubtitleForUrl } from '../../../../utils/navUtils';

interface LearnSectionProps {
  onNavigate: (path: string) => void;
  navItems?: MenuItem[];
}

// Default learn items if no API items available
const defaultLearnItems = [
  {
    icon: GraduationCap,
    title: 'Courses',
    subtitle: 'Structured Learning Paths',
    description: 'Comprehensive courses with interactive content and real-world projects.',
    path: '/courses',
    isPopular: true,
  },
  {
    icon: BookOpen,
    title: 'Tutorials',
    subtitle: 'Quick Learning Guides',
    description: 'Step-by-step tutorials covering specific topics and technologies.',
    path: '/tutorials',
  },
  {
    icon: ClipboardCheck,
    title: 'Quizzes',
    subtitle: 'Test Your Knowledge',
    description: 'Practice quizzes to reinforce learning and track your understanding.',
    path: '/quizzes',
  },
  {
    icon: Award,
    title: 'Skills',
    subtitle: 'Track Your Progress',
    description: 'Monitor your skill development across different areas.',
    path: '/skills',
    isNew: true,
  },
];

export const LearnSection: React.FC<LearnSectionProps> = ({ onNavigate, navItems }) => {
  // Use API items if available, otherwise use defaults
  const items = navItems && navItems.length > 0
    ? navItems.map(item => ({
        icon: GraduationCap, // Will be overridden by getIconForUrl in MenuCard
        title: item.label,
        subtitle: getSubtitleForUrl(item.url),
        description: '',
        path: item.url,
      }))
    : defaultLearnItems;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-4"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
            Learn
          </h3>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Courses, tutorials & quizzes
          </p>
        </div>
      </div>

      {/* Menu Items */}
      <div className="space-y-3">
        {defaultLearnItems.map((item, index) => (
          <MenuCard
            key={item.path}
            icon={item.icon}
            title={item.title}
            subtitle={item.subtitle}
            description={item.description}
            bgGradient={getGradientForUrl(item.path)}
            onClick={() => onNavigate(item.path)}
            index={index}
            isPopular={item.isPopular}
            isNew={item.isNew}
          />
        ))}
      </div>
    </motion.div>
  );
};
