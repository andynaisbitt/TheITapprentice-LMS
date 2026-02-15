// src/components/layout/MobileNav/sections/LearnSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { MenuCard } from '../components/MenuCard';
import { getGradientForUrl } from '../../../../utils/navUtils';
import { usePublicNavigation } from '../../../../hooks/usePublicNavigation';

interface LearnSectionProps {
  onNavigate: (path: string) => void;
}

export const LearnSection: React.FC<LearnSectionProps> = ({ onNavigate }) => {
  const { learnItems, loading } = usePublicNavigation();

  // Show loading state or empty state
  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-4"
      >
        <div className="animate-pulse space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-20 bg-slate-200 dark:bg-slate-700 rounded-xl" />
          ))}
        </div>
      </motion.div>
    );
  }

  // Show empty state if no items
  if (learnItems.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-4"
      >
        <div className="text-center py-8">
          <p className="text-slate-500 dark:text-slate-400">
            No learning content available yet.
          </p>
        </div>
      </motion.div>
    );
  }

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

      {/* Menu Items - Using filtered items from hook */}
      <div className="space-y-3">
        {learnItems.map((item, index) => (
          <MenuCard
            key={item.id}
            icon={item.icon}
            title={item.label}
            subtitle={item.subtitle || ''}
            description={item.description || ''}
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
