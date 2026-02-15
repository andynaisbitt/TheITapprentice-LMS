// src/components/layout/MobileNav/sections/PracticeSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { MenuCard } from '../components/MenuCard';
import { getGradientForUrl } from '../../../../utils/navUtils';
import { usePublicNavigation } from '../../../../hooks/usePublicNavigation';

interface PracticeSectionProps {
  onNavigate: (path: string) => void;
}

export const PracticeSection: React.FC<PracticeSectionProps> = ({ onNavigate }) => {
  const { practiceItems, loading } = usePublicNavigation();

  // Show loading state
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
  if (practiceItems.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-4"
      >
        <div className="text-center py-8">
          <p className="text-slate-500 dark:text-slate-400">
            No practice content available yet.
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
            Practice
          </h3>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Games, challenges & exercises
          </p>
        </div>
      </div>

      {/* Menu Items - Using filtered items from hook */}
      <div className="space-y-3">
        {practiceItems.map((item, index) => (
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
