// src/components/layout/MobileNav/sections/OverviewSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { QuickAccessGrid } from '../components/QuickAccessGrid';
import { MenuCard } from '../components/MenuCard';
import { getGradientForUrl } from '../../../../utils/navUtils';
import { usePublicNavigation } from '../../../../hooks/usePublicNavigation';

interface OverviewSectionProps {
  onNavigate: (path: string) => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({ onNavigate }) => {
  const { overviewItems, loading } = usePublicNavigation();

  // Show loading state
  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6"
      >
        <div className="animate-pulse space-y-3">
          <div className="h-24 bg-slate-200 dark:bg-slate-700 rounded-xl" />
          <div className="h-20 bg-slate-200 dark:bg-slate-700 rounded-xl" />
          <div className="h-20 bg-slate-200 dark:bg-slate-700 rounded-xl" />
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Quick Access Grid */}
      <QuickAccessGrid onItemClick={onNavigate} />

      {/* Featured Cards - Using filtered items from hook */}
      {overviewItems.length > 0 && (
        <div className="space-y-3">
          <h3 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
            Featured
          </h3>

          {overviewItems.map((item, index) => (
            <MenuCard
              key={item.id}
              icon={item.icon}
              title={item.label}
              subtitle={item.subtitle || ''}
              description={item.description || ''}
              bgGradient={getGradientForUrl(item.path)}
              onClick={() => onNavigate(item.path)}
              index={index}
            />
          ))}
        </div>
      )}
    </motion.div>
  );
};
