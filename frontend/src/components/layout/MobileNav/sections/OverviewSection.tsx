// src/components/layout/MobileNav/sections/OverviewSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { QuickAccessGrid } from '../components/QuickAccessGrid';
import { MenuCard } from '../components/MenuCard';
import { Home, BarChart3 } from 'lucide-react';

interface OverviewSectionProps {
  onNavigate: (path: string) => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({ onNavigate }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Quick Access Grid */}
      <QuickAccessGrid onItemClick={onNavigate} />

      {/* Featured Cards */}
      <div className="space-y-3">
        <h3 className="font-semibold text-slate-900 dark:text-slate-100 text-sm">
          Featured
        </h3>

        <MenuCard
          icon={Home}
          title="Dashboard"
          subtitle="Your Learning Hub"
          description="Track your progress, see recent activity, and continue where you left off."
          bgGradient="bg-gradient-to-br from-blue-600 via-indigo-600 to-violet-600"
          onClick={() => onNavigate('/dashboard')}
          index={0}
        />

        <MenuCard
          icon={BarChart3}
          title="Leaderboard"
          subtitle="Top Performers"
          description="See how you rank against other learners."
          bgGradient="bg-gradient-to-br from-purple-500 via-violet-600 to-indigo-600"
          onClick={() => onNavigate('/leaderboard')}
          index={1}
        />
      </div>
    </motion.div>
  );
};
