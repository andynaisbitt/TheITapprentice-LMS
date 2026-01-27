// src/components/layout/MobileNav/sections/PracticeSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { MenuCard } from '../components/MenuCard';
import { Keyboard, Gamepad2, Brain, Target } from 'lucide-react';
import { getGradientForUrl } from '../../../../utils/navUtils';

interface PracticeSectionProps {
  onNavigate: (path: string) => void;
}

const practiceItems = [
  {
    icon: Keyboard,
    title: 'Typing Practice',
    subtitle: 'Build Speed & Accuracy',
    description: 'Master typing with IT terminology. Build muscle memory with real-world commands!',
    path: '/typing',
    isPopular: true,
  },
  {
    icon: Gamepad2,
    title: 'Learning Games',
    subtitle: 'Learn Through Play',
    description: 'Fun interactive games to reinforce your knowledge.',
    path: '/games',
  },
  {
    icon: Brain,
    title: 'Daily Challenges',
    subtitle: 'Earn Streak Bonuses',
    description: 'Complete daily tasks to earn XP with up to 100% bonus from consecutive day streaks!',
    path: '/challenges',
    isNew: true,
  },
  {
    icon: Target,
    title: 'Practice Mode',
    subtitle: 'Skill-Building Exercises',
    description: 'Focused exercises to improve specific skills.',
    path: '/practice',
  },
];

export const PracticeSection: React.FC<PracticeSectionProps> = ({ onNavigate }) => {
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

      {/* Menu Items */}
      <div className="space-y-3">
        {practiceItems.map((item, index) => (
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
