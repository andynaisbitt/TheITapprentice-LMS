// src/components/home/MoreToExplore.tsx
/**
 * "More to Explore" - Compact showcase of LMS features/plugins
 * Displays as animated cards with icons for Courses, Tutorials, Quizzes, Leaderboards, etc.
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  GraduationCap,
  BookOpen,
  Brain,
  Trophy,
  Keyboard,
  BarChart3,
  Flame,
  Users,
  type LucideIcon,
} from 'lucide-react';
import Section from './Section';

interface ExploreItem {
  id: string;
  label: string;
  description: string;
  icon: LucideIcon;
  href: string;
  iconColor: string;
  iconBg: string;
}

const exploreItems: ExploreItem[] = [
  {
    id: 'courses',
    label: 'Courses',
    description: 'Structured learning paths',
    icon: GraduationCap,
    href: '/courses',
    iconColor: 'text-blue-600 dark:text-blue-400',
    iconBg: 'bg-blue-100 dark:bg-blue-500/20',
  },
  {
    id: 'tutorials',
    label: 'Tutorials',
    description: 'Step-by-step guides',
    icon: BookOpen,
    href: '/tutorials',
    iconColor: 'text-purple-600 dark:text-purple-400',
    iconBg: 'bg-purple-100 dark:bg-purple-500/20',
  },
  {
    id: 'quizzes',
    label: 'Quizzes',
    description: 'Test your knowledge',
    icon: Brain,
    href: '/quizzes',
    iconColor: 'text-emerald-600 dark:text-emerald-400',
    iconBg: 'bg-emerald-100 dark:bg-emerald-500/20',
  },
  {
    id: 'leaderboards',
    label: 'Leaderboards',
    description: 'Top performers',
    icon: Trophy,
    href: '/leaderboards',
    iconColor: 'text-amber-600 dark:text-amber-400',
    iconBg: 'bg-amber-100 dark:bg-amber-500/20',
  },
  {
    id: 'typing',
    label: 'Typing Practice',
    description: 'Improve your speed',
    icon: Keyboard,
    href: '/typing',
    iconColor: 'text-cyan-600 dark:text-cyan-400',
    iconBg: 'bg-cyan-100 dark:bg-cyan-500/20',
  },
  {
    id: 'progress',
    label: 'Your Progress',
    description: 'Track achievements',
    icon: BarChart3,
    href: '/dashboard',
    iconColor: 'text-rose-600 dark:text-rose-400',
    iconBg: 'bg-rose-100 dark:bg-rose-500/20',
  },
  {
    id: 'streaks',
    label: 'Daily Streaks',
    description: 'Build consistency',
    icon: Flame,
    href: '/dashboard',
    iconColor: 'text-orange-600 dark:text-orange-400',
    iconBg: 'bg-orange-100 dark:bg-orange-500/20',
  },
  {
    id: 'community',
    label: 'Community',
    description: 'Learn together',
    icon: Users,
    href: '/leaderboards',
    iconColor: 'text-violet-600 dark:text-violet-400',
    iconBg: 'bg-violet-100 dark:bg-violet-500/20',
  },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.1,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20, scale: 0.95 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.4,
      ease: 'easeOut' as const,
    },
  },
};

interface MoreToExploreProps {
  /** Items to exclude (by id) - useful to hide the current section's feature */
  exclude?: string[];
  /** Max items to show (default 6) */
  limit?: number;
}

export const MoreToExplore: React.FC<MoreToExploreProps> = ({
  exclude = [],
  limit = 6,
}) => {
  const visibleItems = exploreItems
    .filter((item) => !exclude.includes(item.id))
    .slice(0, limit);

  return (
    <Section
      eyebrow="Explore"
      title="More to Discover"
      subtitle="Explore all the ways you can learn and grow"
      background="muted"
      paddingY="md"
    >
      <motion.div
        variants={containerVariants}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4"
      >
        {visibleItems.map((item) => {
          const Icon = item.icon;

          return (
            <motion.div key={item.id} variants={itemVariants}>
              <Link
                to={item.href}
                className="group flex flex-col items-center text-center p-4 sm:p-5 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 hover:shadow-lg transition-all h-full"
              >
                <motion.div
                  whileHover={{ scale: 1.1, rotate: 5 }}
                  whileTap={{ scale: 0.95 }}
                  className={`w-12 h-12 sm:w-14 sm:h-14 rounded-xl ${item.iconBg} flex items-center justify-center mb-3 transition-colors`}
                >
                  <Icon className={`w-6 h-6 sm:w-7 sm:h-7 ${item.iconColor}`} />
                </motion.div>

                <h3 className="font-semibold text-sm sm:text-base text-slate-900 dark:text-white mb-0.5 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                  {item.label}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-1 hidden sm:block">
                  {item.description}
                </p>
              </Link>
            </motion.div>
          );
        })}
      </motion.div>
    </Section>
  );
};

export default MoreToExplore;
