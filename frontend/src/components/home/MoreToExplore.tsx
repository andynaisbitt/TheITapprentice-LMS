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
      staggerChildren: 0.07,
      delayChildren: 0.15,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 30, scale: 0.9, rotate: -2 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    rotate: 0,
    transition: {
      duration: 0.5,
      ease: [0.25, 0.1, 0.25, 1] as const,
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
      eyebrow="Keep Exploring"
      title="Your Learning Journey Continues"
      subtitle="Discover more ways to learn, practice, and grow your skills"
      background="gradient"
      paddingY="lg"
      centerHeader
    >
      <motion.div
        variants={containerVariants}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 sm:gap-4"
      >
        {visibleItems.map((item, index) => {
          const Icon = item.icon;
          // Extract color from className for dynamic effects
          const colorMatch = item.iconColor.match(/text-(\w+)-/);
          const colorName = colorMatch ? colorMatch[1] : 'blue';

          return (
            <motion.div
              key={item.id}
              variants={itemVariants}
              whileHover={{
                y: -10,
                scale: 1.05,
                rotate: index % 2 === 0 ? 2 : -2,
              }}
              whileTap={{ scale: 0.95 }}
              transition={{ duration: 0.25, ease: 'easeOut' }}
            >
              <Link
                to={item.href}
                className="group relative flex flex-col items-center text-center p-4 sm:p-5 bg-white dark:bg-slate-800 rounded-2xl border-2 border-slate-200 dark:border-slate-700 shadow-sm hover:shadow-2xl transition-all h-full overflow-hidden"
              >
                {/* Animated gradient background on hover */}
                <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${item.iconBg}`} />

                {/* Floating glow effect */}
                <motion.div
                  className={`absolute -top-10 -right-10 w-20 h-20 rounded-full blur-2xl opacity-0 group-hover:opacity-40 transition-opacity duration-300 ${item.iconBg}`}
                  animate={{ scale: [1, 1.2, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                />

                <div className="relative z-10">
                  {/* Icon with animated ring */}
                  <div className="relative mb-3">
                    <motion.div
                      className={`w-14 h-14 sm:w-16 sm:h-16 rounded-2xl ${item.iconBg} flex items-center justify-center transition-all duration-300 group-hover:scale-110 group-hover:rotate-6`}
                      whileHover={{ rotate: [0, -5, 5, 0] }}
                      transition={{ duration: 0.5 }}
                    >
                      <Icon className={`w-7 h-7 sm:w-8 sm:h-8 ${item.iconColor} transition-transform duration-300 group-hover:scale-110`} />
                    </motion.div>

                    {/* Pulse ring on hover */}
                    <div className={`absolute inset-0 rounded-2xl ${item.iconBg} opacity-0 group-hover:opacity-50 group-hover:animate-ping`} />
                  </div>

                  {/* Label with color change */}
                  <h3 className="font-bold text-sm sm:text-base text-slate-900 dark:text-white mb-1 transition-colors duration-300 group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-blue-600 group-hover:to-purple-600 dark:group-hover:from-blue-400 dark:group-hover:to-purple-400">
                    {item.label}
                  </h3>

                  {/* Description */}
                  <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-1 hidden sm:block transition-colors group-hover:text-slate-600 dark:group-hover:text-slate-300">
                    {item.description}
                  </p>
                </div>

                {/* Arrow indicator on hover */}
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  className="absolute bottom-2 opacity-0 group-hover:opacity-100 transition-all duration-300"
                >
                  <svg className={`w-4 h-4 ${item.iconColor}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </motion.div>
              </Link>
            </motion.div>
          );
        })}
      </motion.div>
    </Section>
  );
};

export default MoreToExplore;
