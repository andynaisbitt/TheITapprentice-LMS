// src/components/home/Section.tsx
/**
 * Reusable Section Wrapper Component
 * Provides consistent spacing, animations, and header patterns for homepage sections
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { ArrowRight, type LucideIcon } from 'lucide-react';

interface SectionProps {
  children: React.ReactNode;
  className?: string;
  // Header props
  eyebrow?: string;
  title?: string;
  subtitle?: string;
  icon?: LucideIcon;
  viewAllLink?: string;
  viewAllText?: string;
  action?: React.ReactNode; // Custom action element (overrides viewAllLink)
  // Styling
  background?: 'default' | 'muted' | 'gradient' | 'accent';
  size?: 'md' | 'lg' | 'xl'; // max-w-5xl | max-w-6xl | max-w-7xl
  noPadding?: boolean;
  paddingY?: 'sm' | 'md' | 'lg'; // py-8 | py-12 | py-16
  centerHeader?: boolean;
  bordered?: boolean;
  // Animation
  animate?: boolean;
  delay?: number;
  staggerChildren?: boolean;
}

const sectionVariants = {
  hidden: { opacity: 0, y: 40 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.7,
      ease: [0.25, 0.1, 0.25, 1] as const, // Custom easing for smoother feel
    },
  },
};

const staggerContainerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.15,
    },
  },
};

const staggerItemVariants = {
  hidden: { opacity: 0, y: 25, scale: 0.98 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: 0.5,
      ease: [0.25, 0.1, 0.25, 1] as const,
    },
  },
};

export const Section: React.FC<SectionProps> = ({
  children,
  className = '',
  eyebrow,
  title,
  subtitle,
  icon: Icon,
  viewAllLink,
  viewAllText = 'View all',
  action,
  background = 'default',
  size = 'lg',
  noPadding = false,
  paddingY = 'md',
  centerHeader = false,
  bordered = false,
  animate = true,
  delay = 0,
  staggerChildren = false,
}) => {
  const bgClasses = {
    default: 'bg-transparent',
    muted: 'bg-slate-50 dark:bg-slate-800/30',
    gradient: 'bg-gradient-to-b from-slate-50 to-white dark:from-slate-900 dark:to-slate-800',
    accent: 'bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900',
  };

  const sizeClasses = {
    md: 'max-w-5xl',
    lg: 'max-w-6xl',
    xl: 'max-w-7xl',
  };

  const paddingClasses = {
    sm: 'py-8 sm:py-10',
    md: 'py-10 sm:py-14',
    lg: 'py-12 sm:py-16',
  };

  const hasHeader = eyebrow || title || subtitle;

  const content = (
    <div className={`${sizeClasses[size]} mx-auto px-4 sm:px-6 lg:px-8 ${noPadding ? '' : paddingClasses[paddingY]} ${className}`}>
      {/* Section Header */}
      {hasHeader && (
        <div className={`flex flex-col gap-4 mb-8 sm:mb-10 ${
          centerHeader
            ? 'items-center text-center'
            : 'sm:flex-row sm:items-end sm:justify-between'
        }`}>
          <div className={centerHeader ? 'max-w-2xl' : ''}>
            {/* Eyebrow */}
            {eyebrow && (
              <div className={`flex items-center gap-2 mb-2 ${centerHeader ? 'justify-center' : ''}`}>
                {Icon && (
                  <Icon className="w-5 h-5 text-blue-500 dark:text-blue-400" />
                )}
                <span className="text-sm font-medium text-blue-600 dark:text-blue-400 uppercase tracking-wider">
                  {eyebrow}
                </span>
              </div>
            )}

            {/* Title */}
            {title && (
              <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-slate-900 dark:text-white">
                {title}
              </h2>
            )}

            {/* Subtitle */}
            {subtitle && (
              <p className={`mt-2 text-base sm:text-lg text-slate-600 dark:text-slate-400 ${centerHeader ? '' : 'max-w-2xl'}`}>
                {subtitle}
              </p>
            )}
          </div>

          {/* Custom action or View All Link */}
          {action ? (
            <div className={`shrink-0 ${centerHeader ? 'mt-4' : ''}`}>
              {action}
            </div>
          ) : viewAllLink ? (
            <Link
              to={viewAllLink}
              className={`group inline-flex items-center gap-2 text-sm font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors shrink-0 ${
                centerHeader ? 'mt-4' : ''
              }`}
            >
              {viewAllText}
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
          ) : null}
        </div>
      )}

      {/* Section Content - optionally with stagger animation */}
      {staggerChildren ? (
        <motion.div
          variants={staggerContainerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, amount: 0.25 }}
        >
          {children}
        </motion.div>
      ) : (
        children
      )}
    </div>
  );

  const borderClass = bordered
    ? 'border-t border-slate-200 dark:border-slate-800'
    : '';

  if (animate) {
    return (
      <motion.section
        variants={sectionVariants}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.25 }}
        transition={{ delay }}
        className={`${bgClasses[background]} ${borderClass}`}
      >
        {content}
      </motion.section>
    );
  }

  return (
    <section className={`${bgClasses[background]} ${borderClass}`}>
      {content}
    </section>
  );
};

// Export stagger variants for use in child components
export { staggerItemVariants };
export default Section;
