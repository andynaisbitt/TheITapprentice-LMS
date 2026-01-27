// src/components/layout/MobileNav/components/MenuCard.tsx
import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronRight, type LucideIcon } from 'lucide-react';

interface MenuCardProps {
  icon: LucideIcon;
  title: string;
  subtitle?: string;
  description?: string;
  bgGradient: string;
  onClick: () => void;
  index: number;
  stats?: {
    label: string;
    value: string;
    icon?: LucideIcon;
  };
  isPopular?: boolean;
  isNew?: boolean;
}

export const MenuCard: React.FC<MenuCardProps> = ({
  icon: Icon,
  title,
  subtitle,
  description,
  bgGradient,
  onClick,
  index,
  stats,
  isPopular,
  isNew,
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const StatsIcon = stats?.icon || Icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 30, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{
        delay: index * 0.1,
        duration: 0.4,
        type: 'spring',
        stiffness: 100,
      }}
      whileHover={{ y: -2, scale: 1.01 }}
      className="relative group"
    >
      <motion.button
        onClick={onClick}
        onHoverStart={() => setIsHovered(true)}
        onHoverEnd={() => setIsHovered(false)}
        whileTap={{ scale: 0.98 }}
        className={`w-full p-5 ${bgGradient} rounded-2xl border border-white/20 hover:border-white/40 transition-all shadow-lg hover:shadow-xl group relative overflow-hidden text-left`}
      >
        {/* Background Animation */}
        <motion.div
          className="absolute inset-0 bg-white/10 rounded-2xl"
          animate={isHovered ? { scale: 1.05, opacity: 1 } : { scale: 1, opacity: 0 }}
          transition={{ duration: 0.3 }}
        />

        {/* Floating Particles */}
        <AnimatePresence>
          {isHovered && (
            <>
              {[...Array(4)].map((_, i) => (
                <motion.div
                  key={i}
                  className="absolute w-1.5 h-1.5 bg-white/30 rounded-full"
                  initial={{
                    opacity: 0,
                    x: Math.random() * 200,
                    y: Math.random() * 100,
                  }}
                  animate={{
                    opacity: [0, 1, 0],
                    y: [0, -20],
                    x: [0, (Math.random() - 0.5) * 30],
                    scale: [0, 1, 0],
                  }}
                  exit={{ opacity: 0 }}
                  transition={{
                    duration: 1.5,
                    delay: i * 0.15,
                    repeat: Infinity,
                    repeatDelay: 2,
                  }}
                />
              ))}
            </>
          )}
        </AnimatePresence>

        {/* Popular/New Badges */}
        {(isPopular || isNew) && (
          <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
            {isPopular && (
              <motion.div
                className="bg-yellow-400 text-yellow-900 text-xs font-bold px-2 py-0.5 rounded-full shadow-lg"
                animate={{ scale: [1, 1.03, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                POPULAR
              </motion.div>
            )}
            {isNew && (
              <motion.div
                className="bg-green-400 text-green-900 text-xs font-bold px-2 py-0.5 rounded-full shadow-lg"
                animate={{ scale: [1, 1.03, 1] }}
                transition={{ duration: 2, repeat: Infinity, delay: 0.3 }}
              >
                NEW
              </motion.div>
            )}
          </div>
        )}

        <div className="flex items-start space-x-4 relative z-10">
          {/* Icon Container */}
          <motion.div
            className="w-12 h-12 bg-white/20 backdrop-blur-sm rounded-xl flex items-center justify-center flex-shrink-0 relative"
            animate={
              isHovered
                ? { rotate: [0, -5, 5, 0], scale: [1, 1.1, 1] }
                : {}
            }
            transition={{ duration: 0.5 }}
          >
            <Icon className="w-6 h-6 text-white" />

            {/* Icon Glow Effect */}
            <motion.div
              className="absolute inset-0 bg-white/10 rounded-xl blur-sm"
              animate={isHovered ? { scale: 1.2, opacity: 0.8 } : { scale: 1, opacity: 0 }}
              transition={{ duration: 0.3 }}
            />
          </motion.div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2 mb-1">
              <h3 className="font-bold text-white text-lg truncate">{title}</h3>
              <motion.div
                animate={isHovered ? { x: 3 } : { x: 0 }}
                transition={{ duration: 0.2 }}
              >
                <ChevronRight className="w-4 h-4 text-white/70" />
              </motion.div>
            </div>

            {subtitle && (
              <p className="text-white/90 font-medium text-sm mb-1">{subtitle}</p>
            )}

            {description && (
              <p className="text-white/70 text-xs leading-relaxed mb-2 line-clamp-2">
                {description}
              </p>
            )}

            {/* Stats */}
            {stats && (
              <motion.div
                className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-lg px-2 py-1 w-fit"
                animate={isHovered ? { scale: 1.02 } : { scale: 1 }}
                transition={{ duration: 0.2 }}
              >
                <StatsIcon className="w-3 h-3 text-white/80" />
                <span className="text-white/90 text-xs font-medium">
                  {stats.value}
                </span>
                <span className="text-white/70 text-xs">{stats.label}</span>
              </motion.div>
            )}
          </div>
        </div>
      </motion.button>
    </motion.div>
  );
};
