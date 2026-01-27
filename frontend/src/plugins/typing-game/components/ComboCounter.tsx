// frontend/src/plugins/typing-game/components/ComboCounter.tsx
/**
 * Animated Combo Counter Component
 *
 * Displays current combo with tier-based styling:
 * - Dynamic colors based on combo tier
 * - Scale animation on increment
 * - Break animation when combo ends
 * - Progress bar to next tier
 */

import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Flame, Zap, Star, Crown, Sparkles } from 'lucide-react';
import type { ComboState, ComboTier } from '../hooks/useComboSystem';
import { COMBO_TIERS } from '../hooks/useComboSystem';

interface ComboCounterProps {
  comboState: ComboState;
  showMaxCombo?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

// Tier icons
const TIER_ICONS: Record<ComboTier, React.ReactNode> = {
  none: null,
  nice: <Flame className="w-4 h-4" />,
  great: <Zap className="w-5 h-5" />,
  epic: <Star className="w-5 h-5" />,
  legendary: <Crown className="w-6 h-6" />,
  godlike: <Sparkles className="w-6 h-6" />,
};

export const ComboCounter: React.FC<ComboCounterProps> = ({
  comboState,
  showMaxCombo = true,
  size = 'md',
  className = '',
}) => {
  const { combo, maxCombo, tier, tierConfig, isActive, justBroke, justLeveledUp } = comboState;
  const [showBreakEffect, setShowBreakEffect] = useState(false);

  // Handle break animation
  useEffect(() => {
    if (justBroke && maxCombo > 0) {
      setShowBreakEffect(true);
      const timer = setTimeout(() => setShowBreakEffect(false), 600);
      return () => clearTimeout(timer);
    }
  }, [justBroke, maxCombo]);

  // Size classes
  const sizeClasses = {
    sm: 'text-2xl px-3 py-1.5',
    md: 'text-3xl px-4 py-2',
    lg: 'text-4xl px-6 py-3',
  };

  const iconSizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-5 h-5',
    lg: 'w-6 h-6',
  };

  // Calculate progress to next tier
  const getProgressToNextTier = (): number => {
    const tiers: ComboTier[] = ['none', 'nice', 'great', 'epic', 'legendary', 'godlike'];
    const currentIndex = tiers.indexOf(tier);
    const nextTier = tiers[currentIndex + 1];

    if (!nextTier || tier === 'godlike') return 100;

    const currentThreshold = COMBO_TIERS[tier].threshold;
    const nextThreshold = COMBO_TIERS[nextTier].threshold;
    const progress = ((combo - currentThreshold) / (nextThreshold - currentThreshold)) * 100;

    return Math.min(100, Math.max(0, progress));
  };

  // Don't show if combo is 0 and we don't want to show max
  if (!isActive && !showMaxCombo) {
    return null;
  }

  return (
    <div className={`relative ${className}`}>
      <AnimatePresence mode="wait">
        {isActive ? (
          <motion.div
            key="active-combo"
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0, y: -20 }}
            className="relative"
          >
            {/* Main combo display */}
            <motion.div
              className={`
                relative inline-flex items-center gap-2
                bg-gradient-to-r ${tierConfig.gradient}
                rounded-xl ${sizeClasses[size]}
                text-white font-bold
                shadow-lg
              `}
              style={{
                boxShadow: tier !== 'none'
                  ? `0 4px 20px rgba(${getGlowRGB(tierConfig.glowColor)}, 0.4)`
                  : undefined,
              }}
              animate={justLeveledUp ? {
                scale: [1, 1.2, 1],
                rotate: [0, -5, 5, 0],
              } : {
                scale: [1, 1.05, 1],
              }}
              transition={{
                duration: justLeveledUp ? 0.4 : 0.15,
                ease: 'easeOut',
              }}
            >
              {/* Tier icon */}
              {tier !== 'none' && (
                <motion.span
                  initial={{ rotate: -180, scale: 0 }}
                  animate={{ rotate: 0, scale: 1 }}
                  className={iconSizeClasses[size]}
                >
                  {TIER_ICONS[tier]}
                </motion.span>
              )}

              {/* Combo number */}
              <span className="tabular-nums">{combo}</span>
              <span className="text-white/70 text-sm font-normal">x</span>

              {/* Tier name badge */}
              {tierConfig.name && (
                <motion.span
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="text-xs uppercase tracking-wider bg-white/20 px-2 py-0.5 rounded-full"
                >
                  {tierConfig.name}
                </motion.span>
              )}
            </motion.div>

            {/* Progress to next tier */}
            {tier !== 'godlike' && (
              <div className="mt-2 h-1 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <motion.div
                  className={`h-full bg-gradient-to-r ${tierConfig.gradient}`}
                  initial={{ width: 0 }}
                  animate={{ width: `${getProgressToNextTier()}%` }}
                  transition={{ duration: 0.2 }}
                />
              </div>
            )}
          </motion.div>
        ) : showMaxCombo && maxCombo > 0 ? (
          <motion.div
            key="max-combo"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center"
          >
            <div className="text-gray-500 dark:text-gray-400 text-sm">
              Max Combo
            </div>
            <div className="text-2xl font-bold text-gray-700 dark:text-gray-300">
              {maxCombo}x
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      {/* Break effect overlay */}
      <AnimatePresence>
        {showBreakEffect && (
          <motion.div
            initial={{ opacity: 1, scale: 1 }}
            animate={{ opacity: 0, scale: 2 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="absolute inset-0 flex items-center justify-center pointer-events-none"
          >
            <div className="text-red-500 font-bold text-xl">
              BREAK!
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Particles effect on level up */}
      <AnimatePresence>
        {justLeveledUp && (
          <>
            {[...Array(8)].map((_, i) => (
              <motion.div
                key={i}
                initial={{
                  opacity: 1,
                  x: 0,
                  y: 0,
                  scale: 1,
                }}
                animate={{
                  opacity: 0,
                  x: Math.cos((i / 8) * Math.PI * 2) * 50,
                  y: Math.sin((i / 8) * Math.PI * 2) * 50,
                  scale: 0,
                }}
                transition={{ duration: 0.5 }}
                className={`absolute top-1/2 left-1/2 w-2 h-2 rounded-full bg-gradient-to-r ${tierConfig.gradient}`}
              />
            ))}
          </>
        )}
      </AnimatePresence>
    </div>
  );
};

// Helper to get RGB values for glow
function getGlowRGB(color: string): string {
  const colors: Record<string, string> = {
    gray: '128, 128, 128',
    green: '34, 197, 94',
    blue: '59, 130, 246',
    purple: '168, 85, 247',
    yellow: '234, 179, 8',
    red: '239, 68, 68',
  };
  return colors[color] || colors.gray;
}

export default ComboCounter;
