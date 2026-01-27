// frontend/src/plugins/skills/components/SkillXPToast.tsx
/**
 * SkillXPToast - Animated notification for skill XP gains
 * Shows when user earns skill XP from completing content
 */

import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { SkillXPGainResponse } from '../types';
import { Zap, TrendingUp, Star } from 'lucide-react';

interface SkillXPToastProps {
  xpGain: SkillXPGainResponse;
  onClose: () => void;
  duration?: number;
}

export const SkillXPToast: React.FC<SkillXPToastProps> = ({
  xpGain,
  onClose,
  duration = 4000,
}) => {
  useEffect(() => {
    const timer = setTimeout(onClose, duration);
    return () => clearTimeout(timer);
  }, [onClose, duration]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 50, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -20, scale: 0.9 }}
      className="fixed bottom-4 right-4 z-50"
    >
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden min-w-[280px]">
        {/* Header with skill icon */}
        <div
          className="px-4 py-3 flex items-center gap-3"
          style={{ backgroundColor: `${xpGain.newTier ? '#F59E0B' : '#10B981'}15` }}
        >
          <div className="w-10 h-10 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
            <Zap className="w-5 h-5 text-green-600 dark:text-green-400" />
          </div>
          <div className="flex-1">
            <div className="font-semibold text-gray-900 dark:text-white">
              +{xpGain.xpGained} {xpGain.skillName} XP
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Total: {xpGain.totalXp.toLocaleString()} XP
            </div>
          </div>
        </div>

        {/* Level up notification */}
        {xpGain.levelUp && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="px-4 py-3 bg-yellow-50 dark:bg-yellow-900/20 border-t border-yellow-200 dark:border-yellow-800"
          >
            <div className="flex items-center gap-2 text-yellow-700 dark:text-yellow-400">
              <TrendingUp className="w-5 h-5" />
              <span className="font-bold">
                Level Up! {xpGain.oldLevel} → {xpGain.newLevel}
              </span>
            </div>
          </motion.div>
        )}

        {/* Tier change notification */}
        {xpGain.tierChanged && xpGain.newTier && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="px-4 py-3 bg-purple-50 dark:bg-purple-900/20 border-t border-purple-200 dark:border-purple-800"
          >
            <div className="flex items-center gap-2 text-purple-700 dark:text-purple-400">
              <Star className="w-5 h-5" />
              <span className="font-bold">
                New Tier: {xpGain.newTier}!
              </span>
            </div>
          </motion.div>
        )}

        {/* Progress bar */}
        <div className="px-4 py-2 bg-gray-50 dark:bg-gray-700/50">
          <div className="h-1.5 bg-gray-200 dark:bg-gray-600 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: '100%' }}
              transition={{ duration: duration / 1000, ease: 'linear' }}
              className="h-full bg-green-500 rounded-full"
            />
          </div>
        </div>
      </div>
    </motion.div>
  );
};

// Hook for managing skill XP toasts
interface SkillXPToastManager {
  toasts: SkillXPGainResponse[];
  addToast: (xpGain: SkillXPGainResponse) => void;
  removeToast: (index: number) => void;
}

export const useSkillXPToasts = (): SkillXPToastManager => {
  const [toasts, setToasts] = useState<SkillXPGainResponse[]>([]);

  const addToast = (xpGain: SkillXPGainResponse) => {
    setToasts((prev) => [...prev, xpGain]);
  };

  const removeToast = (index: number) => {
    setToasts((prev) => prev.filter((_, i) => i !== index));
  };

  return { toasts, addToast, removeToast };
};

// Toast container component
interface SkillXPToastContainerProps {
  toasts: SkillXPGainResponse[];
  onRemove: (index: number) => void;
}

export const SkillXPToastContainer: React.FC<SkillXPToastContainerProps> = ({
  toasts,
  onRemove,
}) => {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      <AnimatePresence>
        {toasts.map((toast, index) => (
          <SkillXPToast
            key={`${toast.skillSlug}-${index}`}
            xpGain={toast}
            onClose={() => onRemove(index)}
          />
        ))}
      </AnimatePresence>
    </div>
  );
};

export default SkillXPToast;
