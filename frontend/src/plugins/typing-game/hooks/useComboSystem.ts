// frontend/src/plugins/typing-game/hooks/useComboSystem.ts
/**
 * Combo System Hook
 *
 * Tracks typing combos for engagement:
 * - Increment on correct characters
 * - Break on errors
 * - Tier-based visual feedback
 */

import { useState, useCallback, useRef, useMemo } from 'react';

// ==================== TYPES ====================

export type ComboTier = 'none' | 'nice' | 'great' | 'epic' | 'legendary' | 'godlike';

export interface ComboTierConfig {
  name: string;
  threshold: number;
  color: string;
  gradient: string;
  glowColor: string;
  sound?: string;
}

export interface ComboState {
  combo: number;
  maxCombo: number;
  tier: ComboTier;
  tierConfig: ComboTierConfig;
  isActive: boolean;
  justBroke: boolean;
  justLeveledUp: boolean;
  previousTier: ComboTier | null;
}

export interface UseComboSystemConfig {
  onComboMilestone?: (combo: number, tier: ComboTier) => void;
  onComboBreak?: (finalCombo: number, maxCombo: number) => void;
  onTierUp?: (newTier: ComboTier, combo: number) => void;
}

// ==================== CONSTANTS ====================

export const COMBO_TIERS: Record<ComboTier, ComboTierConfig> = {
  none: {
    name: '',
    threshold: 0,
    color: 'text-gray-500',
    gradient: 'from-gray-400 to-gray-500',
    glowColor: 'gray',
  },
  nice: {
    name: 'NICE',
    threshold: 10,
    color: 'text-green-500',
    gradient: 'from-green-400 to-emerald-500',
    glowColor: 'green',
    sound: 'combo_nice',
  },
  great: {
    name: 'GREAT',
    threshold: 25,
    color: 'text-blue-500',
    gradient: 'from-blue-400 to-cyan-500',
    glowColor: 'blue',
    sound: 'combo_great',
  },
  epic: {
    name: 'EPIC',
    threshold: 50,
    color: 'text-purple-500',
    gradient: 'from-purple-400 to-pink-500',
    glowColor: 'purple',
    sound: 'combo_epic',
  },
  legendary: {
    name: 'LEGENDARY',
    threshold: 100,
    color: 'text-yellow-500',
    gradient: 'from-yellow-400 to-orange-500',
    glowColor: 'yellow',
    sound: 'combo_legendary',
  },
  godlike: {
    name: 'GODLIKE',
    threshold: 200,
    color: 'text-red-500',
    gradient: 'from-red-400 to-rose-600',
    glowColor: 'red',
    sound: 'combo_godlike',
  },
};

// Milestone combos for achievements/XP
export const COMBO_MILESTONES = [10, 25, 50, 75, 100, 150, 200, 300, 500];

// ==================== UTILITY ====================

function getTierForCombo(combo: number): ComboTier {
  if (combo >= COMBO_TIERS.godlike.threshold) return 'godlike';
  if (combo >= COMBO_TIERS.legendary.threshold) return 'legendary';
  if (combo >= COMBO_TIERS.epic.threshold) return 'epic';
  if (combo >= COMBO_TIERS.great.threshold) return 'great';
  if (combo >= COMBO_TIERS.nice.threshold) return 'nice';
  return 'none';
}

// ==================== HOOK ====================

export function useComboSystem(config: UseComboSystemConfig = {}) {
  const { onComboMilestone, onComboBreak, onTierUp } = config;

  // State
  const [combo, setCombo] = useState(0);
  const [maxCombo, setMaxCombo] = useState(0);
  const [justBroke, setJustBroke] = useState(false);
  const [justLeveledUp, setJustLeveledUp] = useState(false);
  const [previousTier, setPreviousTier] = useState<ComboTier | null>(null);

  // Track last reached milestones to avoid duplicate callbacks
  const reachedMilestones = useRef<Set<number>>(new Set());
  const lastTier = useRef<ComboTier>('none');

  // Current tier based on combo
  const tier = useMemo(() => getTierForCombo(combo), [combo]);
  const tierConfig = COMBO_TIERS[tier];

  // Increment combo
  const increment = useCallback(() => {
    setCombo(prev => {
      const newCombo = prev + 1;

      // Update max combo
      setMaxCombo(max => Math.max(max, newCombo));

      // Check for tier up
      const newTier = getTierForCombo(newCombo);
      if (newTier !== lastTier.current && newTier !== 'none') {
        lastTier.current = newTier;
        setPreviousTier(getTierForCombo(prev));
        setJustLeveledUp(true);
        setTimeout(() => setJustLeveledUp(false), 500);
        onTierUp?.(newTier, newCombo);
      }

      // Check for milestones
      COMBO_MILESTONES.forEach(milestone => {
        if (newCombo === milestone && !reachedMilestones.current.has(milestone)) {
          reachedMilestones.current.add(milestone);
          onComboMilestone?.(milestone, newTier);
        }
      });

      return newCombo;
    });

    // Reset break state
    setJustBroke(false);
  }, [onComboMilestone, onTierUp]);

  // Break combo (on error)
  const breakCombo = useCallback(() => {
    setCombo(prev => {
      if (prev > 0) {
        setJustBroke(true);
        setTimeout(() => setJustBroke(false), 500);
        onComboBreak?.(prev, Math.max(maxCombo, prev));
      }
      return 0;
    });

    // Reset tier tracking
    lastTier.current = 'none';
    setPreviousTier(null);
  }, [maxCombo, onComboBreak]);

  // Reset everything
  const reset = useCallback(() => {
    setCombo(0);
    setMaxCombo(0);
    setJustBroke(false);
    setJustLeveledUp(false);
    setPreviousTier(null);
    reachedMilestones.current = new Set();
    lastTier.current = 'none';
  }, []);

  // Get combo state for display
  const state: ComboState = useMemo(() => ({
    combo,
    maxCombo,
    tier,
    tierConfig,
    isActive: combo > 0,
    justBroke,
    justLeveledUp,
    previousTier,
  }), [combo, maxCombo, tier, tierConfig, justBroke, justLeveledUp, previousTier]);

  // Calculate XP bonus based on max combo
  const getComboXPBonus = useCallback((finalMaxCombo: number): number => {
    if (finalMaxCombo >= 200) return 100;
    if (finalMaxCombo >= 100) return 60;
    if (finalMaxCombo >= 50) return 25;
    if (finalMaxCombo >= 25) return 10;
    return 0;
  }, []);

  return {
    // State
    combo,
    maxCombo,
    tier,
    tierConfig,
    state,

    // Computed
    isActive: combo > 0,
    progress: tier !== 'godlike'
      ? (combo - tierConfig.threshold) /
        (COMBO_TIERS[getNextTier(tier)]?.threshold - tierConfig.threshold || 1) * 100
      : 100,

    // Methods
    increment,
    breakCombo,
    reset,
    getComboXPBonus,

    // Constants (for external use)
    TIERS: COMBO_TIERS,
    MILESTONES: COMBO_MILESTONES,
  };
}

// Helper to get next tier
function getNextTier(current: ComboTier): ComboTier {
  const tiers: ComboTier[] = ['none', 'nice', 'great', 'epic', 'legendary', 'godlike'];
  const currentIndex = tiers.indexOf(current);
  return tiers[Math.min(currentIndex + 1, tiers.length - 1)];
}

export default useComboSystem;
