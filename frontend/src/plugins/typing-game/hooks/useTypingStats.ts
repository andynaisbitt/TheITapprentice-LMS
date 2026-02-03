// frontend/src/plugins/typing-game/hooks/useTypingStats.ts
/**
 * Typing Stats Calculator Hook
 *
 * Centralized stats calculation for all typing games
 * Eliminates duplication across QuickBrownFoxGame, GhostModeGame, and InfiniteRushGame
 *
 * Standard calculations:
 * - WPM: (correct characters / 5) / minutes
 * - Raw WPM: (all typed characters / 5) / minutes
 * - Accuracy: (correct / total) * 100
 */

import { useMemo } from 'react';
import type { WordState } from './useTypingEngine';

export interface TypingStats {
  wpm: number;
  rawWpm: number;
  accuracy: number;
  correctChars: number;
  incorrectChars: number;
  totalChars: number;
  correctWords: number;
  incorrectWords: number;
  totalWords: number;
  timeElapsed: number;
  maxCombo: number;
}

export interface TypingStatsInput {
  // Time tracking
  gameStartTime: number | null;

  // Word states for word-level stats
  wordStates: WordState[];
  totalWords: number;

  // Character tracking
  correctChars: number;
  incorrectChars: number;
  totalTypedChars: number;

  // Combo tracking
  maxCombo: number;
}

/**
 * Calculate typing statistics in real-time
 *
 * @param input - Stats calculation inputs
 * @returns Calculated typing statistics
 */
export function useTypingStats(input: TypingStatsInput): TypingStats {
  const {
    gameStartTime,
    wordStates,
    totalWords,
    correctChars,
    incorrectChars,
    totalTypedChars,
    maxCombo,
  } = input;

  return useMemo((): TypingStats => {
    // Calculate elapsed time
    const timeElapsed = gameStartTime
      ? (Date.now() - gameStartTime) / 1000
      : 0;

    // Word-level stats
    const completedWords = wordStates.filter(
      w => w.status === 'completed' || w.status === 'skipped'
    );
    const correctWords = completedWords.filter(w => w.isCorrect).length;
    const incorrectWords = completedWords.filter(w => !w.isCorrect).length;

    // Calculate WPM metrics
    const minutes = timeElapsed / 60;

    // Standard WPM: (correct characters / 5) / minutes
    const wpm = minutes > 0 ? Math.round((correctChars / 5) / minutes) : 0;

    // Raw WPM: all typed characters / 5 / minutes (includes errors)
    const rawWpm = minutes > 0 ? Math.round((totalTypedChars / 5) / minutes) : 0;

    // Calculate accuracy
    const totalChars = correctChars + incorrectChars;
    const accuracy = totalChars > 0
      ? Math.round((correctChars / totalChars) * 100)
      : 100;

    return {
      wpm,
      rawWpm,
      accuracy,
      correctChars,
      incorrectChars,
      totalChars,
      correctWords,
      incorrectWords,
      totalWords,
      timeElapsed,
      maxCombo,
    };
  }, [
    gameStartTime,
    wordStates,
    totalWords,
    correctChars,
    incorrectChars,
    totalTypedChars,
    maxCombo,
  ]);
}

export default useTypingStats;
