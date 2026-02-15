// frontend/src/plugins/typing-game/hooks/useAntiCheat.ts
/**
 * Anti-Cheat Data Collection Hook
 *
 * Collects typing behavior data for server-side validation:
 * - Keystroke timing (inter-key intervals)
 * - Copy/paste attempts
 * - Focus/blur events
 * - Suspicious activity detection
 */

import { useState, useCallback, useRef, useEffect } from 'react';

// ==================== TYPES ====================

export interface AntiCheatData {
  // Timing data
  keystrokeTimings: number[];      // Inter-key intervals in ms
  keystrokeCount: number;
  avgInterKeyTime: number;
  stdDevInterKeyTime: number;

  // First/last segments for speed ramp analysis
  firstSegmentAvg: number;         // Avg of first 10 keystrokes
  lastSegmentAvg: number;          // Avg of last 10 keystrokes

  // Suspicious activity
  pasteAttempts: number;
  focusLostCount: number;
  focusLostDurations: number[];    // Duration of each focus loss in ms
  totalFocusLostTime: number;

  // Flags
  suspiciousEvents: SuspiciousEvent[];
}

export interface SuspiciousEvent {
  type: 'paste_attempt' | 'focus_lost' | 'impossible_speed' | 'auto_complete';
  timestamp: number;
  details?: string;
}

export interface UseAntiCheatConfig {
  enabled?: boolean;
  onSuspiciousActivity?: (event: SuspiciousEvent) => void;
}

// ==================== CONSTANTS ====================

const MIN_HUMANLY_POSSIBLE_INTERVAL = 15; // ms - true physical limit (key rollover can produce 20-30ms legitimately)
const SEGMENT_SIZE = 10; // Number of keystrokes for first/last segment analysis

// ==================== HOOK ====================

export function useAntiCheat(config: UseAntiCheatConfig = {}) {
  const { enabled = true, onSuspiciousActivity } = config;

  // Refs for data collection (won't cause re-renders)
  const keystrokeTimings = useRef<number[]>([]);
  const lastKeystrokeTime = useRef<number | null>(null);
  const pasteAttempts = useRef(0);
  const focusLostCount = useRef(0);
  const focusLostDurations = useRef<number[]>([]);
  const focusLostStart = useRef<number | null>(null);
  const suspiciousEvents = useRef<SuspiciousEvent[]>([]);
  const isGameActive = useRef(false);

  // Track game state
  const [gameActive, setGameActive] = useState(false);

  // Start collecting data
  const startTracking = useCallback(() => {
    if (!enabled) return;

    keystrokeTimings.current = [];
    lastKeystrokeTime.current = null;
    pasteAttempts.current = 0;
    focusLostCount.current = 0;
    focusLostDurations.current = [];
    focusLostStart.current = null;
    suspiciousEvents.current = [];
    isGameActive.current = true;
    setGameActive(true);
  }, [enabled]);

  // Stop collecting data
  const stopTracking = useCallback(() => {
    isGameActive.current = false;
    setGameActive(false);

    // If focus was lost, record the duration
    if (focusLostStart.current) {
      const duration = Date.now() - focusLostStart.current;
      focusLostDurations.current.push(duration);
      focusLostStart.current = null;
    }
  }, []);

  // Record a keystroke
  const recordKeystroke = useCallback((timestamp?: number) => {
    if (!enabled || !isGameActive.current) return;

    const now = timestamp || Date.now();

    if (lastKeystrokeTime.current !== null) {
      const interval = now - lastKeystrokeTime.current;
      keystrokeTimings.current.push(interval);

      // Check for impossible speed
      if (interval < MIN_HUMANLY_POSSIBLE_INTERVAL) {
        const event: SuspiciousEvent = {
          type: 'impossible_speed',
          timestamp: now,
          details: `Inter-key interval of ${interval}ms detected`,
        };
        suspiciousEvents.current.push(event);
        onSuspiciousActivity?.(event);
      }
    }

    lastKeystrokeTime.current = now;
  }, [enabled, onSuspiciousActivity]);

  // Record paste attempt
  const recordPasteAttempt = useCallback(() => {
    if (!enabled) return;

    pasteAttempts.current++;

    const event: SuspiciousEvent = {
      type: 'paste_attempt',
      timestamp: Date.now(),
      details: `Paste attempt #${pasteAttempts.current}`,
    };
    suspiciousEvents.current.push(event);
    onSuspiciousActivity?.(event);
  }, [enabled, onSuspiciousActivity]);

  // Handle focus loss
  const handleVisibilityChange = useCallback(() => {
    if (!enabled || !isGameActive.current) return;

    if (document.hidden) {
      // Tab became hidden
      focusLostStart.current = Date.now();
      focusLostCount.current++;

      const event: SuspiciousEvent = {
        type: 'focus_lost',
        timestamp: Date.now(),
        details: `Focus lost #${focusLostCount.current}`,
      };
      suspiciousEvents.current.push(event);
      onSuspiciousActivity?.(event);
    } else {
      // Tab became visible again
      if (focusLostStart.current) {
        const duration = Date.now() - focusLostStart.current;
        focusLostDurations.current.push(duration);
        focusLostStart.current = null;
      }
    }
  }, [enabled, onSuspiciousActivity]);

  // Set up visibility change listener
  useEffect(() => {
    if (!enabled) return;

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [enabled, handleVisibilityChange]);

  // Calculate statistics
  const calculateStats = useCallback((): {
    avg: number;
    stdDev: number;
    firstSegmentAvg: number;
    lastSegmentAvg: number;
  } => {
    const timings = keystrokeTimings.current;

    if (timings.length === 0) {
      return { avg: 0, stdDev: 0, firstSegmentAvg: 0, lastSegmentAvg: 0 };
    }

    // Calculate average
    const sum = timings.reduce((a, b) => a + b, 0);
    const avg = sum / timings.length;

    // Calculate standard deviation
    const squaredDiffs = timings.map(t => Math.pow(t - avg, 2));
    const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / timings.length;
    const stdDev = Math.sqrt(avgSquaredDiff);

    // Calculate first segment average
    const firstSegment = timings.slice(0, SEGMENT_SIZE);
    const firstSegmentAvg = firstSegment.length > 0
      ? firstSegment.reduce((a, b) => a + b, 0) / firstSegment.length
      : 0;

    // Calculate last segment average
    const lastSegment = timings.slice(-SEGMENT_SIZE);
    const lastSegmentAvg = lastSegment.length > 0
      ? lastSegment.reduce((a, b) => a + b, 0) / lastSegment.length
      : 0;

    return { avg, stdDev, firstSegmentAvg, lastSegmentAvg };
  }, []);

  // Get complete anti-cheat data for submission
  const getAntiCheatData = useCallback((): AntiCheatData => {
    // Finalize any ongoing focus loss
    if (focusLostStart.current) {
      const duration = Date.now() - focusLostStart.current;
      focusLostDurations.current.push(duration);
      focusLostStart.current = null;
    }

    const { avg, stdDev, firstSegmentAvg, lastSegmentAvg } = calculateStats();
    const totalFocusLostTime = focusLostDurations.current.reduce((a, b) => a + b, 0);

    return {
      keystrokeTimings: keystrokeTimings.current,
      keystrokeCount: keystrokeTimings.current.length + 1, // +1 for first keystroke
      avgInterKeyTime: Math.round(avg * 100) / 100,
      stdDevInterKeyTime: Math.round(stdDev * 100) / 100,
      firstSegmentAvg: Math.round(firstSegmentAvg * 100) / 100,
      lastSegmentAvg: Math.round(lastSegmentAvg * 100) / 100,
      pasteAttempts: pasteAttempts.current,
      focusLostCount: focusLostCount.current,
      focusLostDurations: focusLostDurations.current,
      totalFocusLostTime,
      suspiciousEvents: suspiciousEvents.current,
    };
  }, [calculateStats]);

  // Reset all collected data
  const reset = useCallback(() => {
    keystrokeTimings.current = [];
    lastKeystrokeTime.current = null;
    pasteAttempts.current = 0;
    focusLostCount.current = 0;
    focusLostDurations.current = [];
    focusLostStart.current = null;
    suspiciousEvents.current = [];
    isGameActive.current = false;
    setGameActive(false);
  }, []);

  // Prevent paste event handler
  const createPasteHandler = useCallback(() => {
    return (e: React.ClipboardEvent | ClipboardEvent) => {
      e.preventDefault();
      recordPasteAttempt();
      return false;
    };
  }, [recordPasteAttempt]);

  // Create keyboard event handler that blocks Ctrl+V / Cmd+V
  const createKeyDownHandler = useCallback((originalHandler?: (e: React.KeyboardEvent) => void) => {
    return (e: React.KeyboardEvent<HTMLInputElement>) => {
      // Block paste shortcuts
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v') {
        e.preventDefault();
        recordPasteAttempt();
        return;
      }

      // Record keystroke timing for regular keys
      if (e.key.length === 1 || e.key === 'Backspace' || e.key === ' ') {
        recordKeystroke();
      }

      // Call original handler
      originalHandler?.(e);
    };
  }, [recordKeystroke, recordPasteAttempt]);

  return {
    // State
    isTracking: gameActive,

    // Methods
    startTracking,
    stopTracking,
    recordKeystroke,
    recordPasteAttempt,
    getAntiCheatData,
    reset,

    // Handlers
    createPasteHandler,
    createKeyDownHandler,

    // Quick access to current stats
    get currentStats() {
      return calculateStats();
    },
  };
}

export default useAntiCheat;
