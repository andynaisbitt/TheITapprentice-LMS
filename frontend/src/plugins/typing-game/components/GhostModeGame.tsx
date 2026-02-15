// frontend/src/plugins/typing-game/components/GhostModeGame.tsx
/**
 * Ghost Mode - Race Against Your Personal Best
 *
 * Features:
 * - Shows your personal best as a "ghost" to race against
 * - Real-time progress comparison (ahead/behind indicator)
 * - Ghost progress bar showing expected position
 * - Visual feedback when beating or falling behind ghost
 * - Same 3-round challenge format as Quick Brown Fox
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Play,
  RotateCcw,
  Trophy,
  Clock,
  Keyboard,
  Zap,
  AlertCircle,
  UserPlus,
  Target,
  TrendingUp,
  Flame,
  Ghost,
  ArrowUp,
  ArrowDown,
  Minus,
  Star,
  Sparkles,
  ArrowLeft,
} from 'lucide-react';

import { typingGameApi, type StreakInfo, type DailyChallenge } from '../services/typingGameApi';
import { useTypingEngine } from '../hooks/useTypingEngine';
import { useAntiCheat } from '../hooks/useAntiCheat';
import { useComboSystem } from '../hooks/useComboSystem';
import { useSoundEffects } from '../hooks/useSoundEffects';
import { WordDisplay } from './WordDisplay';
import { ComboCounter } from './ComboCounter';
import { StreakDisplay } from './StreakDisplay';
import { SoundSettingsPanel } from './SoundSettings';
import { Link } from 'react-router-dom';
import { useAuth } from '../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../hooks/useRegistrationPrompt';
import type {
  TypingGameStartResponse,
  TypingGameResultsResponse,
  TypingGameSubmitRequestV2,
  UserTypingStats,
  RoundConfig,
} from '../types';

// ==================== CONFIGURATION ====================

const ROUNDS: RoundConfig[] = [
  {
    roundNumber: 1,
    name: 'Warmup',
    timeLimit: null,
    description: 'Get into the groove. Your ghost is watching!',
  },
  {
    roundNumber: 2,
    name: 'Speed Challenge',
    timeLimit: 25,
    description: 'Beat your ghost in 25 seconds!',
  },
  {
    roundNumber: 3,
    name: 'INSANE MODE',
    timeLimit: 12,
    description: 'Final showdown - 12 seconds!',
  },
];

// Text pools
const ROUND_TEXTS: Record<number, string[]> = {
  1: [
    'The quick brown fox jumps over the lazy dog',
    'Pack my box with five dozen liquor jugs',
    'How vexingly quick daft zebras jump',
    'User reports Outlook stuck on loading profile',
    'Rebooted the server and cleared the DNS cache',
    'Check the firewall rules and open port 443',
    'The backup completed successfully at midnight',
  ],
  2: [
    'function deploy(env) { return fetch(api + env); }',
    'git commit -m "fix: resolve login timeout issue"',
    'docker run -d -p 8080:80 nginx:latest',
    'npm install express cors dotenv jsonwebtoken',
    'ssh admin@192.168.1.100 -i ~/.ssh/id_rsa',
  ],
  3: [
    'Quick wafting zephyrs vex bold Jim',
    'Sphinx of black quartz judge my vow',
    'sudo rm -rf /tmp/cache && reboot now',
    'ping 8.8.8.8 && traceroute google.com',
    'git push origin main --force-with-lease',
  ],
};

// ==================== INTERFACES ====================

interface GhostModeGameProps {
  onComplete?: (results: TypingGameResultsResponse) => void;
  onExit?: () => void;
}

interface RoundResult {
  round: number;
  wpm: number;
  accuracy: number;
  time: number;
  passed: boolean;
  maxCombo: number;
  beatGhost: boolean;
}

type GameStatus = 'idle' | 'ready' | 'playing' | 'round_complete' | 'game_complete' | 'failed' | 'no_ghost';

// ==================== GHOST INDICATOR COMPONENT ====================

const GhostIndicator: React.FC<{
  currentWpm: number;
  ghostWpm: number;
  className?: string;
}> = ({ currentWpm, ghostWpm, className = '' }) => {
  const diff = currentWpm - ghostWpm;
  const isAhead = diff > 0;
  const isBehind = diff < 0;
  const isTied = diff === 0;

  return (
    <motion.div
      className={`flex items-center gap-2 px-3 py-2 rounded-lg ${
        isAhead
          ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
          : isBehind
          ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
          : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-400'
      } ${className}`}
      animate={
        isAhead
          ? { scale: [1, 1.05, 1] }
          : isBehind
          ? { x: [-2, 2, -2, 2, 0] }
          : {}
      }
      transition={{ duration: 0.3 }}
    >
      <Ghost className="w-5 h-5 opacity-70" />
      {isAhead && (
        <>
          <ArrowUp className="w-4 h-4" />
          <span className="font-bold">+{diff} WPM</span>
        </>
      )}
      {isBehind && (
        <>
          <ArrowDown className="w-4 h-4" />
          <span className="font-bold">{diff} WPM</span>
        </>
      )}
      {isTied && (
        <>
          <Minus className="w-4 h-4" />
          <span className="font-bold">Tied!</span>
        </>
      )}
    </motion.div>
  );
};

// ==================== GHOST PROGRESS BAR ====================

const GhostProgressBar: React.FC<{
  currentProgress: number; // 0-100
  ghostProgress: number; // 0-100
}> = ({ currentProgress, ghostProgress }) => {
  return (
    <div className="relative h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
      {/* Ghost progress (translucent) */}
      <motion.div
        className="absolute top-0 left-0 h-full bg-purple-400/40 dark:bg-purple-500/40 rounded-full"
        initial={{ width: '0%' }}
        animate={{ width: `${ghostProgress}%` }}
        transition={{ duration: 0.3 }}
      />
      {/* Player progress */}
      <motion.div
        className={`absolute top-0 left-0 h-full rounded-full ${
          currentProgress >= ghostProgress
            ? 'bg-green-500'
            : 'bg-blue-500'
        }`}
        initial={{ width: '0%' }}
        animate={{ width: `${currentProgress}%` }}
        transition={{ duration: 0.3 }}
      />
      {/* Ghost marker */}
      <motion.div
        className="absolute top-0 h-full w-1 bg-purple-600 dark:bg-purple-400 shadow-lg"
        style={{ left: `calc(${ghostProgress}% - 2px)` }}
      >
        <Ghost className="w-4 h-4 text-purple-600 dark:text-purple-400 absolute -top-5 -left-1.5" />
      </motion.div>
    </div>
  );
};

// ==================== COUNTDOWN COMPONENT ====================

const GhostCountdown: React.FC<{ onComplete: () => void; seconds: number; roundColor: string }> = ({ onComplete, seconds, roundColor }) => {
  const [count, setCount] = useState(seconds);

  useEffect(() => {
    if (count <= 0) {
      onComplete();
      return;
    }
    const timer = setTimeout(() => setCount(c => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [count, onComplete]);

  return (
    <div className="flex flex-col items-center">
      <motion.div
        key={count}
        initial={{ scale: 1.5, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.5, opacity: 0 }}
        transition={{ duration: 0.3, type: 'spring', damping: 15 }}
        className={`text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r ${roundColor}`}
      >
        {count}
      </motion.div>
      {/* Progress bar */}
      <div className="relative w-16 h-1 mt-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <motion.div
          className={`absolute inset-y-0 left-0 bg-gradient-to-r ${roundColor} rounded-full`}
          initial={{ width: '100%' }}
          animate={{ width: '0%' }}
          transition={{ duration: seconds, ease: 'linear' }}
        />
      </div>
    </div>
  );
};

// ==================== COMPONENT ====================

export const GhostModeGame: React.FC<GhostModeGameProps> = ({
  onComplete,
  onExit,
}) => {
  const { isAuthenticated } = useAuth();

  // Registration prompt
  const {
    isPromptOpen,
    closePrompt,
    handleSkip: handlePromptSkip,
    showPrompt,
  } = useRegistrationPrompt({
    context: 'game',
    onSkip: () => {},
  });

  // Sound effects
  const sounds = useSoundEffects();

  // Ghost (personal best) state
  const [ghostStats, setGhostStats] = useState<UserTypingStats | null>(null);
  const [loadingGhost, setLoadingGhost] = useState(true);

  // Game state
  const [gameStatus, setGameStatus] = useState<GameStatus>('idle');
  const [currentRound, setCurrentRound] = useState(0);
  const [roundText, setRoundText] = useState('');
  const [sessionData, setSessionData] = useState<TypingGameStartResponse | null>(null);
  const [results, setResults] = useState<TypingGameResultsResponse | null>(null);
  const [roundResults, setRoundResults] = useState<RoundResult[]>([]);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const [checksum, setChecksum] = useState('');
  const [inputFocused, setInputFocused] = useState(false);

  // Track typed text
  const [actualTypedText, setActualTypedText] = useState('');

  // Streak state
  const [streakInfo, setStreakInfo] = useState<StreakInfo | null>(null);

  // Refs
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const roundStartTime = useRef<number | null>(null);
  const keyDownHandledRef = useRef(false);

  // Current round config
  const currentRoundConfig = ROUNDS[currentRound];

  // Get random text
  const getRandomText = useCallback((roundNum: number): string => {
    const texts = ROUND_TEXTS[roundNum as keyof typeof ROUND_TEXTS] || ROUND_TEXTS[1];
    return texts[Math.floor(Math.random() * texts.length)];
  }, []);

  // Combo tracking
  const lastTierRef = useRef<string>('none');

  // Initialize typing engine
  const {
    status: engineStatus,
    wordStates,
    currentWordIndex,
    currentInput,
    stats,
    combo,
    maxCombo,
    getCharacterStates,
    handleKeyDown: engineHandleKeyDown,
    handlePaste,
    reset: resetEngine,
  } = useTypingEngine(roundText, {
    onWordComplete: (wordIndex, isCorrect, wordWpm) => {
      const completedWord = wordStates[wordIndex];
      if (completedWord) {
        setActualTypedText(prev => prev + (prev ? ' ' : '') + completedWord.typedValue);
      }
      if (isCorrect) {
        sounds.playMilestone();
      }
    },
    onGameComplete: () => {
      sounds.playGameEnd();
      completeRound(true);
    },
    onError: () => {
      sounds.playError();
      comboSystem.breakCombo();
      antiCheat.recordKeystroke();
    },
    onKeystroke: (keystrokeData) => {
      antiCheat.recordKeystroke(keystrokeData.timestamp);
      if (keystrokeData.isCorrect) {
        comboSystem.increment();
        sounds.playKeystroke();
      }
      const newTier = comboSystem.tier;
      if (newTier !== lastTierRef.current && newTier !== 'none') {
        sounds.playCombo(comboSystem.combo);
        lastTierRef.current = newTier;
      }
    },
  });

  // Anti-cheat
  const antiCheat = useAntiCheat({
    enabled: true,
    onSuspiciousActivity: (event) => {
      console.log('[Anti-Cheat] Suspicious activity:', event);
    },
  });

  // Combo system
  const comboSystem = useComboSystem({
    onComboMilestone: (milestone, tier) => {
      console.log(`[Combo] Milestone: ${milestone} (${tier})`);
    },
    onComboBreak: (finalCombo, maxCombo) => {
      console.log(`[Combo] Broken at ${finalCombo}, max was ${maxCombo}`);
    },
    onTierUp: (newTier, comboCount) => {
      console.log(`[Combo] Tier up to ${newTier} at ${comboCount}`);
    },
  });

  // Focus input
  const focusInput = useCallback(() => {
    if (inputRef.current) {
      setTimeout(() => {
        inputRef.current?.focus();
        inputRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 100);
    }
  }, []);

  // Calculate ghost progress (expected WPM-based progress)
  const ghostProgress = useMemo(() => {
    if (!ghostStats || !roundStartTime.current || gameStatus !== 'playing') return 0;
    const elapsed = (Date.now() - roundStartTime.current) / 1000 / 60; // minutes
    if (elapsed <= 0) return 0;
    // Estimate words the ghost would have typed
    const expectedWords = (ghostStats.best_wpm / 60) * (Date.now() - roundStartTime.current) / 1000;
    const totalWords = wordStates.length;
    return Math.min(100, (expectedWords / totalWords) * 100);
  }, [ghostStats, wordStates.length, gameStatus, stats.timeElapsed]);

  // Current progress
  const currentProgress = useMemo(() => {
    if (wordStates.length === 0) return 0;
    return (currentWordIndex / wordStates.length) * 100;
  }, [currentWordIndex, wordStates.length]);

  // Load ghost (personal best)
  useEffect(() => {
    const loadGhost = async () => {
      if (!isAuthenticated) {
        setLoadingGhost(false);
        return;
      }

      try {
        const userStats = await typingGameApi.getMyStats();
        if (userStats.total_games_completed > 0 && userStats.best_wpm > 0) {
          setGhostStats(userStats);
        }
      } catch (error) {
        console.error('Failed to load ghost stats:', error);
      } finally {
        setLoadingGhost(false);
      }
    };

    loadGhost();
  }, [isAuthenticated]);

  // Start game
  const startGame = useCallback(async () => {
    if (!ghostStats) {
      setGameStatus('no_ghost');
      return;
    }

    try {
      const response = await typingGameApi.startGame({
        mode: 'challenge',
        word_count: 9,
      });
      setSessionData(response);
      setChecksum(response.checksum);
    } catch (error) {
      console.error('Failed to start game session:', error);
    }

    setCurrentRound(0);
    setRoundResults([]);
    const text = getRandomText(1);
    setRoundText(text);
    setGameStatus('ready');
  }, [ghostStats, getRandomText]);

  // Start round
  const startRound = useCallback(() => {
    resetEngine();
    comboSystem.reset();
    antiCheat.reset();
    antiCheat.startTracking();
    lastTierRef.current = 'none';
    setActualTypedText('');

    roundStartTime.current = Date.now();
    const roundConfig = ROUNDS[currentRound];
    if (roundConfig.timeLimit) {
      setTimeRemaining(roundConfig.timeLimit);
    } else {
      setTimeRemaining(null);
    }

    sounds.playGameStart();
    setGameStatus('playing');
    focusInput();
  }, [currentRound, resetEngine, comboSystem, antiCheat, focusInput, sounds]);

  // Complete round
  const completeRound = useCallback((passed: boolean) => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    antiCheat.stopTracking();

    const finalTime = roundStartTime.current
      ? (Date.now() - roundStartTime.current) / 1000
      : 0;

    const beatGhost = ghostStats ? stats.wpm > ghostStats.best_wpm : false;

    const roundResult: RoundResult = {
      round: currentRound + 1,
      wpm: stats.wpm,
      accuracy: stats.accuracy,
      time: Math.round(finalTime * 10) / 10,
      passed,
      maxCombo: Math.max(maxCombo, comboSystem.maxCombo),
      beatGhost,
    };

    setRoundResults(prev => [...prev, roundResult]);

    if (!passed) {
      setGameStatus('failed');
    } else if (currentRound >= ROUNDS.length - 1) {
      submitFinalResults();
    } else {
      setGameStatus('round_complete');
    }
  }, [currentRound, stats, maxCombo, comboSystem.maxCombo, antiCheat, ghostStats]);

  // Submit results
  const submitFinalResults = useCallback(async () => {
    if (!sessionData) {
      setGameStatus('game_complete');
      return;
    }

    const antiCheatData = antiCheat.getAntiCheatData();

    const submitRequest: TypingGameSubmitRequestV2 = {
      session_id: sessionData.session_id,
      user_input: actualTypedText,
      time_elapsed: Math.round(stats.timeElapsed),
      checksum: checksum,
      max_combo: Math.max(maxCombo, comboSystem.maxCombo),
      anti_cheat: {
        keystroke_timings: antiCheatData.keystrokeTimings,
        keystroke_count: antiCheatData.keystrokeCount,
        paste_attempts: antiCheatData.pasteAttempts,
        focus_lost_count: antiCheatData.focusLostCount,
        total_focus_lost_time: antiCheatData.totalFocusLostTime,
        first_segment_avg: antiCheatData.firstSegmentAvg,
        last_segment_avg: antiCheatData.lastSegmentAvg,
      },
    };

    try {
      const finalResults = await typingGameApi.submitGameV2(submitRequest);
      if (finalResults.is_personal_best_wpm || finalResults.is_personal_best_accuracy) {
        sounds.playPersonalBest();
      }
      setResults(finalResults);
      setGameStatus('game_complete');
      onComplete?.(finalResults);
    } catch (error) {
      console.error('Failed to submit results:', error);
      setGameStatus('game_complete');
    }
  }, [sessionData, actualTypedText, stats.timeElapsed, checksum, maxCombo, comboSystem.maxCombo, antiCheat, onComplete, sounds]);

  // Next round
  const nextRound = useCallback(() => {
    const nextRoundNum = currentRound + 1;
    setCurrentRound(nextRoundNum);
    const text = getRandomText(nextRoundNum + 1);
    setRoundText(text);
    setGameStatus('ready');
  }, [currentRound, getRandomText]);

  // Timer effect
  useEffect(() => {
    if (gameStatus === 'playing' && currentRoundConfig?.timeLimit) {
      timerRef.current = setInterval(() => {
        const elapsed = roundStartTime.current
          ? (Date.now() - roundStartTime.current) / 1000
          : 0;
        const remaining = currentRoundConfig.timeLimit! - elapsed;

        if (remaining <= 0) {
          setTimeRemaining(0);
          completeRound(false);
        } else {
          setTimeRemaining(Math.ceil(remaining));
        }
      }, 100);

      return () => {
        if (timerRef.current) clearInterval(timerRef.current);
      };
    }
  }, [gameStatus, currentRoundConfig, completeRound]);

  // Auto-focus input when playing starts
  useEffect(() => {
    if (gameStatus === 'playing') {
      setInputFocused(true);
      focusInput();
    }
  }, [gameStatus, focusInput]);

  // Key handler
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>, fromOnChange = false) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v') {
      e.preventDefault();
      antiCheat.recordPasteAttempt();
      return;
    }

    if (!fromOnChange) {
      keyDownHandledRef.current = true;
    }

    engineHandleKeyDown(e);
  }, [engineHandleKeyDown, antiCheat]);

  // Average stats
  const avgStats = useMemo(() => {
    if (roundResults.length === 0) return { wpm: 0, accuracy: 0, maxCombo: 0, roundsBeatGhost: 0 };
    return {
      wpm: Math.round(roundResults.reduce((sum, r) => sum + r.wpm, 0) / roundResults.length),
      accuracy: Math.round(roundResults.reduce((sum, r) => sum + r.accuracy, 0) / roundResults.length),
      maxCombo: Math.max(...roundResults.map(r => r.maxCombo)),
      roundsBeatGhost: roundResults.filter(r => r.beatGhost).length,
    };
  }, [roundResults]);

  // ==================== RENDER: LOADING ====================
  if (loadingGhost) {
    return (
      <div className="max-w-2xl mx-auto p-4 sm:p-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center">
          <Ghost className="w-16 h-16 text-purple-500 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-600 dark:text-gray-400">Loading your ghost...</p>
        </div>
      </div>
    );
  }

  // ==================== RENDER: NO GHOST ====================
  if (gameStatus === 'no_ghost' || (!loadingGhost && !ghostStats && !isAuthenticated)) {
    return (
      <div className="max-w-2xl mx-auto p-4 sm:p-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center">
          <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-purple-100 to-indigo-100 dark:from-purple-900/30 dark:to-indigo-900/30 rounded-full flex items-center justify-center">
            <Ghost className="w-10 h-10 text-purple-400" />
          </div>
          <h2 className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
            {isAuthenticated ? 'Create Your Ghost' : 'No Ghost Yet'}
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            {isAuthenticated
              ? "Play your first typing game to unlock Ghost Mode! Your best performance becomes the ghost you'll race against."
              : "Sign in and complete a challenge to race against your personal best."}
          </p>
          {isAuthenticated ? (
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Link
                to="/typing-practice/play"
                className="px-6 py-3 bg-gradient-to-r from-purple-500 to-indigo-600 text-white rounded-lg font-semibold hover:opacity-90 transition-all inline-flex items-center gap-2 justify-center"
              >
                <Keyboard className="w-5 h-5" />
                Quick Challenge
              </Link>
              <Link
                to="/typing-practice/practice"
                className="px-6 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg font-semibold hover:bg-gray-200 dark:hover:bg-gray-600 transition-all inline-flex items-center gap-2 justify-center"
              >
                <Target className="w-5 h-5" />
                Word Lists
              </Link>
            </div>
          ) : (
            <button
              onClick={showPrompt}
              className="px-6 py-3 bg-purple-500 text-white rounded-lg font-semibold hover:bg-purple-600 transition-all flex items-center gap-2 mx-auto"
            >
              <UserPlus className="w-5 h-5" />
              Sign In
            </button>
          )}
          {onExit && (
            <button
              onClick={onExit}
              className="mt-4 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
            >
              ← Back to Typing Practice
            </button>
          )}
        </div>
      </div>
    );
  }

  // ==================== RENDER: IDLE ====================
  if (gameStatus === 'idle') {
    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6">
        <div className="grid md:grid-cols-3 gap-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="md:col-span-2 bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8"
          >
            <div className="text-center">
              <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-full flex items-center justify-center">
                <Ghost className="w-10 h-10 text-white" />
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold mb-2 text-gray-900 dark:text-white">
                Ghost Mode
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                Race against your personal best. Can you beat your ghost?
              </p>
            </div>

            {/* Ghost stats */}
            {ghostStats && (
              <div className="bg-purple-50 dark:bg-purple-900/20 rounded-xl p-4 mb-6">
                <div className="flex items-center gap-3 mb-3">
                  <Ghost className="w-6 h-6 text-purple-500" />
                  <span className="font-semibold text-gray-900 dark:text-white">
                    Your Ghost's Best
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                      {ghostStats.best_wpm}
                    </div>
                    <div className="text-xs text-gray-500">WPM</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                      {(ghostStats.best_accuracy ?? 0).toFixed(1)}%
                    </div>
                    <div className="text-xs text-gray-500">Accuracy</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                      {ghostStats.total_games_completed}
                    </div>
                    <div className="text-xs text-gray-500">Games</div>
                  </div>
                </div>
              </div>
            )}

            {/* Round preview */}
            <div className="space-y-3 mb-6">
              {ROUNDS.map((round, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className={`
                      w-8 h-8 rounded-full flex items-center justify-center text-white font-bold text-sm
                      ${idx === 0 ? 'bg-green-500' : idx === 1 ? 'bg-yellow-500' : 'bg-red-500'}
                    `}>
                      {round.roundNumber}
                    </div>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {round.name}
                    </span>
                  </div>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {round.timeLimit ? `${round.timeLimit}s limit` : 'No limit'}
                  </span>
                </div>
              ))}
            </div>

            <div className="text-center">
              <button
                onClick={startGame}
                className="px-8 py-3 bg-gradient-to-r from-purple-500 to-indigo-600 text-white rounded-lg font-semibold text-lg hover:from-purple-600 hover:to-indigo-700 transition-all flex items-center gap-2 mx-auto"
              >
                <Play className="w-5 h-5" />
                Challenge Ghost
              </button>
            </div>
          </motion.div>

          {/* Sidebar */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="space-y-4"
          >
            {streakInfo && (
              <StreakDisplay streak={streakInfo} />
            )}

            <div className="bg-gradient-to-br from-purple-50 to-indigo-50 dark:from-gray-800 dark:to-gray-900 rounded-xl p-4 border border-purple-200 dark:border-purple-800">
              <div className="flex items-center gap-2 mb-2">
                <Target className="w-5 h-5 text-purple-500" />
                <span className="font-semibold text-gray-900 dark:text-white">How it works</span>
              </div>
              <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                <li>• Your ghost types at your best WPM</li>
                <li>• Watch the progress bar to stay ahead</li>
                <li>• Beat your ghost to set a new record</li>
              </ul>
            </div>
          </motion.div>
        </div>
      </div>
    );
  }

  // ==================== RENDER: READY ====================
  if (gameStatus === 'ready') {
    return (
      <div className="max-w-3xl mx-auto p-2 sm:p-4 md:p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8 text-center"
        >
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', damping: 10 }}
            className={`
              inline-flex items-center gap-2 px-4 py-2 rounded-full mb-4 text-white font-bold text-lg
              bg-gradient-to-r
              ${currentRound === 0 ? 'from-green-500 to-emerald-600' :
                currentRound === 1 ? 'from-yellow-500 to-orange-600' :
                'from-red-500 to-rose-600'}
            `}
          >
            <Ghost className="w-5 h-5" />
            Round {currentRound + 1}: {currentRoundConfig.name}
          </motion.div>

          <p className="text-gray-600 dark:text-gray-400 mb-3 text-sm">
            {currentRoundConfig.description}
          </p>

          {ghostStats && (
            <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-3 mb-4 inline-flex items-center gap-2">
              <Ghost className="w-4 h-4 text-purple-500" />
              <span className="text-sm text-purple-700 dark:text-purple-300">
                Ghost target: <strong>{ghostStats.best_wpm} WPM</strong>
              </span>
            </div>
          )}

          <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-3 mb-5">
            <p className="font-mono text-base sm:text-lg text-gray-600 dark:text-gray-400 line-clamp-2">
              {roundText}
            </p>
          </div>

          {/* Auto-start countdown */}
          <div className="space-y-3">
            <GhostCountdown
              onComplete={startRound}
              seconds={3}
              roundColor={
                currentRound === 0 ? 'from-green-500 to-emerald-600' :
                currentRound === 1 ? 'from-yellow-500 to-orange-600' :
                'from-red-500 to-rose-600'
              }
            />
            <button
              onClick={startRound}
              className="px-6 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            >
              Start Now →
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  // ==================== RENDER: PLAYING ====================
  if (gameStatus === 'playing') {
    return (
      <div className="max-w-3xl mx-auto p-2 sm:p-4 md:p-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-3 sm:p-4 md:p-6">
          {/* Header */}
          <div className="flex justify-between items-center mb-3 sm:mb-4">
            <div className="flex items-center gap-2">
              {onExit && (
                <button
                  onClick={onExit}
                  className="p-1.5 sm:p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4 sm:w-5 sm:h-5" />
                </button>
              )}
              <div className="text-sm sm:text-base md:text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <Ghost className="w-4 h-4 text-purple-500" />
                Round {currentRound + 1}
              </div>
            </div>
            <div className="flex items-center gap-2 sm:gap-3">
              <div className="hidden xs:block">
                <SoundSettingsPanel
                  settings={sounds.settings}
                  onToggleSound={sounds.toggleSound}
                  onVolumeChange={sounds.setVolume}
                  compact
                />
              </div>
              {timeRemaining !== null && (
                <motion.div
                  className={`text-lg sm:text-xl md:text-2xl font-bold tabular-nums ${
                    timeRemaining <= 5 ? 'text-red-500' : 'text-purple-500'
                  }`}
                  animate={timeRemaining <= 5 ? { scale: [1, 1.1, 1] } : {}}
                  transition={{ duration: 0.5, repeat: timeRemaining <= 5 ? Infinity : 0 }}
                >
                  {timeRemaining}s
                </motion.div>
              )}
            </div>
          </div>

          {/* Ghost comparison */}
          {ghostStats && (
            <div className="mb-3">
              <div className="flex justify-between items-center mb-2">
                <GhostIndicator currentWpm={stats.wpm} ghostWpm={ghostStats.best_wpm} />
                <div className="text-sm text-gray-500">
                  Ghost: {ghostStats.best_wpm} WPM
                </div>
              </div>
              <GhostProgressBar currentProgress={currentProgress} ghostProgress={ghostProgress} />
            </div>
          )}

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-1.5 sm:gap-2 md:gap-4 mb-3 sm:mb-4">
            <div className="bg-blue-50 dark:bg-blue-900/30 rounded-lg p-1.5 sm:p-2 md:p-3 text-center">
              <div className="text-base sm:text-lg md:text-2xl font-bold text-blue-600 dark:text-blue-400 tabular-nums">
                {stats.wpm}
              </div>
              <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">WPM</div>
            </div>
            <div className="bg-green-50 dark:bg-green-900/30 rounded-lg p-1.5 sm:p-2 md:p-3 text-center">
              <div className="text-base sm:text-lg md:text-2xl font-bold text-green-600 dark:text-green-400 tabular-nums">
                {stats.accuracy}%
              </div>
              <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Acc</div>
            </div>
            <div className="bg-purple-50 dark:bg-purple-900/30 rounded-lg p-1.5 sm:p-2 md:p-3 text-center">
              <div className="text-base sm:text-lg md:text-2xl font-bold text-purple-600 dark:text-purple-400 tabular-nums">
                {currentWordIndex}/{wordStates.length}
              </div>
              <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Words</div>
            </div>
            <div className="bg-orange-50 dark:bg-orange-900/30 rounded-lg p-1.5 sm:p-2 md:p-3 text-center">
              <ComboCounter
                comboState={comboSystem.state}
                showMaxCombo={false}
                size="sm"
              />
              {!comboSystem.state.isActive && (
                <div className="text-[10px] sm:text-xs text-gray-600 dark:text-gray-400">Combo</div>
              )}
            </div>
          </div>

          {/* Word display */}
          <div className="relative">
            {!inputFocused && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="absolute inset-0 z-10 flex items-center justify-center bg-gray-900/40 dark:bg-gray-900/60 backdrop-blur-[2px] rounded-xl cursor-pointer"
                onClick={focusInput}
              >
                <div className="text-white text-lg font-medium bg-gray-900/80 px-6 py-3 rounded-lg">
                  Click here to continue typing
                </div>
              </motion.div>
            )}
            <WordDisplay
              words={wordStates}
              currentWordIndex={currentWordIndex}
              currentInput={currentInput}
              getCharacterStates={getCharacterStates}
              onContainerClick={focusInput}
              className="mb-2 sm:mb-3 md:mb-4"
            />

            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              enterKeyHint="next"
              value={currentInput}
              onKeyDown={handleKeyDown}
              onPaste={handlePaste}
              onChange={(e) => {
                if (keyDownHandledRef.current) {
                  keyDownHandledRef.current = false;
                  return;
                }
                const newValue = e.target.value;
                const oldValue = currentInput;
                if (newValue.length > oldValue.length) {
                  const addedChars = newValue.slice(oldValue.length);
                  for (const char of addedChars) {
                    handleKeyDown({
                      key: char,
                      preventDefault: () => {},
                    } as React.KeyboardEvent<HTMLInputElement>, true);
                  }
                } else if (newValue.length < oldValue.length) {
                  handleKeyDown({
                    key: 'Backspace',
                    preventDefault: () => {},
                  } as React.KeyboardEvent<HTMLInputElement>, true);
                }
              }}
              onFocus={() => setInputFocused(true)}
              onBlur={() => setInputFocused(false)}
              className="absolute top-0 left-0 w-full h-full opacity-0 cursor-default"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              aria-label="Type the words shown above"
            />
          </div>

          <p className="text-center text-xs text-gray-500 dark:text-gray-400 mt-1">
            <kbd className="px-1.5 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-[10px] sm:text-xs">Space</kbd>
            <span className="hidden sm:inline"> to move to next word</span>
          </p>
        </div>
      </div>
    );
  }

  // ==================== RENDER: ROUND COMPLETE ====================
  if (gameStatus === 'round_complete') {
    const lastResult = roundResults[roundResults.length - 1];
    const isLastRound = currentRound >= ROUNDS.length - 1;

    return (
      <div className="max-w-3xl mx-auto p-2 sm:p-4 md:p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden"
        >
          <div className={`bg-gradient-to-r ${
            lastResult?.beatGhost
              ? 'from-green-500 to-emerald-600'
              : 'from-purple-500 to-indigo-600'
          } p-4 text-white`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {lastResult?.beatGhost ? (
                  <Star className="w-6 h-6" />
                ) : (
                  <Ghost className="w-6 h-6" />
                )}
                <span className="font-bold text-lg">
                  {lastResult?.beatGhost ? 'You beat your ghost!' : 'Ghost wins this round'}
                </span>
              </div>
              <div className="flex items-center gap-4 text-white/90">
                <span className="font-bold">{lastResult?.wpm || 0} WPM</span>
                <span className="font-bold">{lastResult?.accuracy || 0}%</span>
              </div>
            </div>
          </div>

          {!isLastRound && (
            <div className="p-5 text-center">
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                Next: {ROUNDS[currentRound + 1]?.name}
              </h3>
              <button
                onClick={nextRound}
                className="px-6 py-2 bg-purple-500 hover:bg-purple-600 text-white rounded-lg font-medium transition-colors"
              >
                Continue →
              </button>
            </div>
          )}
        </motion.div>
      </div>
    );
  }

  // ==================== RENDER: FAILED ====================
  if (gameStatus === 'failed') {
    return (
      <div className="max-w-2xl mx-auto p-4 sm:p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8 text-center"
        >
          <Ghost className="w-16 h-16 text-purple-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
            Ghost Wins!
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            You didn't complete Round {currentRound + 1} in time.
          </p>
          <button
            onClick={startGame}
            className="px-6 py-3 bg-purple-500 text-white rounded-lg font-semibold hover:bg-purple-600 transition-all flex items-center gap-2 mx-auto"
          >
            <RotateCcw className="w-5 h-5" />
            Try Again
          </button>
        </motion.div>
      </div>
    );
  }

  // ==================== RENDER: GAME COMPLETE ====================
  if (gameStatus === 'game_complete') {
    const beatGhostOverall = ghostStats ? avgStats.wpm > ghostStats.best_wpm : false;
    const isPersonalBest = results?.is_personal_best_wpm || results?.is_personal_best_accuracy;
    const showCelebration = beatGhostOverall || isPersonalBest;

    return (
      <div className="max-w-3xl mx-auto p-4 sm:p-6 relative">
        {/* Confetti animation for beating ghost or personal best */}
        <AnimatePresence>
          {showCelebration && (
            <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden">
              {[...Array(50)].map((_, i) => (
                <motion.div
                  key={i}
                  initial={{
                    opacity: 1,
                    y: -20,
                    x: Math.random() * (typeof window !== 'undefined' ? window.innerWidth : 1000),
                    rotate: 0,
                  }}
                  animate={{
                    opacity: 0,
                    y: (typeof window !== 'undefined' ? window.innerHeight : 800) + 100,
                    rotate: Math.random() * 720 - 360,
                  }}
                  exit={{ opacity: 0 }}
                  transition={{
                    duration: 2 + Math.random() * 2,
                    delay: Math.random() * 0.5,
                    ease: 'easeOut',
                  }}
                  className={`absolute w-3 h-3 ${
                    ['bg-purple-400', 'bg-indigo-500', 'bg-violet-500', 'bg-pink-500', 'bg-yellow-400'][
                      Math.floor(Math.random() * 5)
                    ]
                  } ${Math.random() > 0.5 ? 'rounded-full' : 'rounded-sm'}`}
                />
              ))}
            </div>
          )}
        </AnimatePresence>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8 text-center"
        >
          {beatGhostOverall ? (
            <>
              <motion.div
                initial={{ scale: 0, rotate: -180 }}
                animate={{ scale: 1, rotate: 0 }}
                transition={{ type: 'spring', damping: 10 }}
                className="relative inline-block"
              >
                <div className="absolute inset-0 flex items-center justify-center">
                  <motion.div
                    animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.8, 0.5] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="w-24 h-24 bg-purple-400/30 rounded-full blur-xl"
                  />
                </div>
                <Star className="w-20 h-20 text-yellow-500 relative" fill="currentColor" />
                <Sparkles className="w-8 h-8 text-yellow-400 absolute -top-2 -right-2" />
              </motion.div>
              <h2 className="text-3xl font-bold mb-2 text-gray-900 dark:text-white mt-4">
                You Beat Your Ghost!
              </h2>
            </>
          ) : (
            <>
              <Ghost className="w-20 h-20 text-purple-500 mx-auto mb-4" />
              <h2 className="text-3xl font-bold mb-2 text-gray-900 dark:text-white">
                Challenge Complete
              </h2>
            </>
          )}

          {/* Performance Grade */}
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.15, type: 'spring', damping: 12 }}
            className="mb-2"
          >
            {(() => {
              const grade = avgStats.wpm >= 80 ? 'S' : avgStats.wpm >= 60 ? 'A' : avgStats.wpm >= 45 ? 'B' : avgStats.wpm >= 30 ? 'C' : 'D';
              const gradeColors: Record<string, string> = {
                S: 'from-yellow-400 via-amber-500 to-orange-500',
                A: 'from-green-400 to-emerald-500',
                B: 'from-blue-400 to-cyan-500',
                C: 'from-gray-400 to-gray-500',
                D: 'from-red-400 to-red-500',
              };
              const gradeLabels: Record<string, string> = {
                S: 'Ghost Slayer!',
                A: 'Spirit Hunter!',
                B: 'Ghost Chaser!',
                C: 'Keep Haunting!',
                D: 'Ghost Apprentice',
              };
              return (
                <>
                  <div className={`inline-block text-5xl font-black bg-gradient-to-br ${gradeColors[grade]} bg-clip-text text-transparent`}>
                    {grade}
                  </div>
                  <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
                    {gradeLabels[grade]}
                  </div>
                </>
              );
            })()}
          </motion.div>

          <p className="text-gray-600 dark:text-gray-400 mb-6">
            {beatGhostOverall
              ? `New personal best! You beat ${ghostStats?.best_wpm} WPM!`
              : `Your ghost (${ghostStats?.best_wpm} WPM) is still the champion.`}
          </p>

          {/* Personal best badges */}
          {isPersonalBest && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="flex flex-wrap justify-center gap-2 mb-4"
            >
              {results?.is_personal_best_wpm && (
                <span className="inline-flex items-center gap-1 bg-gradient-to-r from-purple-400 to-indigo-500 text-white px-3 py-1 rounded-full text-sm font-medium shadow-lg">
                  <Zap className="w-4 h-4" />
                  Best WPM
                </span>
              )}
              {results?.is_personal_best_accuracy && (
                <span className="inline-flex items-center gap-1 bg-gradient-to-r from-green-400 to-emerald-500 text-white px-3 py-1 rounded-full text-sm font-medium shadow-lg">
                  <Target className="w-4 h-4" />
                  Best Accuracy
                </span>
              )}
            </motion.div>
          )}

          {/* Summary stats */}
          <div className="grid grid-cols-4 gap-4 my-6">
            <div className="bg-blue-50 dark:bg-blue-900/30 rounded-lg p-4">
              <TrendingUp className="w-6 h-6 text-blue-500 mx-auto mb-2" />
              <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                {avgStats.wpm}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Avg WPM</div>
            </div>
            <div className="bg-green-50 dark:bg-green-900/30 rounded-lg p-4">
              <Target className="w-6 h-6 text-green-500 mx-auto mb-2" />
              <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                {avgStats.accuracy}%
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Accuracy</div>
            </div>
            <div className="bg-purple-50 dark:bg-purple-900/30 rounded-lg p-4">
              <Ghost className="w-6 h-6 text-purple-500 mx-auto mb-2" />
              <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
                {avgStats.roundsBeatGhost}/3
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Rounds Won</div>
            </div>
            <div className="bg-orange-50 dark:bg-orange-900/30 rounded-lg p-4">
              <Zap className="w-6 h-6 text-orange-500 mx-auto mb-2" />
              <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                {avgStats.maxCombo}x
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Max Combo</div>
            </div>
          </div>

          {/* XP earned with animated effect */}
          {results && isAuthenticated && (
            <motion.div
              initial={{ scale: 0, y: -30 }}
              animate={{ scale: 1, y: 0 }}
              transition={{ delay: 0.4, type: 'spring', damping: 8 }}
              className="bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-purple-900/30 dark:to-indigo-900/30 border border-purple-200 dark:border-purple-700 rounded-xl p-5 mb-6 relative overflow-hidden"
            >
              <motion.div
                animate={{ opacity: [0.3, 0.6, 0.3] }}
                transition={{ duration: 2, repeat: Infinity }}
                className="absolute inset-0 bg-gradient-to-r from-purple-400/10 via-indigo-400/20 to-purple-400/10"
              />
              <div className="relative">
                <motion.div
                  initial={{ scale: 0.5, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 0.6, type: 'spring' }}
                  className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-600 to-indigo-600 dark:from-purple-400 dark:to-indigo-400"
                >
                  +{results.xp_earned} XP
                </motion.div>
                <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Experience Earned
                </div>
              </div>
            </motion.div>
          )}

          {/* Guest XP teaser */}
          {!isAuthenticated && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
              className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4 mb-6"
            >
              <div className="text-xl font-bold text-purple-400/60 line-through mb-1">
                +{Math.round(avgStats.wpm * 2.5)} XP
              </div>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Sign up to earn XP and track your progress!
              </p>
              <button
                onClick={showPrompt}
                className="mt-2 text-sm font-medium text-purple-600 dark:text-purple-400 hover:underline"
              >
                Create free account →
              </button>
            </motion.div>
          )}

          {/* Round breakdown */}
          <div className="space-y-2 mb-6">
            {roundResults.map((result, idx) => (
              <div
                key={idx}
                className={`flex justify-between items-center p-3 rounded-lg ${
                  result.beatGhost
                    ? 'bg-green-50 dark:bg-green-900/20'
                    : 'bg-gray-50 dark:bg-gray-700/50'
                }`}
              >
                <span className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
                  Round {result.round}
                  {result.beatGhost && <Star className="w-4 h-4 text-yellow-500" />}
                </span>
                <span className="text-gray-600 dark:text-gray-400 text-sm">
                  {result.wpm} WPM | {result.accuracy}%
                </span>
              </div>
            ))}
          </div>

          <button
            onClick={startGame}
            className="px-8 py-3 bg-gradient-to-r from-purple-500 to-indigo-600 text-white rounded-lg font-semibold text-lg hover:from-purple-600 hover:to-indigo-700 transition-all flex items-center gap-2 mx-auto"
          >
            <RotateCcw className="w-5 h-5" />
            Race Again
          </button>
        </motion.div>

        <RegistrationPrompt
          isOpen={isPromptOpen}
          onClose={closePrompt}
          onSkip={handlePromptSkip}
          context="game"
        />
      </div>
    );
  }

  return (
    <RegistrationPrompt
      isOpen={isPromptOpen}
      onClose={closePrompt}
      onSkip={handlePromptSkip}
      context="game"
    />
  );
};

export default GhostModeGame;
