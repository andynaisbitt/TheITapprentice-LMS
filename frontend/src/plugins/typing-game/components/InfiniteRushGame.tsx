// frontend/src/plugins/typing-game/components/InfiniteRushGame.tsx
/**
 * Infinite Rush Mode - Continuous 60-second typing challenge
 *
 * Features:
 * - Fixed 60-second countdown
 * - Infinite word stream that regenerates as you type
 * - Score based on words completed and WPM
 * - Combo system for engagement
 * - Real-time stats tracking
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
  Sparkles,
  Star,
  ArrowLeft,
  Infinity as InfinityIcon,
} from 'lucide-react';

import { typingGameApi, type StreakInfo, type DailyChallenge } from '../services/typingGameApi';
import { useComboSystem } from '../hooks/useComboSystem';
import { useSoundEffects } from '../hooks/useSoundEffects';
import { useAntiCheat } from '../hooks/useAntiCheat';
import { useTypingEngine, type WordState } from '../hooks/useTypingEngine';
import { useGameWords } from '../hooks/useGameWords';
import { WordDisplay } from './WordDisplay';
import { ComboCounter } from './ComboCounter';
import { StreakDisplay } from './StreakDisplay';
import { DailyChallengeCard } from './DailyChallengeCard';
import { SoundSettingsPanel } from './SoundSettings';
import { useAuth } from '../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../hooks/useRegistrationPrompt';
import type {
  TypingGameStartResponse,
  TypingGameResultsResponse,
  TypingGameSubmitRequestV2,
} from '../types';

// ==================== CONFIGURATION ====================

const GAME_DURATION = 60; // 60 seconds
const WORDS_PER_BATCH = 12; // Words to display at once
const WORDS_TO_ADD = 6; // Words to add when running low

// IT-themed word pools for continuous generation
const WORD_POOLS = {
  easy: [
    'server', 'code', 'data', 'file', 'user', 'port', 'host', 'node',
    'link', 'path', 'root', 'admin', 'cache', 'query', 'token', 'hash',
    'stack', 'heap', 'queue', 'array', 'loop', 'func', 'class', 'type',
    'debug', 'build', 'test', 'push', 'pull', 'merge', 'branch', 'commit',
    'docker', 'nginx', 'redis', 'mongo', 'mysql', 'linux', 'python', 'react',
    'cloud', 'azure', 'proxy', 'route', 'state', 'props', 'hooks', 'async',
  ],
  medium: [
    'function', 'variable', 'database', 'endpoint', 'protocol', 'network',
    'frontend', 'backend', 'security', 'container', 'cluster', 'pipeline',
    'compiler', 'debugger', 'terminal', 'keyboard', 'interface', 'component',
    'developer', 'architect', 'engineer', 'incident', 'deployment', 'monitoring',
    'kubernetes', 'terraform', 'ansible', 'grafana', 'elastic', 'firebase',
    'typescript', 'javascript', 'microservice', 'middleware', 'authentication',
    'encryption', 'certificate', 'firewall', 'bandwidth', 'throughput',
  ],
  hard: [
    'infrastructure', 'configuration', 'implementation', 'optimization',
    'virtualization', 'orchestration', 'containerization', 'authentication',
    'authorization', 'serialization', 'deserialization', 'asynchronous',
    'synchronization', 'parallelization', 'multithreading', 'concurrency',
  ],
};

// ==================== INTERFACES ====================

interface InfiniteRushGameProps {
  onComplete?: (results: TypingGameResultsResponse) => void;
  onExit?: () => void;
}

type GameStatus = 'idle' | 'ready' | 'playing' | 'game_complete';

// ==================== HELPERS ====================

// Generate random IT-themed words as WordStates for useTypingEngine
const generateWordStates = (count: number, startIndex: number = 0): WordState[] => {
  const allPools = [...WORD_POOLS.easy, ...WORD_POOLS.medium];
  const wordStates: WordState[] = [];

  // Add some hard words occasionally (20% chance)
  for (let i = 0; i < count; i++) {
    let word: string;
    if (Math.random() < 0.2 && WORD_POOLS.hard.length > 0) {
      word = WORD_POOLS.hard[Math.floor(Math.random() * WORD_POOLS.hard.length)];
    } else {
      word = allPools[Math.floor(Math.random() * allPools.length)];
    }

    wordStates.push({
      word,
      index: startIndex + i,
      status: 'pending',
      typedValue: '',
      isCorrect: false,
      characterStates: word.split('').map(char => ({
        char,
        status: 'pending',
        typedChar: undefined,
      })),
    });
  }

  return wordStates;
};

// ==================== RUSH COUNTDOWN COMPONENT ====================

const RushCountdown: React.FC<{ onComplete: () => void; seconds: number }> = ({ onComplete, seconds }) => {
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
        className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-orange-500 to-red-600"
      >
        {count}
      </motion.div>
      {/* Progress ring */}
      <div className="relative w-16 h-1 mt-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <motion.div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-orange-500 to-red-600 rounded-full"
          initial={{ width: '100%' }}
          animate={{ width: '0%' }}
          transition={{ duration: seconds, ease: 'linear' }}
        />
      </div>
    </div>
  );
};

// ==================== COMPONENT ====================

export const InfiniteRushGame: React.FC<InfiniteRushGameProps> = ({
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

  // Game state
  const [gameStatus, setGameStatus] = useState<GameStatus>('idle');
  const [timeRemaining, setTimeRemaining] = useState(GAME_DURATION);
  const [sessionData, setSessionData] = useState<TypingGameStartResponse | null>(null);
  const [results, setResults] = useState<TypingGameResultsResponse | null>(null);
  const [inputFocused, setInputFocused] = useState(false);
  const wordIdCounter = useRef(0);

  // Initialize typing engine with dynamic word generation
  const initialText = useMemo(() => {
    const initialWords = generateWordStates(WORDS_PER_BATCH, 0);
    wordIdCounter.current = initialWords.length;
    return initialWords.map(w => w.word).join(' ');
  }, []);

  // Typing engine with infinite word support
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
    start: startEngine,
    inputProps,
    addWords,
  } = useTypingEngine(initialText, {
    onWordComplete: (wordIndex, isCorrect) => {
      if (isCorrect) {
        sounds.playMilestone();
        comboSystem.increment();
      } else {
        comboSystem.breakCombo();
      }
    },
    onError: () => {
      sounds.playError();
    },
    onLowWordCount: async (currentCount, minCount) => {
      // Generate more words when running low
      const newWords = generateWordStates(WORDS_TO_ADD, wordIdCounter.current);
      wordIdCounter.current += WORDS_TO_ADD;
      return newWords;
    },
    minWordCount: 5,
    wordRefreshThreshold: 3,
    inputMethod: 'keydown',
  });

  // Streak and daily challenges state
  const [streakInfo, setStreakInfo] = useState<StreakInfo | null>(null);
  const [dailyChallenges, setDailyChallenges] = useState<DailyChallenge[]>([]);
  const [claimingChallenge, setClaimingChallenge] = useState<string | null>(null);
  const [showConfetti, setShowConfetti] = useState(false);

  // Refs
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Combo system
  const comboSystem = useComboSystem({
    onComboMilestone: (milestone, tier) => {
      console.log(`[Combo] Milestone reached: ${milestone} (${tier})`);
    },
    onComboBreak: (finalCombo, maxCombo) => {
      console.log(`[Combo] Broken at ${finalCombo}, max was ${maxCombo}`);
    },
    onTierUp: (newTier, comboCount) => {
      console.log(`[Combo] Tier up to ${newTier} at ${comboCount}`);
      sounds.playCombo(comboCount);
    },
  });

  // Anti-cheat system
  const antiCheat = useAntiCheat({
    enabled: true,
    onSuspiciousActivity: (event) => {
      console.log('[Anti-Cheat] Suspicious activity:', event);
    },
  });

  // Focus input helper
  const focusInput = useCallback(() => {
    if (inputRef.current) {
      setTimeout(() => {
        inputRef.current?.focus();
        inputRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 100);
    }
  }, []);

  // Wrapper for key handling (adds game status check)
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (gameStatus !== 'playing') return;

    // Let anti-cheat track keystrokes
    antiCheat.recordKeystroke(Date.now());

    // Delegate to typing engine
    engineHandleKeyDown(e);
  }, [gameStatus, engineHandleKeyDown, antiCheat]);

  // Handle paste (block it)
  const handlePasteBlock = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault();
    antiCheat.recordPasteAttempt();
  }, [antiCheat]);

  // Start the game
  const startGame = useCallback(async () => {
    // Try to get session from backend
    try {
      const response = await typingGameApi.startGame({
        mode: 'challenge',
        word_count: WORDS_PER_BATCH,
      });
      setSessionData(response);
    } catch (error) {
      console.error('Failed to start game session:', error);
    }

    // Reset engine and game state
    resetEngine();
    setTimeRemaining(GAME_DURATION);
    comboSystem.reset();
    antiCheat.reset();

    setGameStatus('ready');
  }, [resetEngine, comboSystem, antiCheat]);

  // Begin playing
  const beginPlaying = useCallback(() => {
    antiCheat.startTracking();
    sounds.playGameStart();
    startEngine(); // This sets engine status to 'playing' and starts timer
    setGameStatus('playing');
    focusInput();
  }, [startEngine, sounds, focusInput, antiCheat]);

  // Refresh streak/challenges
  const refreshStreakAndChallenges = useCallback(async () => {
    if (!isAuthenticated) return;
    try {
      const data = await typingGameApi.getDailyChallenges();
      setStreakInfo(data.streak);
      setDailyChallenges(data.challenges);
    } catch (error) {
      console.error('Failed to refresh streak/challenges:', error);
    }
  }, [isAuthenticated]);

  // End the game
  const endGame = useCallback(async () => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    // Stop anti-cheat tracking
    antiCheat.stopTracking();

    sounds.playGameEnd();

    // Use stats from typing engine
    const finalWpm = stats.wpm;
    const finalAccuracy = stats.accuracy;

    // Submit to backend if we have a session
    if (sessionData) {
      try {
        const typedText = wordStates
          .filter(w => w.status === 'completed')
          .map(w => w.typedValue)
          .join(' ');

        // Gather anti-cheat data
        const antiCheatData = antiCheat.getAntiCheatData();

        const submitRequest: TypingGameSubmitRequestV2 = {
          session_id: sessionData.session_id,
          user_input: typedText,
          time_elapsed: GAME_DURATION,
          checksum: sessionData.checksum,
          max_combo: comboSystem.maxCombo,
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

        const finalResults = await typingGameApi.submitGameV2(submitRequest);

        if (finalResults.is_personal_best_wpm || finalResults.is_personal_best_accuracy) {
          sounds.playPersonalBest();
          setShowConfetti(true);
          setTimeout(() => setShowConfetti(false), 5000);
        }

        setResults(finalResults);
        onComplete?.(finalResults);
        refreshStreakAndChallenges();
      } catch (error) {
        console.error('Failed to submit results:', error);
      }
    }

    setGameStatus('game_complete');
  }, [stats, sessionData, wordStates, comboSystem.maxCombo, antiCheat, sounds, onComplete, refreshStreakAndChallenges]);

  // Timer effect
  useEffect(() => {
    if (gameStatus === 'playing') {
      timerRef.current = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev <= 1) {
            endGame();
            return 0;
          }
          return prev - 1;
        });
        // Stats are automatically updated by useTypingEngine
      }, 1000);

      return () => {
        if (timerRef.current) clearInterval(timerRef.current);
      };
    }
  }, [gameStatus, endGame]);

  // Auto-focus input when playing starts
  useEffect(() => {
    if (gameStatus === 'playing') {
      setInputFocused(true);
      focusInput();
    }
  }, [gameStatus, focusInput]);

  // Fetch streak and challenges on mount
  useEffect(() => {
    if (isAuthenticated) {
      refreshStreakAndChallenges();
    }
  }, [isAuthenticated, refreshStreakAndChallenges]);

  // Claim challenge reward handler
  const handleClaimChallenge = useCallback(async (challengeId: string) => {
    setClaimingChallenge(challengeId);
    try {
      const result = await typingGameApi.claimChallengeReward(challengeId);
      if (result.success) {
        setDailyChallenges(prev =>
          prev.map(c =>
            c.challenge_id === challengeId ? { ...c, is_claimed: true } : c
          )
        );
        sounds.playChallengeComplete();
      }
    } catch (error) {
      console.error('Failed to claim challenge:', error);
    } finally {
      setClaimingChallenge(null);
    }
  }, [sounds]);

  // ==================== RENDER: IDLE ====================
  if (gameStatus === 'idle') {
    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6">
        <div className="grid md:grid-cols-3 gap-6">
          {/* Main game card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="md:col-span-2 bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8"
          >
            <div className="text-center">
              <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-orange-500 to-red-600 rounded-full flex items-center justify-center">
                <InfinityIcon className="w-10 h-10 text-white" />
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold mb-2 text-gray-900 dark:text-white">
                Infinite Rush
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                60 seconds of pure typing adrenaline. How many words can you crush?
              </p>
            </div>

            {/* Mode info */}
            <div className="space-y-3 mb-6">
              <div className="flex items-center justify-between p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                <div className="flex items-center gap-3">
                  <Clock className="w-5 h-5 text-orange-500" />
                  <span className="font-medium text-gray-900 dark:text-white">Duration</span>
                </div>
                <span className="text-sm text-gray-600 dark:text-gray-400">60 seconds</span>
              </div>
              <div className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                <div className="flex items-center gap-3">
                  <Zap className="w-5 h-5 text-red-500" />
                  <span className="font-medium text-gray-900 dark:text-white">Mode</span>
                </div>
                <span className="text-sm text-gray-600 dark:text-gray-400">Continuous word stream</span>
              </div>
              <div className="flex items-center justify-between p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                <div className="flex items-center gap-3">
                  <Target className="w-5 h-5 text-purple-500" />
                  <span className="font-medium text-gray-900 dark:text-white">Goal</span>
                </div>
                <span className="text-sm text-gray-600 dark:text-gray-400">Max words + WPM</span>
              </div>
            </div>

            {/* Guest warning */}
            {!isAuthenticated && (
              <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mb-6 text-left">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-yellow-800 dark:text-yellow-200 text-sm">
                      Playing as guest. Scores won't be saved.
                    </p>
                    <button
                      onClick={showPrompt}
                      className="mt-2 text-sm font-medium text-yellow-700 dark:text-yellow-300 hover:underline flex items-center gap-1"
                    >
                      <UserPlus className="w-4 h-4" />
                      Sign up to track progress
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className="text-center">
              <button
                onClick={startGame}
                className="px-8 py-3 bg-gradient-to-r from-orange-500 to-red-600 text-white rounded-lg font-semibold text-lg hover:from-orange-600 hover:to-red-700 transition-all flex items-center gap-2 mx-auto"
              >
                <Play className="w-5 h-5" />
                Start Rush
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
            {isAuthenticated && streakInfo && (
              <StreakDisplay
                streak={streakInfo}
                onUseFreeze={async () => {
                  try {
                    await typingGameApi.useStreakFreeze();
                    refreshStreakAndChallenges();
                  } catch (error) {
                    console.error('Failed to use freeze:', error);
                  }
                }}
              />
            )}

            {isAuthenticated && dailyChallenges.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                  <Flame className="w-5 h-5 text-amber-500" />
                  Daily Challenges
                </h3>
                <div className="space-y-3">
                  {dailyChallenges.slice(0, 2).map(challenge => (
                    <DailyChallengeCard
                      key={challenge.challenge_id}
                      challenge={challenge}
                      onClaim={handleClaimChallenge}
                      claiming={claimingChallenge === challenge.challenge_id}
                    />
                  ))}
                </div>
              </div>
            )}

            {!isAuthenticated && (
              <div className="bg-gradient-to-br from-orange-50 to-red-50 dark:from-gray-800 dark:to-gray-900 rounded-xl p-4 border border-orange-200 dark:border-orange-800">
                <div className="flex items-center gap-2 mb-2">
                  <Flame className="w-5 h-5 text-orange-500" />
                  <span className="font-semibold text-gray-900 dark:text-white">Build your streak!</span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                  Sign up to track your daily streak and compete on leaderboards.
                </p>
                <button
                  onClick={showPrompt}
                  className="w-full py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  Get Started Free
                </button>
              </div>
            )}
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
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full mb-4 text-white font-bold text-lg bg-gradient-to-r from-orange-500 to-red-600"
          >
            <InfinityIcon className="w-5 h-5" />
            Infinite Rush
          </motion.div>

          <p className="text-gray-600 dark:text-gray-400 mb-3 text-sm">
            Type as many words as you can in 60 seconds!
            <span className="inline-flex items-center gap-1 ml-2 text-orange-500 font-medium">
              <Clock className="w-3.5 h-3.5" />
              60 seconds
            </span>
          </p>

          {/* Preview first few words */}
          <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-3 mb-5">
            <p className="font-mono text-base sm:text-lg text-gray-600 dark:text-gray-400">
              {wordStates.slice(0, 6).map(w => w.word).join(' ')}...
            </p>
          </div>

          {/* Auto-start countdown */}
          <div className="space-y-3">
            <RushCountdown onComplete={beginPlaying} seconds={3} />
            <button
              onClick={beginPlaying}
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
                  title="Exit game"
                >
                  <ArrowLeft className="w-4 h-4 sm:w-5 sm:h-5" />
                </button>
              )}
              <div className="text-sm sm:text-base md:text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <InfinityIcon className="w-4 h-4 text-orange-500" />
                Infinite Rush
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
              {/* Timer - prominent */}
              <motion.div
                className={`text-2xl sm:text-3xl md:text-4xl font-black tabular-nums ${
                  timeRemaining <= 10 ? 'text-red-500' : 'text-orange-500'
                }`}
                animate={timeRemaining <= 10 ? { scale: [1, 1.1, 1] } : {}}
                transition={{ duration: 0.5, repeat: timeRemaining <= 10 ? Infinity : 0 }}
              >
                {timeRemaining}s
              </motion.div>
            </div>
          </div>

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
                {wordStates.filter(w => w.status === 'completed').length}
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

          {/* Rocket Rush Progress Animation */}
          <div className="relative w-full h-12 mb-3 sm:mb-4 bg-gradient-to-r from-indigo-100 via-purple-50 to-pink-100 dark:from-indigo-900/20 dark:via-purple-900/20 dark:to-pink-900/20 rounded-lg overflow-hidden">
            {/* Stars background */}
            {[...Array(12)].map((_, i) => (
              <motion.div
                key={i}
                className="absolute w-1 h-1 bg-yellow-300 dark:bg-yellow-400 rounded-full"
                style={{
                  left: `${(i * 8 + 5)}%`,
                  top: `${20 + (i % 3) * 25}%`,
                }}
                animate={{ opacity: [0.3, 1, 0.3], scale: [0.8, 1.2, 0.8] }}
                transition={{ duration: 1 + (i % 3) * 0.5, repeat: Infinity, delay: i * 0.1 }}
              />
            ))}

            {/* Time progress bar */}
            <motion.div
              className="absolute bottom-0 left-0 h-1.5 bg-gradient-to-r from-orange-400 via-red-500 to-pink-500 rounded-full"
              style={{ width: `${(timeRemaining / GAME_DURATION) * 100}%` }}
              transition={{ duration: 0.1 }}
            />

            {/* Rocket */}
            <motion.div
              className="absolute bottom-2"
              style={{ left: `${Math.min(((GAME_DURATION - timeRemaining) / GAME_DURATION) * 95, 95)}%` }}
              animate={{
                y: [-2, 2, -2],
                rotate: stats.wpm > 60 ? [-5, 5, -5] : 0,
              }}
              transition={{ duration: 0.3, repeat: Infinity }}
            >
              <div className="relative">
                {/* Rocket body */}
                <div className="w-8 h-5 bg-gradient-to-r from-red-500 to-orange-500 rounded-l-full rounded-r-lg relative">
                  {/* Cockpit window */}
                  <div className="absolute top-1 right-1 w-2 h-2 bg-cyan-300 rounded-full" />
                  {/* Wing */}
                  <div className="absolute -bottom-1 left-1 w-3 h-2 bg-red-600 rounded-b-sm transform -rotate-12" />
                  <div className="absolute -top-1 left-1 w-3 h-2 bg-red-600 rounded-t-sm transform rotate-12" />
                </div>
                {/* Flame trail */}
                <motion.div
                  className="absolute -left-4 top-1/2 -translate-y-1/2 flex gap-0.5"
                  animate={{ scaleX: [0.8, 1.2, 0.8] }}
                  transition={{ duration: 0.15, repeat: Infinity }}
                >
                  <div className="w-3 h-2 bg-gradient-to-l from-orange-400 to-yellow-300 rounded-l-full" />
                  <div className="w-2 h-1.5 bg-gradient-to-l from-yellow-300 to-transparent rounded-l-full mt-0.5" />
                </motion.div>
                {/* Speed lines */}
                {stats.wpm > 40 && (
                  <div className="absolute -left-6 top-1/2 -translate-y-1/2 flex flex-col gap-0.5">
                    {[...Array(3)].map((_, i) => (
                      <motion.div
                        key={i}
                        className="h-0.5 bg-orange-300 rounded-full"
                        style={{ width: `${6 - i * 1.5}px`, marginLeft: `${i * 2}px` }}
                        animate={{ opacity: [0.3, 0.8, 0.3] }}
                        transition={{ duration: 0.2, delay: i * 0.05, repeat: Infinity }}
                      />
                    ))}
                  </div>
                )}
              </div>
            </motion.div>

            {/* Words milestone markers */}
            {[10, 20, 30, 40, 50].map((milestone) => (
              <div
                key={milestone}
                className={`absolute bottom-2 text-[10px] font-bold ${
                  wordStates.filter(w => w.status === 'completed').length >= milestone ? 'text-green-500' : 'text-gray-400'
                }`}
                style={{ left: `${(milestone / 60) * 90 + 5}%` }}
              >
                {wordStates.filter(w => w.status === 'completed').length >= milestone ? '✓' : milestone}
              </div>
            ))}

            {/* Finish zone */}
            <div className="absolute right-2 top-2 text-xs text-gray-400 font-mono">
              {Math.round((timeRemaining / GAME_DURATION) * 100)}%
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
              words={wordStates.slice(
                Math.max(0, currentWordIndex - 2),
                currentWordIndex + 10
              ).map((ws, idx) => ({
                ...ws,
                index: idx,
                status: ws.index === wordStates[currentWordIndex]?.index ? 'current' : ws.status,
              }))}
              currentWordIndex={Math.min(2, currentWordIndex)}
              currentInput={currentInput}
              getCharacterStates={(idx) => {
                const actualIdx = Math.max(0, currentWordIndex - 2) + idx;
                return getCharacterStates(actualIdx);
              }}
              onContainerClick={focusInput}
              className="mb-2 sm:mb-3 md:mb-4"
            />

            {/* Hidden input */}
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              enterKeyHint="next"
              value={currentInput}
              onKeyDown={handleKeyDown}
              onPaste={handlePasteBlock}
              onChange={() => {
                // Input is handled via onKeyDown; onChange is intentionally a no-op
              }}
              onFocus={() => setInputFocused(true)}
              onBlur={() => setInputFocused(false)}
              className="absolute top-0 left-0 w-full h-full opacity-0 cursor-default"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              data-gramm="false"
              aria-label="Type the words shown above"
            />
          </div>

          <p className="text-center text-xs text-gray-500 dark:text-gray-400 mt-1">
            <kbd className="px-1.5 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-[10px] sm:text-xs">Space</kbd>
            <span className="sm:hidden"> = next word</span>
            <span className="hidden sm:inline"> to move to next word</span>
          </p>
        </div>
      </div>
    );
  }

  // ==================== RENDER: GAME COMPLETE ====================
  if (gameStatus === 'game_complete') {
    const isPersonalBest = results?.is_personal_best_wpm || results?.is_personal_best_accuracy;

    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6 relative">
        {/* Confetti */}
        <AnimatePresence>
          {showConfetti && (
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
                    ['bg-yellow-400', 'bg-orange-500', 'bg-red-500', 'bg-pink-500'][
                      Math.floor(Math.random() * 4)
                    ]
                  } ${Math.random() > 0.5 ? 'rounded-full' : 'rounded-sm'}`}
                />
              ))}
            </div>
          )}
        </AnimatePresence>

        <div className="grid md:grid-cols-3 gap-6">
          {/* Main results card */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="md:col-span-2 bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8 text-center"
          >
            {isPersonalBest ? (
              <motion.div
                initial={{ scale: 0, rotate: -180 }}
                animate={{ scale: 1, rotate: 0 }}
                transition={{ type: 'spring', damping: 10 }}
                className="relative"
              >
                <div className="absolute inset-0 flex items-center justify-center">
                  <motion.div
                    animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.8, 0.5] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="w-24 h-24 bg-orange-400/30 rounded-full blur-xl"
                  />
                </div>
                <div className="relative">
                  <Star className="w-16 h-16 text-orange-500 mx-auto mb-2" fill="currentColor" />
                  <Sparkles className="w-8 h-8 text-yellow-400 absolute -top-2 -right-2" />
                </div>
              </motion.div>
            ) : (
              <Trophy className="w-16 h-16 text-orange-500 mx-auto mb-4" />
            )}

            {/* Performance Grade */}
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.15, type: 'spring', damping: 12 }}
              className="mb-2"
            >
              {(() => {
                const grade = stats.wpm >= 80 ? 'S' : stats.wpm >= 60 ? 'A' : stats.wpm >= 45 ? 'B' : stats.wpm >= 30 ? 'C' : 'D';
                const gradeColors: Record<string, string> = {
                  S: 'from-yellow-400 via-amber-500 to-orange-500',
                  A: 'from-green-400 to-emerald-500',
                  B: 'from-blue-400 to-cyan-500',
                  C: 'from-gray-400 to-gray-500',
                  D: 'from-red-400 to-red-500',
                };
                const gradeLabels: Record<string, string> = {
                  S: 'Unstoppable!',
                  A: 'Speed Demon!',
                  B: 'Solid Rush!',
                  C: 'Keep Pushing!',
                  D: 'Warming Up!',
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

            <h2 className="text-3xl font-bold mb-2 text-gray-900 dark:text-white">
              {isPersonalBest ? 'New Personal Best!' : 'Rush Complete!'}
            </h2>

            {/* Personal best badges */}
            {isPersonalBest && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="flex flex-wrap justify-center gap-2 mb-4"
              >
                {results?.is_personal_best_wpm && (
                  <span className="inline-flex items-center gap-1 bg-gradient-to-r from-orange-400 to-red-500 text-white px-3 py-1 rounded-full text-sm font-medium shadow-lg">
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
                  {stats.wpm}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">WPM</div>
              </div>
              <div className="bg-green-50 dark:bg-green-900/30 rounded-lg p-4">
                <Target className="w-6 h-6 text-green-500 mx-auto mb-2" />
                <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                  {stats.accuracy}%
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Accuracy</div>
              </div>
              <div className="bg-purple-50 dark:bg-purple-900/30 rounded-lg p-4">
                <Keyboard className="w-6 h-6 text-purple-500 mx-auto mb-2" />
                <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
                  {wordStates.filter(w => w.status === 'completed').length}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Words</div>
              </div>
              <div className="bg-orange-50 dark:bg-orange-900/30 rounded-lg p-4">
                <Zap className="w-6 h-6 text-orange-500 mx-auto mb-2" />
                <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                  {comboSystem.maxCombo}x
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Max Combo</div>
              </div>
            </div>

            {/* XP earned */}
            {results && isAuthenticated && (
              <motion.div
                initial={{ scale: 0, y: -30 }}
                animate={{ scale: 1, y: 0 }}
                transition={{ delay: 0.4, type: 'spring', damping: 8 }}
                className="bg-gradient-to-r from-orange-50 to-red-50 dark:from-orange-900/30 dark:to-red-900/30 border border-orange-200 dark:border-orange-700 rounded-xl p-5 mb-6 relative overflow-hidden"
              >
                <motion.div
                  animate={{ opacity: [0.3, 0.6, 0.3] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  className="absolute inset-0 bg-gradient-to-r from-orange-400/10 via-red-400/20 to-orange-400/10"
                />
                <div className="relative">
                  <motion.div
                    initial={{ scale: 0.5, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ delay: 0.6, type: 'spring' }}
                    className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-orange-600 to-red-600 dark:from-orange-400 dark:to-red-400"
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
                className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-4 mb-6"
              >
                <div className="text-xl font-bold text-orange-400/60 line-through mb-1">
                  +{Math.round(stats.wpm * 2.5)} XP
                </div>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Sign up to earn XP and track your progress!
                </p>
              </motion.div>
            )}

            <button
              onClick={startGame}
              className="px-8 py-3 bg-gradient-to-r from-orange-500 to-red-600 text-white rounded-lg font-semibold text-lg hover:from-orange-600 hover:to-red-700 transition-all flex items-center gap-2 mx-auto"
            >
              <RotateCcw className="w-5 h-5" />
              Play Again
            </button>
          </motion.div>

          {/* Sidebar */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="space-y-4"
          >
            {isAuthenticated && streakInfo && (
              <StreakDisplay streak={streakInfo} />
            )}

            {!isAuthenticated && (
              <div className="bg-gradient-to-br from-orange-50 to-red-50 dark:from-gray-800 dark:to-gray-900 rounded-xl p-4 border border-orange-200 dark:border-orange-800">
                <div className="flex items-center gap-2 mb-2">
                  <Flame className="w-5 h-5 text-orange-500" />
                  <span className="font-semibold text-gray-900 dark:text-white">Track your progress!</span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                  Sign up to build streaks, complete challenges, and climb the leaderboard.
                </p>
                <button
                  onClick={showPrompt}
                  className="w-full py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  Create Free Account
                </button>
              </div>
            )}
          </motion.div>
        </div>

        {/* Registration Modal */}
        <RegistrationPrompt
          isOpen={isPromptOpen}
          onClose={closePrompt}
          onSkip={handlePromptSkip}
          context="game"
        />
      </div>
    );
  }

  // Fallback
  return (
    <RegistrationPrompt
      isOpen={isPromptOpen}
      onClose={closePrompt}
      onSkip={handlePromptSkip}
      context="game"
    />
  );
};

export default InfiniteRushGame;
