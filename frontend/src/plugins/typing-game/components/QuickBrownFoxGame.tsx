// frontend/src/plugins/typing-game/components/QuickBrownFoxGame.tsx
/**
 * Quick Brown Fox Typing Game - 2026 Edition
 *
 * Features:
 * - Word-by-word typing (no going back to previous words)
 * - Anti-cheat data collection
 * - Combo system for engagement
 * - Real-time WPM and accuracy tracking
 * - 3-round progressive challenge
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
  CheckCircle2,
  XCircle,
  UserPlus,
  Target,
  TrendingUp,
  Flame,
  Gift,
  Sparkles,
  Star,
  X,
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
import { DailyChallengeCard } from './DailyChallengeCard';
import { SoundSettingsPanel } from './SoundSettings';
import { FoxRunnerAnimation } from './FoxRunnerAnimation';
import { useAuth } from '../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../hooks/useRegistrationPrompt';
import type {
  TypingGameStartResponse,
  TypingGameResultsResponse,
  TypingGameSubmitRequestV2,
  RoundConfig,
} from '../types';

// ==================== CONFIGURATION ====================

// Round configurations - variety in each round
const ROUNDS: RoundConfig[] = [
  {
    roundNumber: 1,
    name: 'Warmup',
    timeLimit: null,
    description: 'Get familiar with the words. Take your time!',
  },
  {
    roundNumber: 2,
    name: 'Speed Challenge',
    timeLimit: 25,
    description: 'Complete within 25 seconds!',
  },
  {
    roundNumber: 3,
    name: 'INSANE MODE',
    timeLimit: 12,
    description: '12 seconds - Type fast or fail!',
  },
];

// Dynamic text pools - Classic pangrams and fun typing phrases
const ROUND_TEXTS: Record<number, string[]> = {
  // Round 1: Warmup - Classic pangrams (no time limit)
  1: [
    'The quick brown fox jumps over the lazy dog',
    'Pack my box with five dozen liquor jugs',
    'How vexingly quick daft zebras jump',
    'The five boxing wizards jump quickly',
    'Jackdaws love my big sphinx of quartz',
    'Sphinx of black quartz judge my vow',
    'Two driven jocks help fax my big quiz',
    'The jay pig fox zebra and my wolves quack',
    'Sympathizing would fix Quaker objectives',
    'A wizard job is to vex chumps quickly in fog',
    'Watch Jeopardy and Alex Trebek is famous for his quizzing voice',
    'Crazy Frederick bought many very exquisite opal jewels',
    'We promptly judged antique ivory buckles for the next prize',
    'A mad boxer shot a quick gloved jab to the jaw of his dizzy opponent',
    'Jaded zombies acted quaintly but kept driving their oxen forward',
    'The quick onyx goblin jumps over the lazy dwarf',
    'Few quips galvanized the mock jury box',
    'Quick zephyrs blow vexing daft Jim',
    'Waltz bad nymph for quick jigs vex',
    'Glib jocks quiz nymph to vex dwarf',
  ],
  // Round 2: Speed Challenge - Medium pangrams & fun phrases (25s limit)
  2: [
    'The quick brown fox jumped swiftly over the sleeping lazy dog',
    'A quick movement of the enemy will jeopardize six gunboats',
    'All questions asked by five watch experts amazed the judge',
    'Jack quietly moved up front and seized the big ball of wax',
    'Just keep examining every low bid quoted for zinc etchings',
    'My girl wove six dozen plaid jackets before she quit',
    'Sixty zippers were quickly picked from the woven jute bag',
    'Amazingly few discotheques provide jukeboxes',
    'Heavy boxes perform quick waltzes and jigs',
    'Jinxed wizards pluck ivy from the big quilt',
    'The fox was quick and brown as it leaped over the lazy dog',
    'Big July earthquakes confound zany experimental vow',
    'Foxy parsons quiz and cajole the lovably dim wiki user',
    'Have a pick of jab combo and execute wild zig zag left moves',
    'Cozy lummox gives smart squid who asks for job pen',
    'A large fawn jumped quickly over white zinc boxes',
    'Viewing quizzical abstracts mixed up hefty jocks',
    'Brawny gods just flocked up to quiz and vex him',
    'Adjusting quiver and bow Zephyr killed the fox',
    'My faxed joke won a pager in the cable TV quiz show',
  ],
  // Round 3: INSANE MODE - Short punchy pangrams (12s limit)
  3: [
    'Quick wafting zephyrs vex bold Jim',
    'Sphinx of black quartz judge my vow',
    'How quickly daft jumping zebras vex',
    'The five boxing wizards jump quickly',
    'Jackdaws love my big sphinx of quartz',
    'Pack my box with five dozen jugs',
    'Waltz bad nymph for quick jigs vex',
    'Glib jocks quiz nymph to vex dwarf',
    'Quick fox jumps nightly above wizard',
    'The jay pig fox zebra and wolves quack',
    'Vexed nymphs go for quick waltz job',
    'Blowzy night frumps vex had quick',
    'Glum Schwartzkopf vexd by NJ IQ',
    'Vext cwm fly zing jabs Kurd qoph',
    'Jump dogs quiz for why blank vetch',
    'Fox nymphs grab quick lived waltz',
    'Brick quiz whangs jumpy veldt fox',
    'Bright vixens jump dozy fowl quack',
    'Quick wafting zephyrs vex bold Jim',
    'Lazy movers quit hard packing of jewelry boxes',
  ],
};

// ==================== INTERFACES ====================

interface QuickBrownFoxGameProps {
  onComplete?: (results: TypingGameResultsResponse) => void;
  onExit?: () => void;
  wordListId?: string;
}

interface RoundResult {
  round: number;
  wpm: number;
  accuracy: number;
  time: number;
  passed: boolean;
  maxCombo: number;
}

type GameStatus = 'idle' | 'ready' | 'playing' | 'round_complete' | 'game_complete' | 'failed';

// ==================== ROUND COUNTDOWN COMPONENT ====================

const RoundCountdown: React.FC<{ onComplete: () => void; seconds: number }> = ({ onComplete, seconds }) => {
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
        className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-600"
      >
        {count}
      </motion.div>
      {/* Progress ring */}
      <div className="relative w-16 h-1 mt-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <motion.div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full"
          initial={{ width: '100%' }}
          animate={{ width: '0%' }}
          transition={{ duration: seconds, ease: 'linear' }}
        />
      </div>
    </div>
  );
};

// ==================== COMPONENT ====================

export const QuickBrownFoxGame: React.FC<QuickBrownFoxGameProps> = ({
  onComplete,
  onExit,
  wordListId,
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
  const [currentRound, setCurrentRound] = useState(0);
  const [roundText, setRoundText] = useState('');
  const [sessionData, setSessionData] = useState<TypingGameStartResponse | null>(null);
  const [results, setResults] = useState<TypingGameResultsResponse | null>(null);
  const [roundResults, setRoundResults] = useState<RoundResult[]>([]);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const [checksum, setChecksum] = useState('');

  // Track actual typed text for submission
  const [actualTypedText, setActualTypedText] = useState('');

  // Streak and daily challenges state
  const [streakInfo, setStreakInfo] = useState<StreakInfo | null>(null);
  const [dailyChallenges, setDailyChallenges] = useState<DailyChallenge[]>([]);
  const [claimingChallenge, setClaimingChallenge] = useState<string | null>(null);
  const [showConfetti, setShowConfetti] = useState(false);
  const [inputFocused, setInputFocused] = useState(false);

  // Refs
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const roundStartTime = useRef<number | null>(null);
  const keyDownHandledRef = useRef(false);

  // Current round config
  const currentRoundConfig = ROUNDS[currentRound];

  // Get random text for current round
  const getRandomText = useCallback((roundNum: number): string => {
    const texts = ROUND_TEXTS[roundNum as keyof typeof ROUND_TEXTS] || ROUND_TEXTS[1];
    return texts[Math.floor(Math.random() * texts.length)];
  }, []);

  // Track combo tier for sound effects
  const lastTierRef = useRef<string>('none');

  // Initialize typing engine with current round's text
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
    inputProps,
  } = useTypingEngine(roundText, {
    onWordComplete: (wordIndex, isCorrect, wordWpm) => {
      // Collect actual typed text from completed word
      const completedWord = wordStates[wordIndex];
      if (completedWord) {
        setActualTypedText(prev => {
          const newText = prev + (prev ? ' ' : '') + completedWord.typedValue;
          return newText;
        });
      }

      // Sound feedback
      if (isCorrect) {
        sounds.playMilestone();
      }
    },
    onGameComplete: (finalStats) => {
      sounds.playGameEnd();
      completeRound(true);
    },
    onError: (wordIndex, charIndex, expected, actual) => {
      // Play error sound and break combo
      sounds.playError();
      comboSystem.breakCombo();
      antiCheat.recordKeystroke();
    },
    onKeystroke: (keystrokeData) => {
      // Track keystroke for anti-cheat
      antiCheat.recordKeystroke(keystrokeData.timestamp);

      // Increment combo on correct characters (not just words!)
      if (keystrokeData.isCorrect) {
        comboSystem.increment();
        // Optional keystroke sound
        sounds.playKeystroke();
      }

      // Check for combo tier-up
      const newTier = comboSystem.tier;
      if (newTier !== lastTierRef.current && newTier !== 'none') {
        sounds.playCombo(comboSystem.combo);
        lastTierRef.current = newTier;
      }
    },
  });

  // Anti-cheat system
  const antiCheat = useAntiCheat({
    enabled: true,
    onSuspiciousActivity: (event) => {
      console.log('[Anti-Cheat] Suspicious activity:', event);
    },
  });

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
    },
  });

  // Focus input helper - more robust with multiple attempts
  const focusInput = useCallback(() => {
    const attemptFocus = (attempts: number) => {
      if (attempts <= 0) return;

      if (inputRef.current) {
        inputRef.current.focus();
        // Verify focus was successful
        if (document.activeElement === inputRef.current) {
          inputRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
          return;
        }
      }
      // Retry if focus failed
      setTimeout(() => attemptFocus(attempts - 1), 100);
    };

    // Start focusing after a brief delay to allow render
    setTimeout(() => attemptFocus(5), 50);
  }, []);

  // Start the entire game
  const startGame = useCallback(async () => {
    let backendText = '';
    try {
      const response = await typingGameApi.startGame({
        ...(wordListId ? { word_list_id: wordListId } : {}),
        mode: 'challenge',
        word_count: 9,
      });

      setSessionData(response);
      setChecksum(response.checksum);
      // Use backend text if available and reasonable
      if (response.text && response.text.trim().length > 10) {
        backendText = response.text;
      }
    } catch (error) {
      console.error('Failed to start game session:', error);
    }

    // Initialize first round - prefer backend text, fallback to local pool
    setCurrentRound(0);
    setRoundResults([]);
    const text = backendText || getRandomText(1);
    setRoundText(text);
    setGameStatus('ready');
  }, [wordListId, getRandomText]);

  // Start current round
  const startRound = useCallback(() => {
    // Reset systems
    resetEngine();
    comboSystem.reset();
    antiCheat.reset();
    antiCheat.startTracking();
    lastTierRef.current = 'none';

    // Reset typed text tracking
    setActualTypedText('');

    // Set timing
    roundStartTime.current = Date.now();
    const roundConfig = ROUNDS[currentRound];
    if (roundConfig.timeLimit) {
      setTimeRemaining(roundConfig.timeLimit);
    } else {
      setTimeRemaining(null);
    }

    // Play start sound
    sounds.playGameStart();

    setGameStatus('playing');
    focusInput();
  }, [currentRound, resetEngine, comboSystem, antiCheat, focusInput, sounds]);

  // Complete a round
  const completeRound = useCallback((passed: boolean) => {
    // Stop timer
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    // Stop anti-cheat tracking
    antiCheat.stopTracking();

    // Calculate final time
    const finalTime = roundStartTime.current
      ? (Date.now() - roundStartTime.current) / 1000
      : 0;

    // Record round result
    const roundResult: RoundResult = {
      round: currentRound + 1,
      wpm: stats.wpm,
      accuracy: stats.accuracy,
      time: Math.round(finalTime * 10) / 10,
      passed,
      maxCombo: Math.max(maxCombo, comboSystem.maxCombo),
    };

    setRoundResults(prev => [...prev, roundResult]);

    if (!passed) {
      setGameStatus('failed');
    } else if (currentRound >= ROUNDS.length - 1) {
      // All rounds complete
      submitFinalResults();
    } else {
      setGameStatus('round_complete');
    }
  }, [currentRound, stats, maxCombo, comboSystem.maxCombo, antiCheat]);

  // Get final typed text from all word states
  const getFinalTypedText = useCallback((): string => {
    // Combine all completed words' typed values
    const completedTypedText = wordStates
      .filter(ws => ws.status === 'completed' || ws.status === 'skipped')
      .map(ws => ws.typedValue)
      .join(' ');

    // Include current input if we're mid-word
    if (currentInput && currentWordIndex < wordStates.length) {
      return completedTypedText + (completedTypedText ? ' ' : '') + currentInput;
    }

    return completedTypedText || actualTypedText;
  }, [wordStates, currentInput, currentWordIndex, actualTypedText]);

  // Refresh streak/challenges after game completion (defined before submitFinalResults to avoid circular dependency)
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

  // Submit final results to API
  const submitFinalResults = useCallback(async () => {
    if (!sessionData) {
      setGameStatus('game_complete');
      return;
    }

    // Get actual typed text
    const userTypedText = getFinalTypedText();

    // Gather anti-cheat data
    const antiCheatData = antiCheat.getAntiCheatData();

    // Build V2 request with anti-cheat data
    const submitRequest: TypingGameSubmitRequestV2 = {
      session_id: sessionData.session_id,
      user_input: userTypedText, // FIXED: Now sends actual typed text!
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
      // Use V2 endpoint with anti-cheat validation
      const finalResults = await typingGameApi.submitGameV2(submitRequest);

      // Play appropriate sounds and show confetti for personal best
      if (finalResults.is_personal_best_wpm || finalResults.is_personal_best_accuracy) {
        sounds.playPersonalBest();
        setShowConfetti(true);
        // Auto-hide confetti after 5 seconds
        setTimeout(() => setShowConfetti(false), 5000);
      }

      if (finalResults.challenges_completed && finalResults.challenges_completed.length > 0) {
        sounds.playChallengeComplete();
      }

      setResults(finalResults);
      setGameStatus('game_complete');
      onComplete?.(finalResults);

      // Refresh streak and challenges data after game completion
      refreshStreakAndChallenges();
    } catch (error) {
      console.error('Failed to submit results:', error);
      setGameStatus('game_complete');
    }
  }, [sessionData, getFinalTypedText, stats.timeElapsed, checksum, maxCombo, comboSystem.maxCombo, antiCheat, onComplete, sounds, refreshStreakAndChallenges]);

  // Move to next round
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

  // Auto-focus input when entering playing state
  useEffect(() => {
    if (gameStatus === 'playing') {
      // Set inputFocused immediately to prevent blur overlay flash
      setInputFocused(true);
      focusInput();
    }
  }, [gameStatus, focusInput]);

  // Fetch streak and challenges on mount (authenticated users only)
  useEffect(() => {
    if (isAuthenticated) {
      const fetchStreakAndChallenges = async () => {
        try {
          const data = await typingGameApi.getDailyChallenges();
          setStreakInfo(data.streak);
          setDailyChallenges(data.challenges);
        } catch (error) {
          console.error('Failed to fetch streak/challenges:', error);
        }
      };
      fetchStreakAndChallenges();
    }
  }, [isAuthenticated]);

  // Claim challenge reward handler
  const handleClaimChallenge = useCallback(async (challengeId: string) => {
    setClaimingChallenge(challengeId);
    try {
      const result = await typingGameApi.claimChallengeReward(challengeId);
      if (result.success) {
        // Update local challenge state
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

  // Enhanced key handler with anti-cheat
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>, fromOnChange = false) => {
    // Block paste shortcuts
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v') {
      e.preventDefault();
      antiCheat.recordPasteAttempt();
      return;
    }

    // Mark that onKeyDown handled this event (desktop browsers)
    // so onChange won't double-process it
    if (!fromOnChange) {
      keyDownHandledRef.current = true;
    }

    // Pass to typing engine
    engineHandleKeyDown(e);
  }, [engineHandleKeyDown, antiCheat]);

  // Calculate averages for results
  const avgStats = useMemo(() => {
    if (roundResults.length === 0) return { wpm: 0, accuracy: 0, maxCombo: 0 };
    return {
      wpm: Math.round(roundResults.reduce((sum, r) => sum + r.wpm, 0) / roundResults.length),
      accuracy: Math.round(roundResults.reduce((sum, r) => sum + r.accuracy, 0) / roundResults.length),
      maxCombo: Math.max(...roundResults.map(r => r.maxCombo)),
    };
  }, [roundResults]);

  // ==================== RENDER: IDLE ====================
  if (gameStatus === 'idle') {
    // Filter claimable challenges (completed but not claimed)
    const claimableChallenges = dailyChallenges.filter(c => c.is_completed && !c.is_claimed);
    const activeChallenges = dailyChallenges.filter(c => !c.is_completed);

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
              <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                <Keyboard className="w-10 h-10 text-white" />
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold mb-2 text-gray-900 dark:text-white">
                Quick Brown Fox Challenge
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                Word-by-word typing with combo system. No going back!
              </p>
            </div>

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
                className="px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold text-lg hover:from-blue-600 hover:to-purple-700 transition-all flex items-center gap-2 mx-auto"
              >
                <Play className="w-5 h-5" />
                Start Challenge
              </button>
            </div>
          </motion.div>

          {/* Sidebar: Streak & Challenges */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="space-y-4"
          >
            {/* Streak display (authenticated users) */}
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

            {/* Daily challenges */}
            {isAuthenticated && dailyChallenges.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                  <Gift className="w-5 h-5 text-amber-500" />
                  Daily Challenges
                </h3>
                <div className="space-y-3">
                  {/* Show claimable challenges first */}
                  {claimableChallenges.map(challenge => (
                    <DailyChallengeCard
                      key={challenge.challenge_id}
                      challenge={challenge}
                      onClaim={handleClaimChallenge}
                      claiming={claimingChallenge === challenge.challenge_id}
                    />
                  ))}
                  {/* Then show active (incomplete) challenges */}
                  {activeChallenges.slice(0, 2).map(challenge => (
                    <DailyChallengeCard
                      key={challenge.challenge_id}
                      challenge={challenge}
                      onClaim={handleClaimChallenge}
                      claiming={claimingChallenge === challenge.challenge_id}
                    />
                  ))}
                </div>
                {activeChallenges.length > 2 && (
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-2 text-center">
                    +{activeChallenges.length - 2} more challenges
                  </p>
                )}
              </div>
            )}

            {/* Sign up prompt for guests */}
            {!isAuthenticated && (
              <div className="bg-gradient-to-br from-purple-50 to-blue-50 dark:from-gray-800 dark:to-gray-900 rounded-xl p-4 border border-purple-200 dark:border-purple-800">
                <div className="flex items-center gap-2 mb-2">
                  <Flame className="w-5 h-5 text-orange-500" />
                  <span className="font-semibold text-gray-900 dark:text-white">Build your streak!</span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                  Sign up to track your daily streak, complete challenges, and earn XP rewards.
                </p>
                <button
                  onClick={showPrompt}
                  className="w-full py-2 bg-purple-500 hover:bg-purple-600 text-white text-sm font-medium rounded-lg transition-colors"
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
          transition={{ duration: 0.3 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 sm:p-8 text-center"
        >
          {/* Round badge */}
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
            <Zap className="w-5 h-5" />
            Round {currentRound + 1}: {currentRoundConfig.name}
          </motion.div>

          <p className="text-gray-600 dark:text-gray-400 mb-3 text-sm">
            {currentRoundConfig.description}
            {currentRoundConfig.timeLimit && (
              <span className="inline-flex items-center gap-1 ml-2 text-orange-500 font-medium">
                <Clock className="w-3.5 h-3.5" />
                {currentRoundConfig.timeLimit}s limit
              </span>
            )}
          </p>

          {/* Text preview - compact */}
          <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-3 mb-5">
            <p className="font-mono text-base sm:text-lg text-gray-600 dark:text-gray-400 line-clamp-2">
              {roundText}
            </p>
          </div>

          {/* Auto-start countdown for rounds 2+ */}
          {currentRound > 0 ? (
            <div className="space-y-3">
              <RoundCountdown onComplete={startRound} seconds={3} />
              <button
                onClick={startRound}
                className="px-6 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
              >
                Start Now →
              </button>
            </div>
          ) : (
            <button
              onClick={startRound}
              className="px-8 py-3 bg-green-500 text-white rounded-lg font-semibold text-lg hover:bg-green-600 transition-all flex items-center gap-2 mx-auto"
            >
              <Zap className="w-5 h-5" />
              GO!
            </button>
          )}
        </motion.div>
      </div>
    );
  }

  // ==================== RENDER: PLAYING ====================
  if (gameStatus === 'playing') {
    return (
      <div className="max-w-3xl mx-auto p-2 sm:p-4 md:p-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-3 sm:p-4 md:p-6">
          {/* Header with round info, timer, and controls */}
          <div className="flex justify-between items-center mb-3 sm:mb-4">
            <div className="flex items-center gap-2">
              {/* Exit button */}
              {onExit && (
                <button
                  onClick={onExit}
                  className="p-1.5 sm:p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                  title="Exit game"
                >
                  <ArrowLeft className="w-4 h-4 sm:w-5 sm:h-5" />
                </button>
              )}
              <div className="text-sm sm:text-base md:text-lg font-bold text-gray-900 dark:text-white">
                Round {currentRound + 1}: <span className="hidden sm:inline">{currentRoundConfig.name}</span>
              </div>
            </div>
            <div className="flex items-center gap-2 sm:gap-3">
              {/* Sound toggle - hidden on very small screens */}
              <div className="hidden xs:block">
                <SoundSettingsPanel
                  settings={sounds.settings}
                  onToggleSound={sounds.toggleSound}
                  onVolumeChange={sounds.setVolume}
                  compact
                />
              </div>
              {/* Timer */}
              {timeRemaining !== null && (
                <motion.div
                  className={`text-lg sm:text-xl md:text-2xl font-bold tabular-nums ${
                    timeRemaining <= 5 ? 'text-red-500' : 'text-blue-500'
                  }`}
                  animate={timeRemaining <= 5 ? { scale: [1, 1.1, 1] } : {}}
                  transition={{ duration: 0.5, repeat: timeRemaining <= 5 ? Infinity : 0 }}
                >
                  {timeRemaining}s
                </motion.div>
              )}
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

          {/* Fox Runner Animation */}
          <FoxRunnerAnimation
            progress={wordStates.length > 0 ? (currentWordIndex / wordStates.length) * 100 : 0}
            isPlaying={gameStatus === 'playing'}
            className="mb-3 sm:mb-4 bg-gradient-to-b from-sky-100 to-green-50 dark:from-sky-900/20 dark:to-green-900/20 rounded-lg"
          />

          {/* Word display - MonkeyType-style inline typing */}
          <div className="relative">
            {/* Blur overlay when input loses focus */}
            {!inputFocused && gameStatus === 'playing' && (
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

            {/* Hidden input for keystroke capture - invisible but functional */}
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              enterKeyHint="next"
              value={currentInput}
              onKeyDown={handleKeyDown}
              onPaste={handlePaste}
              onChange={(e) => {
                // On desktop, onKeyDown already processed the input - skip to avoid duplicates
                if (keyDownHandledRef.current) {
                  keyDownHandledRef.current = false;
                  return;
                }

                // Handle mobile input where onKeyDown might not fire
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
              data-gramm="false"
              data-gramm_editor="false"
              data-enable-grammarly="false"
              aria-label="Type the words shown above"
            />
          </div>

          {/* Hint - responsive for mobile */}
          <p className="text-center text-xs text-gray-500 dark:text-gray-400 mt-1">
            <span className="hidden sm:inline">Click the text area and start typing. Press </span>
            <kbd className="px-1.5 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-[10px] sm:text-xs">Space</kbd>
            <span className="hidden sm:inline"> to move to next word</span>
            <span className="sm:hidden"> = next word</span>
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
          transition={{ duration: 0.3 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden"
        >
          {/* Compact stats banner */}
          <div className={`bg-gradient-to-r ${
            currentRound === 0 ? 'from-green-500 to-emerald-600' :
            currentRound === 1 ? 'from-yellow-500 to-orange-600' :
            'from-red-500 to-rose-600'
          } p-4 text-white`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-6 h-6" />
                <span className="font-bold text-lg">Round {currentRound + 1} Complete</span>
              </div>
              <div className="flex items-center gap-4 text-white/90">
                <span className="font-bold">{lastResult?.wpm || 0} <span className="text-xs font-normal opacity-80">WPM</span></span>
                <span className="font-bold">{lastResult?.accuracy || 0}% <span className="text-xs font-normal opacity-80">ACC</span></span>
                <span className="font-bold">{lastResult?.maxCombo || 0}x <span className="text-xs font-normal opacity-80">COMBO</span></span>
              </div>
            </div>
          </div>

          {/* Next round preview + auto-advance */}
          {!isLastRound && (
            <div className="p-5 text-center">
              <div className="mb-3">
                <span className="text-sm text-gray-500 dark:text-gray-400 uppercase tracking-wider">Next up</span>
                <h3 className="text-xl font-bold text-gray-900 dark:text-white mt-1">
                  {ROUNDS[currentRound + 1]?.name}
                </h3>
                {ROUNDS[currentRound + 1]?.timeLimit && (
                  <div className="flex items-center justify-center gap-1 text-orange-500 text-sm mt-1">
                    <Clock className="w-4 h-4" />
                    <span>{ROUNDS[currentRound + 1].timeLimit}s time limit</span>
                  </div>
                )}
              </div>

              {/* Auto-advance countdown */}
              <RoundCountdown onComplete={nextRound} seconds={3} />

              <button
                onClick={nextRound}
                className="mt-3 px-6 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
              >
                Skip →
              </button>
            </div>
          )}

          {isLastRound && (
            <div className="p-5 text-center">
              <button
                onClick={nextRound}
                className="px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold text-lg hover:from-blue-600 hover:to-purple-700 transition-all"
              >
                See Results
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
          <XCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />

          <h2 className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
            Time's Up!
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            You didn't complete Round {currentRound + 1} in time.
          </p>

          <div className="flex gap-4 justify-center">
            <button
              onClick={startGame}
              className="px-6 py-3 bg-blue-500 text-white rounded-lg font-semibold hover:bg-blue-600 transition-all flex items-center gap-2"
            >
              <RotateCcw className="w-5 h-5" />
              Try Again
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  // ==================== RENDER: GAME COMPLETE ====================
  if (gameStatus === 'game_complete') {
    // Filter newly completed (claimable) challenges
    const newlyCompletedChallenges = dailyChallenges.filter(c => c.is_completed && !c.is_claimed);
    const isPersonalBest = results?.is_personal_best_wpm || results?.is_personal_best_accuracy;

    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6 relative">
        {/* Confetti animation for personal best */}
        <AnimatePresence>
          {showConfetti && (
            <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden">
              {[...Array(50)].map((_, i) => (
                <motion.div
                  key={i}
                  initial={{
                    opacity: 1,
                    y: -20,
                    x: Math.random() * window.innerWidth,
                    rotate: 0,
                  }}
                  animate={{
                    opacity: 0,
                    y: window.innerHeight + 100,
                    rotate: Math.random() * 720 - 360,
                  }}
                  exit={{ opacity: 0 }}
                  transition={{
                    duration: 2 + Math.random() * 2,
                    delay: Math.random() * 0.5,
                    ease: 'easeOut',
                  }}
                  className={`absolute w-3 h-3 ${
                    ['bg-yellow-400', 'bg-purple-500', 'bg-blue-500', 'bg-green-500', 'bg-pink-500', 'bg-orange-500'][
                      Math.floor(Math.random() * 6)
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
            {/* Personal best celebration */}
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
                    className="w-24 h-24 bg-yellow-400/30 rounded-full blur-xl"
                  />
                </div>
                <div className="relative">
                  <Star className="w-16 h-16 text-yellow-500 mx-auto mb-2" fill="currentColor" />
                  <Sparkles className="w-8 h-8 text-yellow-400 absolute -top-2 -right-2" />
                </div>
              </motion.div>
            ) : (
              <Trophy className="w-16 h-16 text-yellow-500 mx-auto mb-4" />
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
                  S: 'Lightning Fingers!',
                  A: 'Speed Demon!',
                  B: 'Solid Typist!',
                  C: 'Keep Practicing!',
                  D: 'Room to Grow!',
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
              {isPersonalBest ? 'New Personal Best!' : 'Challenge Complete!'}
            </h2>

            {isPersonalBest && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="flex flex-wrap justify-center gap-2 mb-4"
              >
                {results?.is_personal_best_wpm && (
                  <span className="inline-flex items-center gap-1 bg-gradient-to-r from-yellow-400 to-orange-500 text-white px-3 py-1 rounded-full text-sm font-medium shadow-lg">
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
            <div className="grid grid-cols-3 gap-4 my-6">
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
                <div className="text-sm text-gray-600 dark:text-gray-400">Avg Accuracy</div>
              </div>
              <div className="bg-orange-50 dark:bg-orange-900/30 rounded-lg p-4">
                <Zap className="w-6 h-6 text-orange-500 mx-auto mb-2" />
                <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                  {avgStats.maxCombo}x
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Best Combo</div>
              </div>
            </div>

            {/* XP earned with animated drop effect - for authenticated users */}
            {isAuthenticated && (
              <motion.div
                initial={{ scale: 0, y: -30 }}
                animate={{ scale: 1, y: 0 }}
                transition={{ delay: 0.4, type: 'spring', damping: 8 }}
                className="bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-purple-900/30 dark:to-indigo-900/30 border border-purple-200 dark:border-purple-700 rounded-xl p-5 mb-6 relative overflow-hidden"
              >
                {/* Glow effect */}
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
                    +{results?.xp_earned ?? Math.round(avgStats.wpm * 2.5)} XP
                  </motion.div>
                  <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    {results?.streak?.streak_bonus_xp && results.streak.streak_bonus_xp > 0 ? (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.8 }}
                        className="inline-flex items-center gap-1 text-orange-500 font-medium"
                      >
                        <Flame className="w-4 h-4" />
                        Includes +{results.streak.streak_bonus_xp} streak bonus!
                      </motion.span>
                    ) : (
                      'Experience Earned'
                    )}
                  </div>
                </div>
              </motion.div>
            )}

            {/* Guest XP teaser - show regardless of results */}
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
                  className="flex flex-col sm:flex-row justify-between items-start sm:items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg gap-1"
                >
                  <span className="font-medium text-gray-900 dark:text-white">
                    Round {result.round}
                  </span>
                  <span className="text-gray-600 dark:text-gray-400 text-sm">
                    {result.wpm} WPM | {result.accuracy}% | {result.time}s | {result.maxCombo}x
                  </span>
                </div>
              ))}
            </div>

            <button
              onClick={startGame}
              className="px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold text-lg hover:from-blue-600 hover:to-purple-700 transition-all flex items-center gap-2 mx-auto"
            >
              <RotateCcw className="w-5 h-5" />
              Play Again
            </button>
          </motion.div>

          {/* Sidebar: Streak & Completed Challenges */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="space-y-4"
          >
            {/* Streak update (authenticated users) */}
            {isAuthenticated && streakInfo && (
              <div className="relative">
                {results?.streak?.streak_extended && (
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className="absolute -top-2 -right-2 bg-green-500 text-white text-xs font-bold px-2 py-1 rounded-full z-10"
                  >
                    +1 Day!
                  </motion.div>
                )}
                <StreakDisplay streak={streakInfo} />
              </div>
            )}

            {/* Completed challenges to claim */}
            {isAuthenticated && newlyCompletedChallenges.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="bg-gradient-to-br from-amber-50 to-yellow-50 dark:from-amber-900/20 dark:to-yellow-900/20 rounded-xl p-4 border border-amber-200 dark:border-amber-800"
              >
                <h3 className="font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                  <Gift className="w-5 h-5 text-amber-500" />
                  Challenges Completed!
                </h3>
                <div className="space-y-3">
                  {newlyCompletedChallenges.map(challenge => (
                    <DailyChallengeCard
                      key={challenge.challenge_id}
                      challenge={challenge}
                      onClaim={handleClaimChallenge}
                      claiming={claimingChallenge === challenge.challenge_id}
                    />
                  ))}
                </div>
              </motion.div>
            )}

            {/* Challenges completed notification from API response */}
            {results?.challenges_completed && results.challenges_completed.length > 0 && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.5 }}
                className="bg-green-50 dark:bg-green-900/30 rounded-xl p-4 border border-green-200 dark:border-green-800"
              >
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle2 className="w-5 h-5 text-green-500" />
                  <span className="font-semibold text-green-700 dark:text-green-300">
                    {results.challenges_completed.length} Challenge{results.challenges_completed.length > 1 ? 's' : ''} Completed!
                  </span>
                </div>
                <div className="space-y-1">
                  {results.challenges_completed.map((c, i) => (
                    <div key={i} className="flex justify-between text-sm text-green-600 dark:text-green-400">
                      <span>{c.challenge_type.replace('_', ' ')}</span>
                      <span>+{c.xp_reward} XP</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}

            {/* Sign up prompt for guests */}
            {!isAuthenticated && (
              <div className="bg-gradient-to-br from-purple-50 to-blue-50 dark:from-gray-800 dark:to-gray-900 rounded-xl p-4 border border-purple-200 dark:border-purple-800">
                <div className="flex items-center gap-2 mb-2">
                  <Flame className="w-5 h-5 text-orange-500" />
                  <span className="font-semibold text-gray-900 dark:text-white">Track your progress!</span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                  Sign up to build streaks, complete challenges, and climb the leaderboard.
                </p>
                <button
                  onClick={showPrompt}
                  className="w-full py-2 bg-purple-500 hover:bg-purple-600 text-white text-sm font-medium rounded-lg transition-colors"
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

  // Fallback - registration modal
  return (
    <RegistrationPrompt
      isOpen={isPromptOpen}
      onClose={closePrompt}
      onSkip={handlePromptSkip}
      context="game"
    />
  );
};

export default QuickBrownFoxGame;
