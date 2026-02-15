// frontend/src/plugins/typing-game/components/WordListPracticeGame.tsx
/**
 * Word List Practice Mode - Practice typing with custom word lists
 *
 * Features:
 * - Uses custom word lists from backend
 * - No time limit (practice at your own pace)
 * - Real-time WPM and accuracy tracking
 * - Combo system for engagement
 * - Anti-cheat integration
 * - Sound effects
 * - Submit results to backend
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Play,
  RotateCcw,
  Trophy,
  Target,
  AlertCircle,
  ArrowLeft,
  BookOpen,
} from 'lucide-react';

import { typingGameApi, type StreakInfo } from '../services/typingGameApi';
import { useComboSystem } from '../hooks/useComboSystem';
import { useSoundEffects } from '../hooks/useSoundEffects';
import { useAntiCheat } from '../hooks/useAntiCheat';
import { WordDisplay } from './WordDisplay';
import { ComboCounter } from './ComboCounter';
import { StreakDisplay } from './StreakDisplay';
import { SoundSettingsPanel } from './SoundSettings';
import { useAuth } from '../../../state/contexts/AuthContext';
import { RegistrationPrompt } from '../../../components/auth/RegistrationPrompt';
import { useRegistrationPrompt } from '../../../hooks/useRegistrationPrompt';
import type { WordState, CharacterState } from '../hooks/useTypingEngine';
import type {
  TypingGameStartResponse,
  TypingGameResultsResponse,
  TypingGameSubmitRequestV2,
} from '../types';

// ==================== CONFIGURATION ====================

const DEFAULT_WORD_COUNT = 50; // Number of words to practice with

// ==================== INTERFACES ====================

interface WordListPracticeGameProps {
  wordListId: string;
  wordListName?: string;
  onComplete?: (results: TypingGameResultsResponse) => void;
  onExit?: () => void;
}

type GameStatus = 'loading' | 'ready' | 'countdown' | 'playing' | 'completed';

// ==================== HELPERS ====================

const initializeWordStates = (words: string[]): WordState[] => {
  return words.map((word, index) => ({
    word,
    index,
    status: index === 0 ? 'current' : 'pending',
    typedValue: '',
    isCorrect: true,
    characterStates: word.split('').map(char => ({
      char,
      status: 'pending',
      typedChar: undefined,
    })),
  }));
};

// ==================== COUNTDOWN COMPONENT ====================

const PracticeCountdown: React.FC<{ onComplete: () => void; seconds: number }> = ({ onComplete, seconds }) => {
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
        className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-green-500 to-teal-600"
      >
        {count}
      </motion.div>
      <div className="relative w-16 h-1 mt-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <motion.div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-green-500 to-teal-600 rounded-full"
          initial={{ width: '100%' }}
          animate={{ width: '0%' }}
          transition={{ duration: seconds, ease: 'linear' }}
        />
      </div>
    </div>
  );
};

// ==================== COMPONENT ====================

export const WordListPracticeGame: React.FC<WordListPracticeGameProps> = ({
  wordListId,
  wordListName,
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
  const [gameStatus, setGameStatus] = useState<GameStatus>('loading');
  const [wordStates, setWordStates] = useState<WordState[]>([]);
  const [currentWordIndex, setCurrentWordIndex] = useState(0);
  const [currentInput, setCurrentInput] = useState('');
  const [sessionData, setSessionData] = useState<TypingGameStartResponse | null>(null);
  const [results, setResults] = useState<TypingGameResultsResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Stats
  const [wordsCompleted, setWordsCompleted] = useState(0);
  const [correctChars, setCorrectChars] = useState(0);
  const [incorrectChars, setIncorrectChars] = useState(0);
  const [wpm, setWpm] = useState(0);
  const [accuracy, setAccuracy] = useState(100);

  // Streak state
  const [streakInfo, setStreakInfo] = useState<StreakInfo | null>(null);

  // Refs
  const inputRef = useRef<HTMLInputElement>(null);
  const startTimeRef = useRef<number | null>(null);

  // Hooks
  const comboSystem = useComboSystem();
  const antiCheat = useAntiCheat();

  // Focus input helper
  const focusInput = useCallback(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, []);

  // Auto-focus on mount and when playing
  useEffect(() => {
    if (gameStatus === 'playing') {
      const timer = setTimeout(() => {
        focusInput();
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [gameStatus, focusInput]);

  // Load word list from backend
  useEffect(() => {
    const loadWordList = async () => {
      setGameStatus('loading');
      setLoadError(null);

      try {
        const response = await typingGameApi.startGame({
          word_list_id: wordListId,
          mode: 'practice',
          word_count: DEFAULT_WORD_COUNT,
        });

        setSessionData(response);

        // Check if backend returned valid text
        if (!response.text || response.text.trim().length === 0) {
          throw new Error('No words received from word list. Please try another list.');
        }

        // Initialize word states from backend text
        const words = response.text.trim().split(/\s+/);
        setWordStates(initializeWordStates(words));
        setCurrentWordIndex(0);
        setGameStatus('ready');
      } catch (error) {
        console.error('Failed to load word list:', error);
        setLoadError(
          error instanceof Error
            ? error.message
            : 'Failed to load word list. Please try again.'
        );
        setGameStatus('ready');
      }
    };

    loadWordList();
  }, [wordListId]);

  // Start the game
  const startGame = useCallback(() => {
    if (wordStates.length === 0) {
      setLoadError('No words to practice. Please select another word list.');
      return;
    }

    setCurrentInput('');
    setWordsCompleted(0);
    setCorrectChars(0);
    setIncorrectChars(0);
    setWpm(0);
    setAccuracy(100);
    comboSystem.reset();
    antiCheat.reset();

    setGameStatus('countdown');
  }, [wordStates, comboSystem, antiCheat]);

  // Begin playing after countdown
  const beginPlaying = useCallback(() => {
    startTimeRef.current = Date.now();
    antiCheat.startTracking();
    sounds.playGameStart();
    setGameStatus('playing');
    focusInput();
  }, [antiCheat, sounds, focusInput]);

  // Calculate real-time stats
  const updateStats = useCallback(() => {
    if (!startTimeRef.current) return;

    const now = Date.now();
    const elapsedMinutes = (now - startTimeRef.current) / 1000 / 60;

    if (elapsedMinutes > 0) {
      const totalChars = correctChars + incorrectChars;
      const wordsTyped = totalChars / 5; // Standard: 5 chars = 1 word
      const calculatedWpm = Math.round(wordsTyped / elapsedMinutes);
      const calculatedAccuracy = totalChars > 0 ? (correctChars / totalChars) * 100 : 100;

      setWpm(calculatedWpm);
      setAccuracy(Math.round(calculatedAccuracy * 10) / 10);
    }
  }, [correctChars, incorrectChars]);

  // Handle typing input
  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (gameStatus !== 'playing') return;

      const value = e.target.value;

      // Handle space - move to next word
      if (value.endsWith(' ')) {
        const typedWord = value.trim();
        const currentWord = wordStates[currentWordIndex];
        if (!currentWord) return;

        const isCorrect = typedWord === currentWord.word;

        // Update stats for this word
        const wordLength = currentWord.word.length;
        if (isCorrect) {
          setCorrectChars(prev => prev + wordLength);
          sounds.playMilestone();
          comboSystem.increment();
        } else {
          // Count correct and incorrect chars
          let correct = 0;
          let incorrect = 0;
          for (let i = 0; i < Math.max(typedWord.length, wordLength); i++) {
            if (i < typedWord.length && i < wordLength && typedWord[i] === currentWord.word[i]) {
              correct++;
            } else {
              incorrect++;
            }
          }
          setCorrectChars(prev => prev + correct);
          setIncorrectChars(prev => prev + incorrect);
          sounds.playError();
          comboSystem.breakCombo();
        }

        // Mark word as completed and move to next
        const newWordStates = [...wordStates];
        newWordStates[currentWordIndex] = {
          ...currentWord,
          status: 'completed',
          typedValue: typedWord,
          isCorrect,
          characterStates: currentWord.word.split('').map((char, idx) => ({
            char,
            status: idx < typedWord.length
              ? (typedWord[idx] === char ? 'correct' : 'incorrect')
              : 'incorrect',
            typedChar: typedWord[idx],
          })),
        };

        setWordsCompleted(prev => prev + 1);

        // Move to next word or end game
        if (currentWordIndex < wordStates.length - 1) {
          newWordStates[currentWordIndex + 1] = {
            ...newWordStates[currentWordIndex + 1],
            status: 'current',
          };
          setCurrentWordIndex(prev => prev + 1);
          setWordStates(newWordStates);
          setCurrentInput('');
        } else {
          setWordStates(newWordStates);
          endGame();
        }

        antiCheat.recordKeystroke();
        return;
      }

      // Normal typing - update character states
      setCurrentInput(value);
      antiCheat.recordKeystroke();

      const currentWord = wordStates[currentWordIndex];
      if (!currentWord) return;

      // Update character states for visual feedback
      const newCharStates: CharacterState[] = currentWord.word.split('').map((char, idx) => {
        if (idx < value.length) {
          const typedChar = value[idx];
          const isCorrect = typedChar === char;
          return {
            char,
            status: isCorrect ? 'correct' : 'incorrect',
            typedChar,
          };
        }
        return {
          char,
          status: 'pending',
          typedChar: undefined,
        };
      });

      const newWordStates = [...wordStates];
      newWordStates[currentWordIndex] = {
        ...currentWord,
        typedValue: value,
        characterStates: newCharStates,
      };
      setWordStates(newWordStates);
    },
    [gameStatus, wordStates, currentWordIndex, antiCheat, sounds, comboSystem]
  );

  // End game and submit results
  const endGame = useCallback(async () => {
    antiCheat.stopTracking();
    sounds.playGameEnd();

    const elapsedSeconds = startTimeRef.current
      ? Math.round((Date.now() - startTimeRef.current) / 1000)
      : 0;

    // Submit to backend if we have a session
    if (sessionData && isAuthenticated) {
      try {
        const typedText = wordStates
          .map(w => w.typedValue || '')
          .join(' ');

        const antiCheatData = antiCheat.getAntiCheatData();

        const submitRequest: TypingGameSubmitRequestV2 = {
          session_id: sessionData.session_id,
          user_input: typedText,
          time_elapsed: elapsedSeconds,
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

        const result = await typingGameApi.submitGameV2(submitRequest);
        setResults(result);

        // Fetch updated streak info
        try {
          const dailyData = await typingGameApi.getDailyChallenges();
          setStreakInfo(dailyData.streak);
        } catch (err) {
          console.error('Failed to fetch streak info:', err);
        }

        if (onComplete) {
          onComplete(result);
        }
      } catch (error) {
        console.error('Failed to submit results:', error);
      }
    } else if (!isAuthenticated) {
      showPrompt();
    }

    setGameStatus('completed');
  }, [
    antiCheat,
    sounds,
    sessionData,
    isAuthenticated,
    wordStates,
    comboSystem.maxCombo,
    onComplete,
    showPrompt,
  ]);

  // Update stats periodically
  useEffect(() => {
    if (gameStatus === 'playing') {
      const interval = setInterval(updateStats, 100);
      return () => clearInterval(interval);
    }
  }, [gameStatus, updateStats]);

  // Handle paste prevention
  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault();
    antiCheat.recordPasteAttempt();
  }, [antiCheat]);

  // Handle focus tracking
  const handleBlur = useCallback(() => {
    // Focus tracking handled automatically by useAntiCheat via visibilitychange
  }, []);

  const handleFocus = useCallback(() => {
    // Focus tracking handled automatically by useAntiCheat via visibilitychange
  }, []);

  // Restart game
  const restartGame = useCallback(() => {
    setResults(null);
    setCurrentWordIndex(0);
    setCurrentInput('');

    // Re-initialize word states
    if (sessionData?.text) {
      const words = sessionData.text.trim().split(/\s+/);
      setWordStates(initializeWordStates(words));
    }

    startGame();
  }, [sessionData, startGame]);

  // Calculate progress
  const progress = wordStates.length > 0
    ? (wordsCompleted / wordStates.length) * 100
    : 0;

  // ==================== RENDER ====================

  // Loading state
  if (gameStatus === 'loading') {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-green-500 to-teal-600 rounded-full mb-4 animate-pulse">
            <BookOpen className="w-8 h-8 text-white" />
          </div>
          <p className="text-gray-600 dark:text-gray-400">Loading word list...</p>
        </div>
      </div>
    );
  }

  // Ready/Idle state
  if (gameStatus === 'ready') {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl w-full"
        >
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8">
            {/* Header */}
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-green-500 to-teal-600 rounded-2xl mb-4 shadow-lg">
                <Target className="w-10 h-10 text-white" />
              </div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                Practice Mode
              </h1>
              {wordListName && (
                <p className="text-lg text-gray-600 dark:text-gray-400">
                  {wordListName}
                </p>
              )}
            </div>

            {/* Error message */}
            {loadError && (
              <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-red-600 dark:text-red-400 flex items-center gap-2">
                  <AlertCircle className="w-5 h-5" />
                  {loadError}
                </p>
              </div>
            )}

            {/* Info */}
            {!loadError && (
              <div className="mb-8 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                <p className="text-green-700 dark:text-green-300 text-center">
                  Practice {wordStates.length} words • Press SPACE after each word
                </p>
              </div>
            )}

            {/* Buttons */}
            <div className="flex gap-4">
              <button
                onClick={onExit}
                className="flex-1 px-6 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors flex items-center justify-center gap-2"
              >
                <ArrowLeft className="w-5 h-5" />
                Back
              </button>
              <button
                onClick={startGame}
                disabled={loadError !== null || wordStates.length === 0}
                className="flex-1 px-6 py-3 bg-gradient-to-r from-green-500 to-teal-600 text-white rounded-lg font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                <Play className="w-5 h-5" />
                Start Practice
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  // Countdown state
  if (gameStatus === 'countdown') {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-8">
            Get Ready!
          </h2>
          <PracticeCountdown onComplete={beginPlaying} seconds={3} />
        </div>
      </div>
    );
  }

  // Playing state
  if (gameStatus === 'playing') {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
        <div className="max-w-5xl mx-auto px-4">
          {/* Header with stats */}
          <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <button
                onClick={onExit}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors flex items-center gap-2"
              >
                <ArrowLeft className="w-5 h-5" />
                Exit
              </button>
              <div className="flex items-center gap-4">
                <SoundSettingsPanel
                  settings={sounds.settings}
                  onToggleSound={sounds.toggleSound}
                  onVolumeChange={sounds.setVolume}
                  compact
                />
              </div>
            </div>

            {/* Stats display */}
            <div className="mb-4">
              <div className="flex items-center justify-center gap-6">
                <div className="text-center">
                  <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                    {wpm}
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">WPM</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                    {accuracy.toFixed(1)}%
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Accuracy</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
                    {wordsCompleted}/{wordStates.length}
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Words</div>
                </div>
              </div>
            </div>

            {/* Progress bar */}
            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-green-500 to-teal-600"
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          </div>

          {/* Combo counter */}
          <div className="mb-6">
            <ComboCounter comboState={comboSystem.state} />
          </div>

          {/* Word display */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 mb-6">
            <WordDisplay
              words={wordStates}
              currentWordIndex={currentWordIndex}
              currentInput={currentInput}
              getCharacterStates={(wordIndex) => wordStates[wordIndex]?.characterStates || []}
              onContainerClick={focusInput}
            />
          </div>

          {/* Input */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
            <input
              ref={inputRef}
              type="text"
              value={currentInput}
              onChange={handleInputChange}
              onPaste={handlePaste}
              onBlur={handleBlur}
              onFocus={handleFocus}
              className="w-full px-4 py-3 text-2xl text-center bg-gray-50 dark:bg-gray-700 border-2 border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:border-green-500 dark:focus:border-green-400"
              placeholder="Type the word and press SPACE..."
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck="false"
              inputMode="text"
            />
            <p className="text-center text-sm text-gray-500 dark:text-gray-400 mt-2">
              Press SPACE after each word to continue
            </p>
          </div>
        </div>

        {/* Registration prompt */}
        <RegistrationPrompt
          isOpen={isPromptOpen}
          onClose={closePrompt}
          onSkip={handlePromptSkip}
          context="game"
        />
      </div>
    );
  }

  // Completed state
  if (gameStatus === 'completed' && results) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
        <div className="max-w-3xl mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8"
          >
            {/* Header */}
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-green-500 to-teal-600 rounded-2xl mb-4 shadow-lg">
                <Trophy className="w-10 h-10 text-white" />
              </div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                Practice Complete!
              </h1>
              {wordListName && (
                <p className="text-gray-600 dark:text-gray-400">{wordListName}</p>
              )}
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
              <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/30 rounded-lg">
                <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                  {results.metrics.wpm}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">WPM</div>
                {results.is_personal_best_wpm && (
                  <div className="mt-1 text-xs text-blue-600 dark:text-blue-400 font-medium">
                    Personal Best! 🎉
                  </div>
                )}
              </div>
              <div className="text-center p-4 bg-green-50 dark:bg-green-900/30 rounded-lg">
                <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                  {results.metrics.accuracy.toFixed(1)}%
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Accuracy</div>
              </div>
              <div className="text-center p-4 bg-purple-50 dark:bg-purple-900/30 rounded-lg">
                <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
                  {results.max_combo}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Max Combo</div>
              </div>
              <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/30 rounded-lg">
                <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                  +{results.xp_earned}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">XP</div>
              </div>
            </div>

            {/* Streak info */}
            {streakInfo && streakInfo.current_streak > 0 && (
              <div className="mb-8">
                <StreakDisplay streak={streakInfo} />
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-4">
              <button
                onClick={onExit}
                className="flex-1 px-6 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
              >
                Back to Word Lists
              </button>
              <button
                onClick={restartGame}
                className="flex-1 px-6 py-3 bg-gradient-to-r from-green-500 to-teal-600 text-white rounded-lg font-medium hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
              >
                <RotateCcw className="w-5 h-5" />
                Practice Again
              </button>
            </div>
          </motion.div>
        </div>

        {/* Registration prompt */}
        <RegistrationPrompt
          isOpen={isPromptOpen}
          onClose={closePrompt}
          onSkip={handlePromptSkip}
          context="game"
        />
      </div>
    );
  }

  return null;
};

export default WordListPracticeGame;
