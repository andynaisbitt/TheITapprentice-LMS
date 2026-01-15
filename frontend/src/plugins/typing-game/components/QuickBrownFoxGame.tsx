// frontend/src/plugins/typing-game/components/QuickBrownFoxGame.tsx
/**
 * Quick Brown Fox Typing Game - Main game component
 * 3-round progressive challenge: Warmup -> Speed -> Insane Mode
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Play,
  RotateCcw,
  Trophy,
  Target,
  Clock,
  Keyboard,
  Zap,
  AlertCircle,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { typingGameApi } from '../services/typingGameApi';
import type {
  TypingGameStartResponse,
  TypingGameResultsResponse,
  GameState,
  RoundConfig
} from '../types';

// Round configuration
const ROUNDS: RoundConfig[] = [
  { roundNumber: 1, name: 'Warmup Round', timeLimit: null, description: 'Get familiar with the text!' },
  { roundNumber: 2, name: 'Speed Challenge', timeLimit: 20, description: 'Complete in 20 seconds!' },
  { roundNumber: 3, name: 'INSANE MODE', timeLimit: 10, description: '10 seconds or FAIL!' }
];

// The classic text
const QUICK_BROWN_FOX = "The quick brown fox jumps over the lazy dog";

interface QuickBrownFoxGameProps {
  onComplete?: (results: TypingGameResultsResponse) => void;
  wordListId?: string;
}

export const QuickBrownFoxGame: React.FC<QuickBrownFoxGameProps> = ({
  onComplete,
  wordListId
}) => {
  // Game state
  const [gameState, setGameState] = useState<'idle' | 'ready' | 'playing' | 'round_complete' | 'game_complete' | 'failed'>('idle');
  const [currentRound, setCurrentRound] = useState(0);
  const [sessionData, setSessionData] = useState<TypingGameStartResponse | null>(null);
  const [results, setResults] = useState<TypingGameResultsResponse | null>(null);

  // Typing state
  const [text, setText] = useState(QUICK_BROWN_FOX);
  const [userInput, setUserInput] = useState('');
  const [checksum, setChecksum] = useState('');

  // Stats
  const [wpm, setWpm] = useState(0);
  const [accuracy, setAccuracy] = useState(100);
  const [errors, setErrors] = useState(0);
  const [startTime, setStartTime] = useState<number | null>(null);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);

  // Round results
  const [roundResults, setRoundResults] = useState<Array<{
    round: number;
    wpm: number;
    accuracy: number;
    time: number;
    passed: boolean;
  }>>([]);

  // Refs
  const inputRef = useRef<HTMLInputElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Current round config
  const currentRoundConfig = ROUNDS[currentRound];

  // Start the game
  const startGame = useCallback(async () => {
    try {
      const response = await typingGameApi.startGame({
        word_list_id: wordListId || 'quick-brown-fox',
        mode: 'challenge',
        word_count: 9 // Quick brown fox has 9 words
      });

      setSessionData(response);
      setText(response.text || QUICK_BROWN_FOX);
      setChecksum(response.checksum);
      setCurrentRound(0);
      setRoundResults([]);
      setGameState('ready');
    } catch (error) {
      console.error('Failed to start game:', error);
      // Use default text if API fails
      setText(QUICK_BROWN_FOX);
      setChecksum('');
      setCurrentRound(0);
      setRoundResults([]);
      setGameState('ready');
    }
  }, [wordListId]);

  // Start a round
  const startRound = useCallback(() => {
    setUserInput('');
    setErrors(0);
    setWpm(0);
    setAccuracy(100);
    setStartTime(Date.now());
    setTimeElapsed(0);

    const roundConfig = ROUNDS[currentRound];
    if (roundConfig.timeLimit) {
      setTimeRemaining(roundConfig.timeLimit);
    } else {
      setTimeRemaining(null);
    }

    setGameState('playing');
    inputRef.current?.focus();
  }, [currentRound]);

  // Calculate stats
  const calculateStats = useCallback((input: string, elapsed: number) => {
    // Calculate WPM: (characters / 5) / minutes
    const words = input.length / 5;
    const minutes = elapsed / 60;
    const calculatedWpm = minutes > 0 ? Math.round(words / minutes) : 0;

    // Calculate accuracy
    let correctChars = 0;
    const minLen = Math.min(input.length, text.length);
    for (let i = 0; i < minLen; i++) {
      if (input[i] === text[i]) correctChars++;
    }
    const calculatedAccuracy = input.length > 0
      ? Math.round((correctChars / input.length) * 100)
      : 100;

    // Count errors
    let errorCount = 0;
    for (let i = 0; i < input.length; i++) {
      if (i >= text.length || input[i] !== text[i]) errorCount++;
    }

    setWpm(calculatedWpm);
    setAccuracy(calculatedAccuracy);
    setErrors(errorCount);

    return { wpm: calculatedWpm, accuracy: calculatedAccuracy, errors: errorCount };
  }, [text]);

  // Handle input change
  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (gameState !== 'playing') return;

    const newInput = e.target.value;
    setUserInput(newInput);

    const elapsed = (Date.now() - (startTime || Date.now())) / 1000;
    setTimeElapsed(elapsed);
    calculateStats(newInput, elapsed);

    // Check if completed
    if (newInput === text) {
      completeRound(true);
    }
  }, [gameState, startTime, text, calculateStats]);

  // Complete a round
  const completeRound = useCallback((passed: boolean) => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    const finalTime = (Date.now() - (startTime || Date.now())) / 1000;
    const finalStats = calculateStats(userInput, finalTime);

    const roundResult = {
      round: currentRound + 1,
      wpm: finalStats.wpm,
      accuracy: finalStats.accuracy,
      time: Math.round(finalTime),
      passed
    };

    setRoundResults(prev => [...prev, roundResult]);

    if (!passed) {
      setGameState('failed');
    } else if (currentRound >= ROUNDS.length - 1) {
      // All rounds complete
      submitFinalResults();
    } else {
      setGameState('round_complete');
    }
  }, [currentRound, startTime, userInput, calculateStats]);

  // Submit final results to API
  const submitFinalResults = useCallback(async () => {
    if (!sessionData) {
      setGameState('game_complete');
      return;
    }

    try {
      const finalResults = await typingGameApi.submitGame({
        session_id: sessionData.session_id,
        user_input: userInput,
        time_elapsed: Math.round(timeElapsed),
        checksum: checksum
      });

      setResults(finalResults);
      setGameState('game_complete');
      onComplete?.(finalResults);
    } catch (error) {
      console.error('Failed to submit results:', error);
      setGameState('game_complete');
    }
  }, [sessionData, userInput, timeElapsed, checksum, onComplete]);

  // Next round
  const nextRound = useCallback(() => {
    setCurrentRound(prev => prev + 1);
    setGameState('ready');
  }, []);

  // Timer effect
  useEffect(() => {
    if (gameState === 'playing' && currentRoundConfig?.timeLimit) {
      timerRef.current = setInterval(() => {
        const elapsed = (Date.now() - (startTime || Date.now())) / 1000;
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
  }, [gameState, startTime, currentRoundConfig, completeRound]);

  // Render word display with character highlighting
  const renderText = () => {
    return text.split('').map((char, index) => {
      let className = 'text-gray-400';

      if (index < userInput.length) {
        if (userInput[index] === char) {
          className = 'text-green-500';
        } else {
          className = 'text-red-500 bg-red-100 dark:bg-red-900/30';
        }
      } else if (index === userInput.length) {
        className = 'text-gray-900 dark:text-white bg-blue-100 dark:bg-blue-900/50 animate-pulse';
      }

      return (
        <span key={index} className={`${className} font-mono text-2xl`}>
          {char}
        </span>
      );
    });
  };

  // Idle screen
  if (gameState === 'idle') {
    return (
      <div className="max-w-2xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center"
        >
          <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
            <Keyboard className="w-10 h-10 text-white" />
          </div>

          <h1 className="text-3xl font-bold mb-2 text-gray-900 dark:text-white">
            Quick Brown Fox Challenge
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Type the classic pangram through 3 progressively harder rounds!
          </p>

          <div className="space-y-3 mb-8">
            {ROUNDS.map((round, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <span className="font-medium text-gray-900 dark:text-white">
                  Round {round.roundNumber}: {round.name}
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {round.timeLimit ? `${round.timeLimit}s limit` : 'No limit'}
                </span>
              </div>
            ))}
          </div>

          <button
            onClick={startGame}
            className="px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold text-lg hover:from-blue-600 hover:to-purple-700 transition-all flex items-center gap-2 mx-auto"
          >
            <Play className="w-5 h-5" />
            Start Challenge
          </button>
        </motion.div>
      </div>
    );
  }

  // Ready screen
  if (gameState === 'ready') {
    return (
      <div className="max-w-2xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center"
        >
          <div className="text-6xl font-bold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-600">
            Round {currentRound + 1}
          </div>
          <h2 className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
            {currentRoundConfig.name}
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            {currentRoundConfig.description}
          </p>

          {currentRoundConfig.timeLimit && (
            <div className="flex items-center justify-center gap-2 mb-6 text-orange-500">
              <Clock className="w-5 h-5" />
              <span className="font-bold">{currentRoundConfig.timeLimit} second time limit</span>
            </div>
          )}

          <button
            onClick={startRound}
            className="px-8 py-3 bg-green-500 text-white rounded-lg font-semibold text-lg hover:bg-green-600 transition-all flex items-center gap-2 mx-auto"
          >
            <Zap className="w-5 h-5" />
            GO!
          </button>
        </motion.div>
      </div>
    );
  }

  // Playing screen
  if (gameState === 'playing') {
    return (
      <div className="max-w-3xl mx-auto p-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8">
          {/* Header */}
          <div className="flex justify-between items-center mb-6">
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              Round {currentRound + 1}: {currentRoundConfig.name}
            </div>
            {timeRemaining !== null && (
              <motion.div
                className={`text-2xl font-bold ${
                  timeRemaining <= 3 ? 'text-red-500 animate-pulse' : 'text-blue-500'
                }`}
                animate={timeRemaining <= 3 ? { scale: [1, 1.1, 1] } : {}}
                transition={{ duration: 0.5, repeat: timeRemaining <= 3 ? Infinity : 0 }}
              >
                {timeRemaining}s
              </motion.div>
            )}
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="bg-blue-50 dark:bg-blue-900/30 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">{wpm}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">WPM</div>
            </div>
            <div className="bg-green-50 dark:bg-green-900/30 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-green-600 dark:text-green-400">{accuracy}%</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Accuracy</div>
            </div>
            <div className="bg-red-50 dark:bg-red-900/30 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">{errors}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Errors</div>
            </div>
          </div>

          {/* Text display */}
          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-6 mb-4 min-h-[100px] select-none">
            <div className="leading-relaxed break-words">
              {renderText()}
            </div>
          </div>

          {/* Input */}
          <input
            ref={inputRef}
            type="text"
            value={userInput}
            onChange={handleInputChange}
            className="w-full p-4 text-xl font-mono border-2 border-gray-200 dark:border-gray-700 rounded-lg focus:border-blue-500 focus:outline-none bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
            placeholder="Start typing..."
            autoFocus
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
          />
        </div>
      </div>
    );
  }

  // Round complete screen
  if (gameState === 'round_complete') {
    const lastResult = roundResults[roundResults.length - 1];

    return (
      <div className="max-w-2xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center"
        >
          <CheckCircle2 className="w-16 h-16 text-green-500 mx-auto mb-4" />

          <h2 className="text-2xl font-bold mb-2 text-gray-900 dark:text-white">
            Round {currentRound + 1} Complete!
          </h2>

          <div className="grid grid-cols-3 gap-4 my-6">
            <div className="bg-blue-50 dark:bg-blue-900/30 rounded-lg p-4">
              <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                {lastResult?.wpm || 0}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">WPM</div>
            </div>
            <div className="bg-green-50 dark:bg-green-900/30 rounded-lg p-4">
              <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                {lastResult?.accuracy || 0}%
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Accuracy</div>
            </div>
            <div className="bg-purple-50 dark:bg-purple-900/30 rounded-lg p-4">
              <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">
                {lastResult?.time || 0}s
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Time</div>
            </div>
          </div>

          <button
            onClick={nextRound}
            className="px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold text-lg hover:from-blue-600 hover:to-purple-700 transition-all"
          >
            Next Round
          </button>
        </motion.div>
      </div>
    );
  }

  // Failed screen
  if (gameState === 'failed') {
    return (
      <div className="max-w-2xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center"
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

  // Game complete screen
  if (gameState === 'game_complete') {
    const avgWpm = Math.round(roundResults.reduce((sum, r) => sum + r.wpm, 0) / roundResults.length);
    const avgAccuracy = Math.round(roundResults.reduce((sum, r) => sum + r.accuracy, 0) / roundResults.length);

    return (
      <div className="max-w-2xl mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8 text-center"
        >
          <Trophy className="w-16 h-16 text-yellow-500 mx-auto mb-4" />

          <h2 className="text-3xl font-bold mb-2 text-gray-900 dark:text-white">
            Challenge Complete!
          </h2>

          {results?.is_personal_best_wpm && (
            <div className="inline-flex items-center gap-2 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 px-4 py-2 rounded-full mb-4">
              <Trophy className="w-5 h-5" />
              New Personal Best!
            </div>
          )}

          <div className="grid grid-cols-2 gap-4 my-6">
            <div className="bg-blue-50 dark:bg-blue-900/30 rounded-lg p-4">
              <div className="text-4xl font-bold text-blue-600 dark:text-blue-400">
                {avgWpm}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Average WPM</div>
            </div>
            <div className="bg-green-50 dark:bg-green-900/30 rounded-lg p-4">
              <div className="text-4xl font-bold text-green-600 dark:text-green-400">
                {avgAccuracy}%
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Average Accuracy</div>
            </div>
          </div>

          {results && (
            <div className="bg-purple-50 dark:bg-purple-900/30 rounded-lg p-4 mb-6">
              <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                +{results.xp_earned} XP
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Earned</div>
            </div>
          )}

          {/* Round breakdown */}
          <div className="space-y-2 mb-6">
            {roundResults.map((result, idx) => (
              <div key={idx} className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <span className="font-medium text-gray-900 dark:text-white">
                  Round {result.round}
                </span>
                <span className="text-gray-600 dark:text-gray-400">
                  {result.wpm} WPM | {result.accuracy}% | {result.time}s
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
      </div>
    );
  }

  return null;
};

export default QuickBrownFoxGame;
