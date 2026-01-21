// frontend/src/plugins/typing-game/components/PVPGameInterface.tsx
/**
 * PVP Game Interface Component
 * The main typing interface for PVP matches with real-time opponent tracking
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Zap,
  Target,
  Clock,
  User,
  Users,
  AlertTriangle,
  Wifi,
  WifiOff
} from 'lucide-react';
import { usePVPWebSocket, OpponentProgress } from '../hooks/usePVPWebSocket';
import type { PVPMatch, PVPMatchDetail } from '../types';

interface PVPGameInterfaceProps {
  match: PVPMatch | PVPMatchDetail;
  roundText: string;
  timeLimit: number;
  currentRound: number;
  totalRounds: number;
  playerNumber: 1 | 2;
  opponentInfo?: {
    username: string;
    rating: number;
  };
  onRoundComplete: (wpm: number, accuracy: number, timeElapsed: number) => void;
  onForfeit: () => void;
  allowBackspace?: boolean;
}

export const PVPGameInterface: React.FC<PVPGameInterfaceProps> = ({
  match,
  roundText,
  timeLimit,
  currentRound,
  totalRounds,
  playerNumber,
  opponentInfo,
  onRoundComplete,
  onForfeit,
  allowBackspace = true,
}) => {
  // Game state
  const [userInput, setUserInput] = useState('');
  const [startTime, setStartTime] = useState<number | null>(null);
  const [timeRemaining, setTimeRemaining] = useState(timeLimit);
  const [isComplete, setIsComplete] = useState(false);
  const [currentWpm, setCurrentWpm] = useState(0);
  const [accuracy, setAccuracy] = useState(100);
  const [errors, setErrors] = useState(0);

  // Opponent state
  const [opponentProgress, setOpponentProgress] = useState(0);
  const [opponentWpm, setOpponentWpm] = useState(0);
  const [opponentFinished, setOpponentFinished] = useState(false);
  const [opponentDisconnected, setOpponentDisconnected] = useState(false);

  // Refs
  const inputRef = useRef<HTMLInputElement>(null);
  const progressUpdateRef = useRef<NodeJS.Timeout | null>(null);

  // WebSocket connection
  const {
    isConnected,
    error: wsError,
    sendProgress,
    sendRoundComplete,
    sendForfeit,
  } = usePVPWebSocket({
    matchId: match.id,
    onOpponentProgress: (progress: OpponentProgress) => {
      setOpponentProgress(progress.progress);
      setOpponentWpm(progress.current_wpm);
    },
    onOpponentFinished: (data) => {
      setOpponentFinished(true);
    },
    onOpponentDisconnected: () => {
      setOpponentDisconnected(true);
    },
  });

  // Calculate progress percentage
  const progress = useMemo(() => {
    if (!roundText) return 0;
    return Math.min(100, (userInput.length / roundText.length) * 100);
  }, [userInput.length, roundText]);

  // Calculate WPM and accuracy
  const calculateMetrics = useCallback(() => {
    if (!startTime || userInput.length === 0) return { wpm: 0, accuracy: 100 };

    const timeElapsed = (Date.now() - startTime) / 1000 / 60; // in minutes
    const wordsTyped = userInput.split(/\s+/).length;
    const wpm = Math.round(wordsTyped / Math.max(timeElapsed, 0.01));

    let correctChars = 0;
    for (let i = 0; i < userInput.length && i < roundText.length; i++) {
      if (userInput[i] === roundText[i]) {
        correctChars++;
      }
    }
    const acc = userInput.length > 0 ? (correctChars / userInput.length) * 100 : 100;

    return { wpm, accuracy: Math.round(acc * 10) / 10 };
  }, [startTime, userInput, roundText]);

  // Update metrics in real-time
  useEffect(() => {
    const metrics = calculateMetrics();
    setCurrentWpm(metrics.wpm);
    setAccuracy(metrics.accuracy);
  }, [calculateMetrics]);

  // Timer countdown
  useEffect(() => {
    if (!startTime || isComplete) return;

    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      const remaining = Math.max(0, timeLimit - elapsed);
      setTimeRemaining(remaining);

      if (remaining === 0) {
        handleTimeUp();
      }
    }, 100);

    return () => clearInterval(interval);
  }, [startTime, timeLimit, isComplete]);

  // Send progress updates to opponent
  useEffect(() => {
    if (!isConnected || isComplete) return;

    progressUpdateRef.current = setInterval(() => {
      const wordsTyped = userInput.split(/\s+/).filter(w => w).length;
      sendProgress(progress, wordsTyped, currentWpm);
    }, 500);

    return () => {
      if (progressUpdateRef.current) {
        clearInterval(progressUpdateRef.current);
      }
    };
  }, [isConnected, isComplete, progress, currentWpm, userInput, sendProgress]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Handle time up
  const handleTimeUp = useCallback(() => {
    if (isComplete) return;
    setIsComplete(true);

    const metrics = calculateMetrics();
    const timeElapsed = startTime ? (Date.now() - startTime) / 1000 : timeLimit;

    sendRoundComplete(metrics.wpm, metrics.accuracy);
    onRoundComplete(metrics.wpm, metrics.accuracy, timeElapsed);
  }, [isComplete, calculateMetrics, startTime, timeLimit, sendRoundComplete, onRoundComplete]);

  // Handle input change
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (isComplete) return;

    let value = e.target.value;

    // If backspace is not allowed and user is trying to delete, prevent it
    if (!allowBackspace && value.length < userInput.length) {
      // Restore the previous value - don't allow deletion
      e.target.value = userInput;
      return;
    }

    // Start timer on first input
    if (!startTime && value.length > 0) {
      setStartTime(Date.now());
    }

    // Count errors
    let errorCount = 0;
    for (let i = 0; i < value.length && i < roundText.length; i++) {
      if (value[i] !== roundText[i]) {
        errorCount++;
      }
    }
    setErrors(errorCount);
    setUserInput(value);

    // Check if complete
    if (value === roundText) {
      setIsComplete(true);
      const metrics = calculateMetrics();
      const timeElapsed = startTime ? (Date.now() - startTime) / 1000 : 0;

      sendRoundComplete(metrics.wpm, metrics.accuracy);
      onRoundComplete(metrics.wpm, metrics.accuracy, timeElapsed);
    }
  };

  // Handle forfeit
  const handleForfeit = () => {
    sendForfeit();
    onForfeit();
  };

  // Render text with highlighting - word-by-word for better mobile display
  const renderText = () => {
    const words = roundText.split(' ');
    const inputWords = userInput.split(' ');
    let charIndex = 0;

    return words.map((word, wordIndex) => {
      const wordStartIndex = charIndex;
      const wordElements = word.split('').map((char, i) => {
        const absoluteIndex = wordStartIndex + i;
        let className = 'text-gray-400 dark:text-gray-500';

        if (absoluteIndex < userInput.length) {
          if (userInput[absoluteIndex] === char) {
            className = 'text-green-500 dark:text-green-400';
          } else {
            className = 'text-red-500 dark:text-red-400 bg-red-100 dark:bg-red-900/30';
          }
        } else if (absoluteIndex === userInput.length) {
          className = 'text-gray-900 dark:text-white bg-blue-100 dark:bg-blue-900/50 border-l-2 border-blue-500 animate-pulse';
        }

        return (
          <span key={absoluteIndex} className={className}>
            {char}
          </span>
        );
      });

      charIndex += word.length + 1; // +1 for space

      // Determine if this word is completed, current, or upcoming
      const wordEndIndex = wordStartIndex + word.length;
      const isCompleted = userInput.length > wordEndIndex;
      const isCurrent = userInput.length >= wordStartIndex && userInput.length <= wordEndIndex;

      return (
        <span
          key={wordIndex}
          className={`inline-block mr-2 mb-1 px-1 rounded transition-all duration-200 ${
            isCompleted
              ? 'opacity-60 scale-95'  // Completed words fade and shrink
              : isCurrent
                ? 'bg-blue-50 dark:bg-blue-900/30 scale-105'  // Current word highlighted
                : ''
          }`}
        >
          {wordElements}
          {wordIndex < words.length - 1 && (
            <span className={userInput.length > wordEndIndex ? 'text-green-500' : 'text-gray-400'}>{'\u00A0'}</span>
          )}
        </span>
      );
    });
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-6">
      <div className="max-w-4xl mx-auto px-4">
        {/* Header with match info */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 mb-6"
        >
          <div className="flex justify-between items-center">
            {/* Player Info */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
                <User className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="font-medium text-gray-900 dark:text-white">You</div>
                <div className="text-sm text-gray-500">Player {playerNumber}</div>
              </div>
            </div>

            {/* Round Counter */}
            <div className="text-center">
              <div className="text-sm text-gray-500">Round</div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {currentRound} / {totalRounds}
              </div>
            </div>

            {/* Opponent Info */}
            <div className="flex items-center gap-3">
              <div>
                <div className="font-medium text-gray-900 dark:text-white text-right">
                  {opponentInfo?.username || 'Opponent'}
                </div>
                <div className="text-sm text-gray-500 text-right">
                  {opponentDisconnected ? (
                    <span className="text-red-500">Disconnected</span>
                  ) : (
                    `Rating: ${opponentInfo?.rating || '???'}`
                  )}
                </div>
              </div>
              <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                opponentDisconnected ? 'bg-red-500' : 'bg-orange-500'
              }`}>
                {opponentDisconnected ? (
                  <WifiOff className="w-5 h-5 text-white" />
                ) : (
                  <User className="w-5 h-5 text-white" />
                )}
              </div>
            </div>
          </div>

          {/* Connection Status */}
          {wsError && (
            <div className="mt-3 p-2 bg-yellow-50 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {wsError}
            </div>
          )}
        </motion.div>

        {/* Progress Bars */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 mb-6"
        >
          {/* Your Progress */}
          <div className="mb-4">
            <div className="flex justify-between items-center mb-1">
              <span className="text-sm font-medium text-blue-600 dark:text-blue-400">You</span>
              <span className="text-sm text-gray-500">{Math.round(progress)}%</span>
            </div>
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-blue-500 to-blue-600 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.2 }}
              />
            </div>
          </div>

          {/* Opponent Progress */}
          <div>
            <div className="flex justify-between items-center mb-1">
              <span className="text-sm font-medium text-orange-600 dark:text-orange-400">
                {opponentInfo?.username || 'Opponent'}
                {opponentFinished && ' (Finished!)'}
              </span>
              <span className="text-sm text-gray-500">{Math.round(opponentProgress)}%</span>
            </div>
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-orange-500 to-orange-600 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${opponentProgress}%` }}
                transition={{ duration: 0.2 }}
              />
            </div>
          </div>
        </motion.div>

        {/* Stats Row */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="grid grid-cols-4 gap-4 mb-6"
        >
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 text-center">
            <Clock className="w-5 h-5 mx-auto mb-1 text-blue-500" />
            <div className={`text-2xl font-bold ${
              timeRemaining <= 10 ? 'text-red-500 animate-pulse' : 'text-gray-900 dark:text-white'
            }`}>
              {timeRemaining}s
            </div>
            <div className="text-xs text-gray-500">Time Left</div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 text-center">
            <Zap className="w-5 h-5 mx-auto mb-1 text-yellow-500" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{currentWpm}</div>
            <div className="text-xs text-gray-500">WPM</div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 text-center">
            <Target className="w-5 h-5 mx-auto mb-1 text-green-500" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{accuracy.toFixed(1)}%</div>
            <div className="text-xs text-gray-500">Accuracy</div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 text-center">
            <Zap className="w-5 h-5 mx-auto mb-1 text-orange-500" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{opponentWpm}</div>
            <div className="text-xs text-gray-500">Opponent WPM</div>
          </div>
        </motion.div>

        {/* Typing Area */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-4 sm:p-6"
        >
          {/* Text Display - optimized for mobile */}
          <div
            className="mb-4 sm:mb-6 p-3 sm:p-4 bg-gray-50 dark:bg-gray-900 rounded-lg font-mono text-sm sm:text-base md:text-lg leading-relaxed select-none overflow-y-auto max-h-40 sm:max-h-60"
            style={{ wordBreak: 'break-word' }}
          >
            {renderText()}
          </div>

          {/* Input Field */}
          <input
            ref={inputRef}
            type="text"
            value={userInput}
            onChange={handleInputChange}
            disabled={isComplete}
            className={`w-full p-4 text-lg font-mono border-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors > 0
                ? 'border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20'
                : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'
            } ${isComplete ? 'opacity-50 cursor-not-allowed' : ''}`}
            placeholder={isComplete ? 'Round complete!' : 'Start typing...'}
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />

          {/* No corrections warning */}
          {!allowBackspace && !isComplete && (
            <div className="mt-2 text-xs text-yellow-600 dark:text-yellow-400 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              <span>Corrections disabled - mistakes are permanent</span>
            </div>
          )}

          {/* Status Messages */}
          <AnimatePresence>
            {isComplete && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 p-4 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded-lg text-center"
              >
                Round complete! Waiting for results...
              </motion.div>
            )}

            {opponentFinished && !isComplete && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 p-4 bg-orange-50 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded-lg text-center"
              >
                Opponent has finished! Keep going!
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Forfeit Button */}
        <div className="mt-6 text-center">
          <button
            onClick={handleForfeit}
            className="text-red-500 hover:text-red-700 text-sm font-medium"
          >
            Forfeit Match
          </button>
        </div>
      </div>
    </div>
  );
};

export default PVPGameInterface;
