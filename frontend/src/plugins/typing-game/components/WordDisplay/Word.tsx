// frontend/src/plugins/typing-game/components/WordDisplay/Word.tsx
/**
 * Individual Word Component - Enhanced with micro-interactions
 *
 * Renders a single word with character-level highlighting:
 * - Correct characters: green with subtle pulse
 * - Incorrect characters: red with shake animation
 * - Extra characters: red (typed beyond word length)
 * - Pending characters: gray
 * - Current character: highlighted cursor position
 */

import React, { useRef, useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { CharacterState } from '../../hooks/useTypingEngine';

type WordStatus = 'pending' | 'current' | 'completed' | 'skipped';

interface WordProps {
  word: string;
  status: WordStatus;
  isCorrect: boolean;
  characterStates: CharacterState[];
  isCurrent: boolean;
  typedValue: string;
}

export const Word: React.FC<WordProps> = ({
  word,
  status,
  isCorrect,
  characterStates,
  isCurrent,
  typedValue,
}) => {
  const [shaking, setShaking] = useState(false);
  const [lastCorrectIndex, setLastCorrectIndex] = useState(-1);
  const prevTypedLenRef = useRef(0);

  // Detect errors for shake effect
  useEffect(() => {
    if (!isCurrent) return;

    const currentLen = typedValue.length;
    const prevLen = prevTypedLenRef.current;
    prevTypedLenRef.current = currentLen;

    // Only check on new character (not backspace)
    if (currentLen > prevLen && currentLen > 0) {
      const lastCharIndex = currentLen - 1;
      const charState = characterStates[lastCharIndex];

      if (charState && (charState.status === 'incorrect' || charState.status === 'extra')) {
        // Trigger shake on error
        setShaking(true);
        setTimeout(() => setShaking(false), 200);
      } else if (charState && charState.status === 'correct') {
        setLastCorrectIndex(lastCharIndex);
      }
    }
  }, [typedValue, isCurrent, characterStates]);

  // Determine word wrapper styles based on status
  const getWordClasses = () => {
    const base = 'inline-flex font-mono text-base sm:text-lg md:text-xl lg:text-2xl rounded px-0.5 sm:px-1 transition-all duration-200';

    switch (status) {
      case 'completed':
        return `${base} ${
          isCorrect
            ? 'bg-green-100/50 dark:bg-green-900/20'
            : 'bg-red-100/50 dark:bg-red-900/20'
        }`;
      case 'current':
        return `${base} bg-blue-100/50 dark:bg-blue-900/30 ring-2 ring-blue-400 dark:ring-blue-500`;
      case 'skipped':
        return `${base} bg-orange-100/50 dark:bg-orange-900/20 opacity-60`;
      case 'pending':
      default:
        return `${base} opacity-60`;
    }
  };

  // Get character styling
  const getCharacterClasses = (charState: CharacterState, index: number) => {
    const isCursor = isCurrent && index === typedValue.length;

    const base = 'relative transition-colors duration-75';

    // Cursor position styling
    const cursorClass = isCursor
      ? 'after:absolute after:left-0 after:bottom-0 after:w-full after:h-0.5 after:bg-blue-500 after:animate-pulse'
      : '';

    switch (charState.status) {
      case 'correct':
        return `${base} ${cursorClass} text-green-600 dark:text-green-400`;
      case 'incorrect':
        return `${base} ${cursorClass} text-red-600 dark:text-red-400 bg-red-200 dark:bg-red-900/50 rounded`;
      case 'extra':
        return `${base} ${cursorClass} text-red-500 dark:text-red-400 bg-red-200 dark:bg-red-900/50 rounded line-through`;
      case 'pending':
      default:
        return `${base} ${cursorClass} text-gray-400 dark:text-gray-500`;
    }
  };

  // Render completed word with final state
  if (status === 'completed' || status === 'skipped') {
    return (
      <motion.span
        className={getWordClasses()}
        initial={{ scale: 1 }}
        animate={{ scale: [1, 0.98, 1], opacity: [1, 0.8, 0.9] }}
        transition={{ duration: 0.3 }}
      >
        {characterStates.map((charState, index) => (
          <span
            key={index}
            className={getCharacterClasses(charState, index)}
          >
            {charState.char}
          </span>
        ))}
        {/* Show lock icon for completed words */}
        <AnimatePresence>
          {status === 'completed' && (
            <motion.span
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: 0.5, scale: 1 }}
              exit={{ opacity: 0, scale: 0 }}
              className="ml-1 text-xs"
            >
              {isCorrect ? '✓' : '✗'}
            </motion.span>
          )}
        </AnimatePresence>
      </motion.span>
    );
  }

  // Shake animation styles
  const shakeStyle = shaking
    ? { animation: 'word-shake 0.2s ease-in-out' }
    : {};

  // Render current or pending word with live character states
  return (
    <>
      {/* Inject shake keyframes */}
      {shaking && (
        <style>{`
          @keyframes word-shake {
            0%, 100% { transform: translateX(0); }
            20% { transform: translateX(-3px); }
            40% { transform: translateX(3px); }
            60% { transform: translateX(-2px); }
            80% { transform: translateX(2px); }
          }
        `}</style>
      )}
      <span className={getWordClasses()} style={shakeStyle}>
        {characterStates.map((charState, index) => {
          const isCursorPos = isCurrent && index === typedValue.length;
          const justTypedCorrect = isCurrent && index === lastCorrectIndex && charState.status === 'correct';

          return (
            <motion.span
              key={index}
              className={`${getCharacterClasses(charState, index)} ${
                isCursorPos ? 'relative' : ''
              }`}
              animate={
                justTypedCorrect
                  ? { scale: [1, 1.15, 1] }
                  : charState.status === 'incorrect'
                  ? { scale: [1, 0.95, 1] }
                  : {}
              }
              transition={{ duration: 0.12 }}
            >
              {charState.char}
              {/* Blinking cursor */}
              {isCursorPos && (
                <motion.span
                  className="absolute -bottom-0.5 left-0 w-full h-1 bg-blue-500 rounded-full"
                  initial={{ opacity: 1 }}
                  animate={{ opacity: [1, 0.3, 1] }}
                  transition={{ duration: 0.8, repeat: Infinity }}
                />
              )}
            </motion.span>
          );
        })}
        {/* Show extra typed characters (beyond word length) */}
        {isCurrent && typedValue.length > word.length && (
          <>
            {typedValue.slice(word.length).split('').map((char, i) => (
              <motion.span
                key={`extra-${i}`}
                className="text-red-500 dark:text-red-400 bg-red-200 dark:bg-red-900/50 rounded"
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.1 }}
              >
                {char}
              </motion.span>
            ))}
          </>
        )}
        {/* Cursor at end of word */}
        {isCurrent && typedValue.length >= word.length && (
          <motion.span
            className="inline-block w-0.5 h-6 bg-blue-500 ml-0.5 rounded-full"
            initial={{ opacity: 1 }}
            animate={{ opacity: [1, 0.3, 1] }}
            transition={{ duration: 0.8, repeat: Infinity }}
          />
        )}
      </span>
    </>
  );
};

export default Word;
