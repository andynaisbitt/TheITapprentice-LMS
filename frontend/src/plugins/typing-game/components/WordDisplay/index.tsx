// frontend/src/plugins/typing-game/components/WordDisplay/index.tsx
/**
 * Word-by-Word Display Component
 *
 * Renders text as individual words with status-based styling:
 * - Completed words: locked, green (correct) or red (incorrect)
 * - Current word: active with character highlighting
 * - Pending words: grayed out
 */

import React, { useRef, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Word } from './Word';
import type { WordState, CharacterState } from '../../hooks/useTypingEngine';

const WORDS_PER_LINE = 8;

interface WordDisplayProps {
  words: WordState[];
  currentWordIndex: number;
  currentInput: string;
  getCharacterStates: (wordIndex: number) => CharacterState[];
  onContainerClick?: () => void;
  className?: string;
  wordsPerLine?: number;
}

export const WordDisplay: React.FC<WordDisplayProps> = ({
  words,
  currentWordIndex,
  currentInput,
  getCharacterStates,
  onContainerClick,
  className = '',
  wordsPerLine = WORDS_PER_LINE,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const currentWordRef = useRef<HTMLDivElement>(null);

  // Group words into lines for cleaner visual layout
  const lines = useMemo(() => {
    const result: WordState[][] = [];
    for (let i = 0; i < words.length; i += wordsPerLine) {
      result.push(words.slice(i, i + wordsPerLine));
    }
    return result;
  }, [words, wordsPerLine]);

  // Auto-scroll to keep current word visible
  useEffect(() => {
    if (currentWordRef.current && containerRef.current) {
      const container = containerRef.current;
      const word = currentWordRef.current;

      const wordTop = word.offsetTop;
      const wordBottom = wordTop + word.offsetHeight;
      const containerScrollTop = container.scrollTop;
      const containerHeight = container.clientHeight;

      // Scroll if word is out of view
      if (wordTop < containerScrollTop + 20) {
        container.scrollTo({
          top: Math.max(0, wordTop - 20),
          behavior: 'smooth',
        });
      } else if (wordBottom > containerScrollTop + containerHeight - 20) {
        container.scrollTo({
          top: wordBottom - containerHeight + 20,
          behavior: 'smooth',
        });
      }
    }
  }, [currentWordIndex]);

  return (
    <motion.div
      ref={containerRef}
      onClick={onContainerClick}
      className={`
        relative overflow-y-auto overflow-x-hidden
        bg-gray-50 dark:bg-gray-900/80
        rounded-xl p-4 sm:p-6 md:p-8
        min-h-[120px] sm:min-h-[140px] md:min-h-[160px]
        max-h-[200px] sm:max-h-[250px] md:max-h-[320px]
        cursor-text select-none
        border-2 border-gray-200 dark:border-gray-700
        transition-all duration-200
        focus-within:border-blue-500 dark:focus-within:border-blue-400
        focus-within:shadow-lg focus-within:shadow-blue-500/10
        touch-manipulation
        ${className}
      `}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      role="textbox"
      aria-label="Type the words shown"
    >
      <div className="space-y-2 sm:space-y-2.5 md:space-y-3 pb-2">
        {lines.map((lineWords, lineIndex) => (
          <div
            key={lineIndex}
            className="flex flex-wrap gap-x-1.5 gap-y-1 sm:gap-x-2 md:gap-x-3 leading-relaxed"
          >
            {lineWords.map((wordState) => {
              const isCurrent = wordState.index === currentWordIndex;
              const characterStates = getCharacterStates(wordState.index);

              return (
                <div
                  key={wordState.index}
                  ref={isCurrent ? currentWordRef : undefined}
                >
                  <Word
                    word={wordState.word}
                    status={wordState.status}
                    isCorrect={wordState.isCorrect}
                    characterStates={characterStates}
                    isCurrent={isCurrent}
                    typedValue={isCurrent ? currentInput : wordState.typedValue}
                  />
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* Progress indicator */}
      <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-200 dark:bg-gray-700 rounded-b-xl overflow-hidden">
        <motion.div
          className="h-full bg-gradient-to-r from-blue-500 to-purple-500"
          initial={{ width: 0 }}
          animate={{ width: `${(currentWordIndex / words.length) * 100}%` }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
        />
      </div>
    </motion.div>
  );
};

export default WordDisplay;
