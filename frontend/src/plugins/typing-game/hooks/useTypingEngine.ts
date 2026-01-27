// frontend/src/plugins/typing-game/hooks/useTypingEngine.ts
/**
 * Core Word-by-Word Typing Engine
 *
 * Key mechanics:
 * - Text is split into words
 * - Space key finalizes current word and advances to next
 * - Backspace only works within current word (cannot go back to previous words)
 * - Completed words are locked
 * - Real-time WPM, accuracy, and error tracking
 */

import { useState, useCallback, useRef, useEffect, useMemo } from 'react';

// ==================== TYPES ====================

export interface WordState {
  word: string;
  index: number;
  status: 'pending' | 'current' | 'completed' | 'skipped';
  typedValue: string;
  isCorrect: boolean;
  startTime?: number;
  endTime?: number;
  characterStates: CharacterState[];
}

export interface CharacterState {
  char: string;
  status: 'pending' | 'correct' | 'incorrect' | 'extra';
  typedChar?: string;
}

export interface TypingEngineConfig {
  onWordComplete?: (wordIndex: number, isCorrect: boolean, wpm: number) => void;
  onGameComplete?: (stats: TypingStats) => void;
  onError?: (wordIndex: number, charIndex: number, expected: string, actual: string) => void;
  onKeystroke?: (keystrokeData: KeystrokeData) => void;
}

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

export interface KeystrokeData {
  key: string;
  timestamp: number;
  interKeyTime: number;
  wordIndex: number;
  charIndex: number;
  isCorrect: boolean;
  expected: string;
}

export interface TypingEngineState {
  status: 'idle' | 'ready' | 'playing' | 'paused' | 'completed';
  words: WordState[];
  currentWordIndex: number;
  currentInput: string;
  stats: TypingStats;
  combo: number;
  maxCombo: number;
}

// ==================== HOOK ====================

export function useTypingEngine(text: string, config: TypingEngineConfig = {}) {
  const { onWordComplete, onGameComplete, onError, onKeystroke } = config;

  // Parse text into words
  const words = useMemo(() => text.trim().split(/\s+/), [text]);

  // State
  const [status, setStatus] = useState<TypingEngineState['status']>('idle');
  const [wordStates, setWordStates] = useState<WordState[]>([]);
  const [currentWordIndex, setCurrentWordIndex] = useState(0);
  const [currentInput, setCurrentInput] = useState('');
  const [combo, setCombo] = useState(0);
  const [maxCombo, setMaxCombo] = useState(0);

  // Timing refs
  const gameStartTime = useRef<number | null>(null);
  const lastKeystrokeTime = useRef<number | null>(null);
  const wordStartTime = useRef<number | null>(null);

  // Stats tracking
  const correctChars = useRef(0);
  const incorrectChars = useRef(0);
  const totalTypedChars = useRef(0);

  // Initialize word states when text changes
  useEffect(() => {
    const initialStates: WordState[] = words.map((word, index) => ({
      word,
      index,
      status: index === 0 ? 'current' : 'pending',
      typedValue: '',
      isCorrect: false,
      characterStates: word.split('').map(char => ({
        char,
        status: 'pending' as const,
        typedChar: undefined,
      })),
    }));

    setWordStates(initialStates);
    setCurrentWordIndex(0);
    setCurrentInput('');
    setCombo(0);
    setMaxCombo(0);
    correctChars.current = 0;
    incorrectChars.current = 0;
    totalTypedChars.current = 0;
    gameStartTime.current = null;
    lastKeystrokeTime.current = null;
    wordStartTime.current = null;
    setStatus('ready');
  }, [words]);

  // Calculate current stats
  const stats = useMemo((): TypingStats => {
    const timeElapsed = gameStartTime.current
      ? (Date.now() - gameStartTime.current) / 1000
      : 0;

    const completedWords = wordStates.filter(w => w.status === 'completed' || w.status === 'skipped');
    const correctWords = completedWords.filter(w => w.isCorrect).length;
    const incorrectWords = completedWords.filter(w => !w.isCorrect).length;

    // Standard WPM: (correct characters / 5) / minutes
    const minutes = timeElapsed / 60;
    const wpm = minutes > 0 ? Math.round((correctChars.current / 5) / minutes) : 0;

    // Raw WPM: all typed characters / 5 / minutes
    const rawWpm = minutes > 0 ? Math.round((totalTypedChars.current / 5) / minutes) : 0;

    // Accuracy: correct / total * 100
    const totalChars = correctChars.current + incorrectChars.current;
    const accuracy = totalChars > 0
      ? Math.round((correctChars.current / totalChars) * 100)
      : 100;

    return {
      wpm,
      rawWpm,
      accuracy,
      correctChars: correctChars.current,
      incorrectChars: incorrectChars.current,
      totalChars,
      correctWords,
      incorrectWords,
      totalWords: words.length,
      timeElapsed,
      maxCombo,
    };
  }, [wordStates, maxCombo, words.length]);

  // Get character states for current word display
  const getCharacterStates = useCallback((wordIndex: number): CharacterState[] => {
    const wordState = wordStates[wordIndex];
    if (!wordState) return [];

    const targetWord = wordState.word;
    const typedValue = wordIndex === currentWordIndex ? currentInput : wordState.typedValue;

    const states: CharacterState[] = [];

    // Process each character in target word
    for (let i = 0; i < targetWord.length; i++) {
      const expectedChar = targetWord[i];
      const typedChar = typedValue[i];

      if (typedChar === undefined) {
        states.push({ char: expectedChar, status: 'pending' });
      } else if (typedChar === expectedChar) {
        states.push({ char: expectedChar, status: 'correct', typedChar });
      } else {
        states.push({ char: expectedChar, status: 'incorrect', typedChar });
      }
    }

    // Add extra characters (typed beyond word length)
    for (let i = targetWord.length; i < typedValue.length; i++) {
      states.push({ char: typedValue[i], status: 'extra', typedChar: typedValue[i] });
    }

    return states;
  }, [wordStates, currentWordIndex, currentInput]);

  // Handle key press
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    // Prevent default for special keys we handle
    if (e.key === 'Tab') {
      e.preventDefault();
      return;
    }

    // Start game on first keystroke
    if (status === 'ready') {
      gameStartTime.current = Date.now();
      wordStartTime.current = Date.now();
      setStatus('playing');
    }

    if (status !== 'playing' && status !== 'ready') return;

    const now = Date.now();
    const interKeyTime = lastKeystrokeTime.current ? now - lastKeystrokeTime.current : 0;
    lastKeystrokeTime.current = now;

    const currentWord = words[currentWordIndex];
    if (!currentWord) return;

    // Handle space - finalize current word
    if (e.key === ' ') {
      e.preventDefault();

      // Don't allow empty words (must type something)
      if (currentInput.length === 0) return;

      finalizeCurrentWord();
      return;
    }

    // Handle backspace - only within current word
    if (e.key === 'Backspace') {
      if (currentInput.length > 0) {
        setCurrentInput(prev => prev.slice(0, -1));
      }
      // Cannot backspace to previous words - this is intentional
      return;
    }

    // Ignore modifier keys
    if (e.key.length > 1 && !['Enter'].includes(e.key)) {
      return;
    }

    // Handle Enter as space for final word
    if (e.key === 'Enter') {
      if (currentWordIndex === words.length - 1 && currentInput.length > 0) {
        finalizeCurrentWord();
      }
      return;
    }

    // Regular character input
    const char = e.key;
    if (char.length === 1) {
      const expectedChar = currentWord[currentInput.length];
      const isCorrect = char === expectedChar;

      // Track keystroke
      totalTypedChars.current++;

      if (isCorrect) {
        correctChars.current++;
        setCombo(prev => {
          const newCombo = prev + 1;
          setMaxCombo(max => Math.max(max, newCombo));
          return newCombo;
        });
      } else {
        incorrectChars.current++;
        setCombo(0); // Break combo on error
        onError?.(currentWordIndex, currentInput.length, expectedChar || '', char);
      }

      // Report keystroke
      onKeystroke?.({
        key: char,
        timestamp: now,
        interKeyTime,
        wordIndex: currentWordIndex,
        charIndex: currentInput.length,
        isCorrect,
        expected: expectedChar || '',
      });

      setCurrentInput(prev => prev + char);
    }
  }, [status, currentWordIndex, currentInput, words, onError, onKeystroke]);

  // Finalize current word and advance
  const finalizeCurrentWord = useCallback(() => {
    const currentWord = words[currentWordIndex];
    const isCorrect = currentInput === currentWord;

    // Calculate word WPM
    const wordTime = wordStartTime.current
      ? (Date.now() - wordStartTime.current) / 1000
      : 0;
    const wordWpm = wordTime > 0
      ? Math.round((currentWord.length / 5) / (wordTime / 60))
      : 0;

    // Update word state
    setWordStates(prev => prev.map((ws, idx) => {
      if (idx === currentWordIndex) {
        return {
          ...ws,
          status: 'completed' as const,
          typedValue: currentInput,
          isCorrect,
          endTime: Date.now(),
        };
      }
      if (idx === currentWordIndex + 1) {
        return { ...ws, status: 'current' as const };
      }
      return ws;
    }));

    // Callback
    onWordComplete?.(currentWordIndex, isCorrect, wordWpm);

    // Move to next word or complete game
    if (currentWordIndex + 1 >= words.length) {
      // Game complete
      setStatus('completed');
      onGameComplete?.(stats);
    } else {
      // Advance to next word
      setCurrentWordIndex(prev => prev + 1);
      setCurrentInput('');
      wordStartTime.current = Date.now();
    }
  }, [currentWordIndex, currentInput, words, stats, onWordComplete, onGameComplete]);

  // Prevent paste
  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault();
    return false;
  }, []);

  // Reset the game
  const reset = useCallback(() => {
    const initialStates: WordState[] = words.map((word, index) => ({
      word,
      index,
      status: index === 0 ? 'current' : 'pending',
      typedValue: '',
      isCorrect: false,
      characterStates: word.split('').map(char => ({
        char,
        status: 'pending' as const,
        typedChar: undefined,
      })),
    }));

    setWordStates(initialStates);
    setCurrentWordIndex(0);
    setCurrentInput('');
    setCombo(0);
    setMaxCombo(0);
    correctChars.current = 0;
    incorrectChars.current = 0;
    totalTypedChars.current = 0;
    gameStartTime.current = null;
    lastKeystrokeTime.current = null;
    wordStartTime.current = null;
    setStatus('ready');
  }, [words]);

  // Start the game (can be called externally)
  const start = useCallback(() => {
    if (status === 'ready') {
      gameStartTime.current = Date.now();
      wordStartTime.current = Date.now();
      setStatus('playing');
    }
  }, [status]);

  // Pause the game
  const pause = useCallback(() => {
    if (status === 'playing') {
      setStatus('paused');
    }
  }, [status]);

  // Resume the game
  const resume = useCallback(() => {
    if (status === 'paused') {
      setStatus('playing');
    }
  }, [status]);

  return {
    // State
    status,
    wordStates,
    currentWordIndex,
    currentInput,
    stats,
    combo,
    maxCombo,

    // Computed
    words,
    currentWord: words[currentWordIndex] || '',
    isComplete: status === 'completed',
    progress: words.length > 0 ? (currentWordIndex / words.length) * 100 : 0,

    // Methods
    getCharacterStates,
    handleKeyDown,
    handlePaste,
    reset,
    start,
    pause,
    resume,

    // For input component
    inputProps: {
      value: currentInput,
      onKeyDown: handleKeyDown,
      onPaste: handlePaste,
      onChange: () => {}, // Controlled by onKeyDown
      autoComplete: 'off',
      autoCorrect: 'off',
      autoCapitalize: 'off',
      spellCheck: false,
    },
  };
}

export default useTypingEngine;
