// frontend/src/plugins/typing-game/hooks/useGameWords.ts
/**
 * Unified Word Loading Hook for Typing Games
 *
 * Supports three word loading strategies:
 * 1. Hardcoded - Static text pools (e.g., QuickBrownFoxGame)
 * 2. Backend - Fetch from API with word_list_id (e.g., WordListPracticeGame)
 * 3. Dynamic - Generate words on-the-fly (e.g., InfiniteRushGame)
 */

import { useState, useEffect, useCallback } from 'react';
import { typingGameApi } from '../services/typingGameApi';

// ==================== TYPES ====================

export type WordSource = 'hardcoded' | 'backend' | 'dynamic';

export interface HardcodedConfig {
  source: 'hardcoded';
  textPool: string[];
  selectionStrategy?: 'random' | 'sequential';
}

export interface BackendConfig {
  source: 'backend';
  wordListId?: string;
  mode?: 'challenge' | 'practice' | 'pvp';
  wordCount?: number;
  fallbackText?: string[];
}

export interface DynamicConfig {
  source: 'dynamic';
  generator: () => Promise<string[]> | string[];
  initialWordCount?: number;
  regenerateOnLow?: boolean;
  minWordThreshold?: number;
}

export type WordConfig = HardcodedConfig | BackendConfig | DynamicConfig;

export interface UseGameWordsReturn {
  text: string;
  words: string[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  loadMore: () => Promise<void>;
}

// ==================== HOOK ====================

/**
 * Load and manage words for typing games
 *
 * @param config - Word loading configuration
 * @returns Word management state and methods
 */
export function useGameWords(config: WordConfig): UseGameWordsReturn {
  const [text, setText] = useState('');
  const [words, setWords] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentIndex, setCurrentIndex] = useState(0);

  // ==================== HARDCODED SOURCE ====================

  const loadHardcoded = useCallback((cfg: HardcodedConfig) => {
    const { textPool, selectionStrategy = 'random' } = cfg;

    if (!textPool || textPool.length === 0) {
      setError('Empty text pool');
      setLoading(false);
      return;
    }

    let selectedText: string;

    if (selectionStrategy === 'sequential') {
      selectedText = textPool[currentIndex % textPool.length];
      setCurrentIndex(prev => prev + 1);
    } else {
      // Random selection
      selectedText = textPool[Math.floor(Math.random() * textPool.length)];
    }

    setText(selectedText);
    setWords(selectedText.trim().split(/\s+/));
    setError(null);
    setLoading(false);
  }, [currentIndex]);

  // ==================== BACKEND SOURCE ====================

  const loadBackend = useCallback(async (cfg: BackendConfig) => {
    const { wordListId, mode = 'practice', wordCount = 50, fallbackText } = cfg;

    try {
      setLoading(true);
      setError(null);

      const response = await typingGameApi.startGame({
        ...(wordListId ? { word_list_id: wordListId } : {}),
        mode,
        word_count: wordCount,
      });

      // Use backend text if available and reasonable
      if (response.text && response.text.trim().length > 10) {
        const backendText = response.text.trim();
        setText(backendText);
        setWords(backendText.split(/\s+/));
        setError(null);
      } else if (fallbackText && fallbackText.length > 0) {
        // Fall back to provided default text
        const fallback = fallbackText[Math.floor(Math.random() * fallbackText.length)];
        setText(fallback);
        setWords(fallback.trim().split(/\s+/));
        setError('Using fallback text (backend returned empty)');
      } else {
        throw new Error('Backend returned empty text and no fallback provided');
      }
    } catch (err: any) {
      console.error('Failed to load words from backend:', err);

      // Try fallback if provided
      if (fallbackText && fallbackText.length > 0) {
        const fallback = fallbackText[Math.floor(Math.random() * fallbackText.length)];
        setText(fallback);
        setWords(fallback.trim().split(/\s+/));
        setError(`Backend error: ${err.message || 'Failed to load'} - Using fallback`);
      } else {
        setError(err.message || 'Failed to load words');
        setText('');
        setWords([]);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // ==================== DYNAMIC SOURCE ====================

  const loadDynamic = useCallback(async (cfg: DynamicConfig) => {
    const { generator, initialWordCount = 50 } = cfg;

    try {
      setLoading(true);
      setError(null);

      const generatedWords = await generator();

      if (!generatedWords || generatedWords.length === 0) {
        throw new Error('Generator returned empty word list');
      }

      // Take requested number of words
      const selectedWords = generatedWords.slice(0, initialWordCount);
      const generatedText = selectedWords.join(' ');

      setText(generatedText);
      setWords(selectedWords);
      setError(null);
    } catch (err: any) {
      console.error('Failed to generate words:', err);
      setError(err.message || 'Failed to generate words');
      setText('');
      setWords([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // ==================== LOAD MORE (for dynamic/infinite modes) ====================

  const loadMore = useCallback(async () => {
    if (config.source !== 'dynamic') {
      console.warn('loadMore() only works with dynamic word source');
      return;
    }

    const cfg = config as DynamicConfig;

    try {
      const generatedWords = await cfg.generator();

      if (!generatedWords || generatedWords.length === 0) {
        console.warn('Generator returned empty word list');
        return;
      }

      // Append new words
      setWords(prev => [...prev, ...generatedWords]);
      setText(prev => prev + ' ' + generatedWords.join(' '));
    } catch (err: any) {
      console.error('Failed to load more words:', err);
    }
  }, [config]);

  // ==================== REFETCH ====================

  const refetch = useCallback(async () => {
    setCurrentIndex(0);

    switch (config.source) {
      case 'hardcoded':
        loadHardcoded(config);
        break;
      case 'backend':
        await loadBackend(config);
        break;
      case 'dynamic':
        await loadDynamic(config);
        break;
    }
  }, [config, loadHardcoded, loadBackend, loadDynamic]);

  // ==================== INITIAL LOAD ====================

  useEffect(() => {
    refetch();
  }, [refetch]);

  return {
    text,
    words,
    loading,
    error,
    refetch,
    loadMore,
  };
}

export default useGameWords;
