// frontend/src/plugins/tutorials/hooks/useTutorials.ts
/**
 * React hooks for tutorial data fetching and state management
 */
import { useState, useEffect } from 'react';
import type {
  TutorialCategory,
  TutorialListItem,
  TutorialDetail,
  TutorialProgress,
  TutorialFilters,
} from '../types';
import * as tutorialApi from '../services/tutorialApi';

/**
 * Hook to fetch tutorial categories
 */
export function useTutorialCategories() {
  const [categories, setCategories] = useState<TutorialCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchCategories() {
      try {
        setLoading(true);
        const data = await tutorialApi.getTutorialCategories();
        setCategories(data);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to load categories');
      } finally {
        setLoading(false);
      }
    }

    fetchCategories();
  }, []);

  return { categories, loading, error };
}

/**
 * Hook to fetch tutorials with filters
 */
export function useTutorials(filters?: TutorialFilters) {
  const [tutorials, setTutorials] = useState<TutorialListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchTutorials() {
      try {
        setLoading(true);
        const data = await tutorialApi.getTutorials(filters);
        setTutorials(data);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to load tutorials');
      } finally {
        setLoading(false);
      }
    }

    fetchTutorials();
  }, [
    filters?.category_id,
    filters?.difficulty,
    filters?.search,
    filters?.is_featured,
    filters?.skip,
    filters?.limit,
  ]);

  return { tutorials, loading, error, refetch: () => setLoading(true) };
}

/**
 * Hook to fetch featured tutorials
 */
export function useFeaturedTutorials(limit: number = 5) {
  const [tutorials, setTutorials] = useState<TutorialListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchTutorials() {
      try {
        setLoading(true);
        const data = await tutorialApi.getFeaturedTutorials(limit);
        setTutorials(data);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to load featured tutorials');
      } finally {
        setLoading(false);
      }
    }

    fetchTutorials();
  }, [limit]);

  return { tutorials, loading, error };
}

/**
 * Hook to fetch a single tutorial by slug
 */
export function useTutorial(slug: string | undefined) {
  const [tutorial, setTutorial] = useState<TutorialDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!slug) {
      setTutorial(null);
      setLoading(false);
      return;
    }

    async function fetchTutorial() {
      try {
        setLoading(true);
        const data = await tutorialApi.getTutorialBySlug(slug!); // Non-null assertion since we checked above
        setTutorial(data);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to load tutorial');
        setTutorial(null);
      } finally {
        setLoading(false);
      }
    }

    fetchTutorial();
  }, [slug]);

  return { tutorial, loading, error, refetch: () => setLoading(true) };
}

/**
 * Hook to fetch user's tutorial progress
 */
export function useMyTutorialProgress(status?: 'in_progress' | 'completed') {
  const [progress, setProgress] = useState<TutorialProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchProgress() {
      try {
        setLoading(true);
        const data = await tutorialApi.getMyTutorialProgress(status);
        setProgress(data);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to load progress');
      } finally {
        setLoading(false);
      }
    }

    fetchProgress();
  }, [status]);

  return { progress, loading, error, refetch: () => setLoading(true) };
}

/**
 * Hook for tutorial progress actions (start, complete step)
 */
export function useTutorialProgress() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startTutorial = async (tutorialId: number) => {
    try {
      setLoading(true);
      setError(null);
      const progress = await tutorialApi.startTutorial(tutorialId);
      return progress;
    } catch (err: any) {
      setError(err.message || 'Failed to start tutorial');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const completeStep = async (tutorialId: number, stepId: number) => {
    try {
      setLoading(true);
      setError(null);
      const result = await tutorialApi.completeStep(tutorialId, stepId);
      return result;
    } catch (err: any) {
      setError(err.message || 'Failed to complete step');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { startTutorial, completeStep, loading, error };
}
