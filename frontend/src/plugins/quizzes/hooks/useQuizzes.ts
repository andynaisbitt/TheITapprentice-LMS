// frontend/src/plugins/quizzes/hooks/useQuizzes.ts
/**
 * Quiz Plugin Data Hooks
 */
import { useState, useEffect, useCallback } from 'react';
import { api } from '../../../api/client';
import type {
  Quiz,
  QuizSummary,
  QuizAttempt,
  QuizAttemptResult,
  UserQuizStats,
  QuizLeaderboard,
  QuizAdminResponse,
  QuizCreateInput,
  QuizSubmitInput,
  QuizDifficulty,
} from '../types';

const API_BASE = '/api/v1/quizzes';

// ============== Public Hooks ==============

interface UseQuizzesOptions {
  category?: string;
  difficulty?: QuizDifficulty;
  skip?: number;
  limit?: number;
}

export function useQuizzes(options: UseQuizzesOptions = {}) {
  const [quizzes, setQuizzes] = useState<QuizSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchQuizzes = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (options.category) params.append('category', options.category);
      if (options.difficulty) params.append('difficulty', options.difficulty);
      if (options.skip) params.append('skip', options.skip.toString());
      if (options.limit) params.append('limit', options.limit.toString());

      const response = await api.get(`${API_BASE}/?${params.toString()}`);
      setQuizzes(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load quizzes');
    } finally {
      setLoading(false);
    }
  }, [options.category, options.difficulty, options.skip, options.limit]);

  useEffect(() => {
    fetchQuizzes();
  }, [fetchQuizzes]);

  return { quizzes, loading, error, refetch: fetchQuizzes };
}

export function useFeaturedQuizzes(limit: number = 6) {
  const [quizzes, setQuizzes] = useState<QuizSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFeatured = async () => {
      try {
        const response = await api.get(`${API_BASE}/featured?limit=${limit}`);
        setQuizzes(response.data);
      } catch (err) {
        console.error('Failed to load featured quizzes:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchFeatured();
  }, [limit]);

  return { quizzes, loading };
}

export function useQuiz(quizId: string | undefined) {
  const [quiz, setQuiz] = useState<Quiz | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!quizId) {
      setLoading(false);
      return;
    }

    const fetchQuiz = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await api.get(`${API_BASE}/${quizId}`);
        setQuiz(response.data);
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to load quiz');
      } finally {
        setLoading(false);
      }
    };
    fetchQuiz();
  }, [quizId]);

  return { quiz, loading, error };
}

export function useQuizLeaderboard(quizId: string | undefined, limit: number = 10) {
  const [leaderboard, setLeaderboard] = useState<QuizLeaderboard | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!quizId) {
      setLoading(false);
      return;
    }

    const fetchLeaderboard = async () => {
      try {
        const response = await api.get(`${API_BASE}/${quizId}/leaderboard?limit=${limit}`);
        setLeaderboard(response.data);
      } catch (err) {
        console.error('Failed to load leaderboard:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchLeaderboard();
  }, [quizId, limit]);

  return { leaderboard, loading };
}

// ============== User Attempt Hooks ==============

export function useMyAttempts(quizId?: string) {
  const [attempts, setAttempts] = useState<QuizAttempt[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAttempts = useCallback(async () => {
    setLoading(true);
    try {
      const params = quizId ? `?quiz_id=${quizId}` : '';
      const response = await api.get(`${API_BASE}/attempts/me${params}`);
      setAttempts(response.data);
    } catch (err) {
      console.error('Failed to load attempts:', err);
    } finally {
      setLoading(false);
    }
  }, [quizId]);

  useEffect(() => {
    fetchAttempts();
  }, [fetchAttempts]);

  return { attempts, loading, refetch: fetchAttempts };
}

export function useMyQuizStats() {
  const [stats, setStats] = useState<UserQuizStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await api.get(`${API_BASE}/stats/me`);
        setStats(response.data);
      } catch (err) {
        console.error('Failed to load quiz stats:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  return { stats, loading };
}

// ============== Quiz Taking Functions ==============

export async function startQuizAttempt(quizId: string): Promise<QuizAttempt> {
  const response = await api.post(`${API_BASE}/${quizId}/start`);
  return response.data;
}

export async function submitQuizAttempt(
  quizId: string,
  submission: QuizSubmitInput
): Promise<QuizAttemptResult> {
  const response = await api.post(`${API_BASE}/${quizId}/submit`, submission);
  return response.data;
}

// ============== Admin Hooks ==============

interface UseAdminQuizzesOptions {
  status?: string;
  search?: string;
  skip?: number;
  limit?: number;
}

export function useAdminQuizzes(options: UseAdminQuizzesOptions = {}) {
  const [quizzes, setQuizzes] = useState<QuizAdminResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchQuizzes = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (options.status) params.append('status', options.status);
      if (options.search) params.append('search', options.search);
      if (options.skip) params.append('skip', options.skip.toString());
      if (options.limit) params.append('limit', (options.limit || 50).toString());

      const response = await api.get(`${API_BASE}/admin/all?${params.toString()}`);
      setQuizzes(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load quizzes');
    } finally {
      setLoading(false);
    }
  }, [options.status, options.search, options.skip, options.limit]);

  useEffect(() => {
    fetchQuizzes();
  }, [fetchQuizzes]);

  return { quizzes, loading, error, refetch: fetchQuizzes };
}

export function useAdminQuiz(quizId: string | undefined) {
  const [quiz, setQuiz] = useState<QuizAdminResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchQuiz = useCallback(async () => {
    if (!quizId) {
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const response = await api.get(`${API_BASE}/admin/${quizId}`);
      setQuiz(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load quiz');
    } finally {
      setLoading(false);
    }
  }, [quizId]);

  useEffect(() => {
    fetchQuiz();
  }, [fetchQuiz]);

  return { quiz, loading, error, refetch: fetchQuiz };
}

// ============== Admin CRUD Functions ==============

export async function createQuiz(quizData: QuizCreateInput): Promise<QuizAdminResponse> {
  const response = await api.post(`${API_BASE}/admin`, quizData);
  return response.data;
}

export async function updateQuiz(
  quizId: string,
  quizData: Partial<QuizCreateInput>
): Promise<QuizAdminResponse> {
  const response = await api.put(`${API_BASE}/admin/${quizId}`, quizData);
  return response.data;
}

export async function deleteQuiz(quizId: string): Promise<void> {
  await api.delete(`${API_BASE}/admin/${quizId}`);
}

export async function addQuestion(
  quizId: string,
  questionData: any
): Promise<any> {
  const response = await api.post(`${API_BASE}/admin/${quizId}/questions`, questionData);
  return response.data;
}

export async function updateQuestion(
  questionId: number,
  questionData: any
): Promise<any> {
  const response = await api.put(`${API_BASE}/admin/questions/${questionId}`, questionData);
  return response.data;
}

export async function deleteQuestion(questionId: number): Promise<void> {
  await api.delete(`${API_BASE}/admin/questions/${questionId}`);
}

export async function reorderQuestions(
  quizId: string,
  questionOrder: number[]
): Promise<void> {
  await api.post(`${API_BASE}/admin/${quizId}/questions/reorder`, questionOrder);
}
