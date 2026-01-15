// frontend/src/plugins/tutorials/services/tutorialApi.ts
/**
 * Tutorial API Service
 * Handles all HTTP requests to tutorial endpoints
 */
import axios from 'axios';
import type {
  TutorialCategory,
  TutorialListItem,
  TutorialDetail,
  TutorialProgress,
  CompleteStepResponse,
  TutorialAnalytics,
  TutorialCreate,
  TutorialUpdate,
  TutorialFilters,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8100';
const TUTORIAL_BASE = `${API_BASE}/api/v1/tutorials`;

// Create axios instance with credentials
const api = axios.create({
  baseURL: TUTORIAL_BASE,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ============================================================================
// PUBLIC ENDPOINTS - Tutorial Browsing
// ============================================================================

/**
 * Get all tutorial categories
 */
export async function getTutorialCategories(): Promise<TutorialCategory[]> {
  const response = await api.get('/categories');
  return response.data;
}

/**
 * Get all published tutorials with optional filtering
 */
export async function getTutorials(
  filters?: TutorialFilters
): Promise<TutorialListItem[]> {
  const params = new URLSearchParams();

  if (filters?.category_id) params.append('category_id', filters.category_id.toString());
  if (filters?.difficulty) params.append('difficulty', filters.difficulty);
  if (filters?.search) params.append('search', filters.search);
  if (filters?.is_featured !== undefined && filters.is_featured !== null) params.append('is_featured', filters.is_featured.toString());
  if (filters?.skip) params.append('skip', filters.skip.toString());
  if (filters?.limit) params.append('limit', filters.limit.toString());

  const response = await api.get('', { params });
  return response.data;
}

/**
 * Get featured tutorials
 */
export async function getFeaturedTutorials(limit: number = 5): Promise<TutorialListItem[]> {
  const response = await api.get('/featured', {
    params: { limit },
  });
  return response.data;
}

/**
 * Get popular tutorials by view count
 */
export async function getPopularTutorials(limit: number = 10): Promise<TutorialListItem[]> {
  const response = await api.get('/popular', {
    params: { limit },
  });
  return response.data;
}

/**
 * Get tutorial by slug (with all steps)
 */
export async function getTutorialBySlug(slug: string): Promise<TutorialDetail> {
  const response = await api.get(`/${slug}`);
  return response.data;
}

// ============================================================================
// USER PROGRESS ENDPOINTS - Authenticated Users
// ============================================================================

/**
 * Start a tutorial (or resume if already started)
 */
export async function startTutorial(tutorialId: number): Promise<TutorialProgress> {
  const response = await api.post(`/${tutorialId}/start`);
  return response.data;
}

/**
 * Mark a tutorial step as complete
 */
export async function completeStep(
  tutorialId: number,
  stepId: number
): Promise<CompleteStepResponse> {
  const response = await api.post(`/${tutorialId}/steps/${stepId}/complete`);
  return response.data;
}

/**
 * Get all tutorial progress for current user
 */
export async function getMyTutorialProgress(
  status?: 'in_progress' | 'completed'
): Promise<TutorialProgress[]> {
  const params = status ? { status } : {};
  const response = await api.get('/progress/my-tutorials', { params });
  return response.data;
}

// ============================================================================
// ADMIN ENDPOINTS - Tutorial Management
// ============================================================================

/**
 * Create new tutorial (admin only)
 */
export async function createTutorial(
  tutorial: TutorialCreate
): Promise<TutorialDetail> {
  const response = await api.post('/admin/tutorials', tutorial);
  return response.data;
}

/**
 * Get all tutorials including unpublished (admin only)
 */
export async function getAllTutorialsAdmin(
  filters?: TutorialFilters & { is_published?: boolean }
): Promise<TutorialListItem[]> {
  const params = new URLSearchParams();

  if (filters?.category_id) params.append('category_id', filters.category_id.toString());
  if (filters?.difficulty) params.append('difficulty', filters.difficulty);
  if (filters?.is_published !== undefined) params.append('is_published', filters.is_published.toString());
  if (filters?.search) params.append('search', filters.search);
  if (filters?.skip) params.append('skip', filters.skip.toString());
  if (filters?.limit) params.append('limit', filters.limit.toString());

  const response = await api.get('/admin/tutorials', { params });
  return response.data;
}

/**
 * Update tutorial (admin only)
 */
export async function updateTutorial(
  tutorialId: number,
  updates: TutorialUpdate
): Promise<TutorialDetail> {
  const response = await api.put(`/admin/tutorials/${tutorialId}`, updates);
  return response.data;
}

/**
 * Delete tutorial (admin only)
 */
export async function deleteTutorial(tutorialId: number): Promise<void> {
  await api.delete(`/admin/tutorials/${tutorialId}`);
}

/**
 * Create tutorial step (admin only)
 */
export async function createTutorialStep(
  tutorialId: number,
  step: {
    step_order: number;
    title: string;
    content?: string;
    code_example?: string;
    code_language?: string;
    hints?: string[];
  }
): Promise<any> {
  const response = await api.post(`/admin/tutorials/${tutorialId}/steps`, step);
  return response.data;
}

/**
 * Update tutorial step (admin only)
 */
export async function updateTutorialStep(
  tutorialId: number,
  stepId: number,
  updates: {
    step_order?: number;
    title?: string;
    content?: string;
    code_example?: string;
    code_language?: string;
    hints?: string[];
  }
): Promise<any> {
  const response = await api.put(`/admin/tutorials/${tutorialId}/steps/${stepId}`, updates);
  return response.data;
}

/**
 * Delete tutorial step (admin only)
 */
export async function deleteTutorialStep(
  tutorialId: number,
  stepId: number
): Promise<void> {
  await api.delete(`/admin/tutorials/${tutorialId}/steps/${stepId}`);
}

/**
 * Create tutorial category (admin only)
 */
export async function createTutorialCategory(category: {
  name: string;
  slug: string;
  description?: string;
  icon?: string;
  color?: string;
}): Promise<TutorialCategory> {
  const response = await api.post('/admin/categories', category);
  return response.data;
}

/**
 * Update tutorial category (admin only)
 */
export async function updateTutorialCategory(
  categoryId: number,
  updates: {
    name?: string;
    slug?: string;
    description?: string;
    icon?: string;
    color?: string;
    display_order?: number;
  }
): Promise<TutorialCategory> {
  const response = await api.put(`/admin/categories/${categoryId}`, updates);
  return response.data;
}

/**
 * Delete tutorial category (admin only)
 */
export async function deleteTutorialCategory(categoryId: number): Promise<void> {
  await api.delete(`/admin/categories/${categoryId}`);
}

/**
 * Get tutorial analytics (admin only)
 */
export async function getTutorialAnalytics(
  tutorialId: number
): Promise<TutorialAnalytics> {
  const response = await api.get(`/admin/tutorials/${tutorialId}/analytics`);
  return response.data;
}
