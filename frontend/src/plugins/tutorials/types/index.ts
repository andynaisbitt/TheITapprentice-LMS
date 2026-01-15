// frontend/src/plugins/tutorials/types/index.ts
/**
 * TypeScript types for Tutorial Plugin
 * Matches backend Pydantic schemas
 */

export type TutorialDifficulty = "beginner" | "intermediate" | "advanced";
export type TutorialProgressStatus = "in_progress" | "completed";

/**
 * Tutorial Category
 */
export interface TutorialCategory {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  icon: string | null;
  color: string | null;
  display_order: number;
  created_at: string;
}

/**
 * Tutorial Step
 */
export interface TutorialStep {
  id: number;
  tutorial_id: number;
  step_order: number;
  title: string;
  content: string | null;
  code_example: string | null;
  code_language: string | null;
  hints: string[];
  created_at: string;
}

/**
 * Tutorial List Item (for browse/search)
 */
export interface TutorialListItem {
  id: number;
  title: string;
  slug: string;
  description: string | null;
  difficulty: TutorialDifficulty;
  estimated_time_minutes: number | null;
  category_id: number | null;
  category: TutorialCategory | null;
  thumbnail_url: string | null;
  xp_reward: number;
  related_skills: string[];
  view_count: number;
  completion_count: number;
  is_published?: boolean; // Admin views include this
  is_featured?: boolean; // Admin views include this
  created_at: string;
  // User progress (if authenticated)
  user_progress_percentage?: number | null;
  user_completed?: boolean | null;
}

/**
 * Tutorial Detail (with steps)
 */
export interface TutorialDetail {
  id: number;
  title: string;
  slug: string;
  description: string | null;
  difficulty: TutorialDifficulty;
  estimated_time_minutes: number | null;
  category_id: number | null;
  thumbnail_url: string | null;
  xp_reward: number;
  related_skills: string[];
  author_id: number;
  is_published: boolean;
  is_featured: boolean;
  view_count: number;
  completion_count: number;
  created_at: string;
  updated_at: string;
  published_at: string | null;
  // Relationships
  category: TutorialCategory | null;
  steps: TutorialStep[];
  // User progress (if authenticated)
  user_progress?: {
    current_step_id: number | null;
    completed_step_ids: number[];
    progress_percentage: number;
    status: TutorialProgressStatus;
    time_spent_minutes: number;
  } | null;
}

/**
 * Tutorial Progress
 */
export interface TutorialProgress {
  id: number;
  user_id: number;
  tutorial_id: number;
  current_step_id: number | null;
  completed_step_ids: number[];
  status: TutorialProgressStatus;
  time_spent_minutes: number;
  started_at: string;
  last_accessed_at: string;
  completed_at: string | null;
  // Computed fields
  progress_percentage?: number | null;
  total_steps?: number | null;
}

/**
 * Response when completing a step
 */
export interface CompleteStepResponse {
  message: string;
  progress_percentage: number;
  tutorial_completed: boolean;
  xp_awarded: number | null;
  next_step_id: number | null;
}

/**
 * Tutorial Analytics (Admin)
 */
export interface TutorialAnalytics {
  tutorial_id: number;
  title: string;
  total_views: number;
  total_starts: number;
  total_completions: number;
  completion_rate: number;
  average_time_minutes: number | null;
  step_dropoff_rates: Array<{
    step_id: number;
    step_title: string;
    completions: number;
    dropoff_rate: number;
  }>;
}

/**
 * Tutorial Create/Update (Admin)
 */
export interface TutorialCreate {
  title: string;
  slug: string;
  description?: string | null;
  difficulty?: TutorialDifficulty;
  estimated_time_minutes?: number | null;
  category_id?: number | null;
  thumbnail_url?: string | null;
  xp_reward?: number;
  related_skills?: string[];
  is_published?: boolean;
  is_featured?: boolean;
  steps: Array<{
    step_order: number;
    title: string;
    content?: string | null;
    code_example?: string | null;
    code_language?: string | null;
    hints?: string[];
  }>;
}

export interface TutorialUpdate {
  title?: string;
  slug?: string;
  description?: string | null;
  difficulty?: TutorialDifficulty;
  estimated_time_minutes?: number | null;
  category_id?: number | null;
  thumbnail_url?: string | null;
  is_published?: boolean;
  is_featured?: boolean;
  xp_reward?: number;
  related_skills?: string[];
}

/**
 * Filters for tutorial search
 */
export interface TutorialFilters {
  category_id?: number | null;
  difficulty?: TutorialDifficulty | null;
  search?: string | null;
  is_featured?: boolean | null;
  skip?: number;
  limit?: number;
}
