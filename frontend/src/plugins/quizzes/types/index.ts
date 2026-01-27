// frontend/src/plugins/quizzes/types/index.ts
/**
 * Quiz Plugin Type Definitions
 */

export type QuestionType =
  | 'multiple_choice'
  | 'multiple_select'
  | 'true_false'
  | 'short_answer'
  | 'code'
  | 'fill_blank';

export type QuizDifficulty = 'easy' | 'medium' | 'hard' | 'expert';

export type QuizStatus = 'draft' | 'published' | 'archived';

export interface QuestionOption {
  id: string;
  text: string;
  is_correct?: boolean; // Only available in admin view
}

export interface QuizQuestion {
  id: number;
  question_type: QuestionType;
  question_text: string;
  question_html?: string;
  options: QuestionOption[];
  code_language?: string;
  code_template?: string;
  points: number;
  order_index: number;
  image_url?: string;
  // Admin only fields
  correct_answer?: any;
  explanation?: string;
}

export interface QuizSummary {
  id: string;
  title: string;
  description?: string;
  category?: string;
  difficulty: QuizDifficulty;
  time_limit_minutes?: number;
  passing_score: number;
  question_count: number;
  xp_reward: number;
  status: QuizStatus;
  is_featured: boolean;
  total_attempts: number;
  avg_score: number;
  pass_rate: number;
  related_skills: string[];
  created_at: string;
}

export interface Quiz extends QuizSummary {
  instructions?: string;
  tags: string[];
  max_attempts: number;
  question_order: 'sequential' | 'random';
  show_answers_after: boolean;
  allow_review: boolean;
  xp_perfect: number;
  questions: QuizQuestion[];
}

export interface QuizAdminResponse extends Quiz {
  course_id?: string;
  module_id?: string;
  created_by?: number;
  updated_at: string;
  published_at?: string;
}

export interface QuizAttempt {
  id: number;
  quiz_id: string;
  user_id: number;
  attempt_number: number;
  score: number;
  max_score: number;
  percentage: number;
  passed: boolean;
  time_taken_seconds?: number;
  started_at: string;
  completed_at?: string;
  is_complete: boolean;
  xp_awarded: number;
}

export interface QuestionResult {
  question_id: number;
  correct: boolean;
  points_earned: number;
  user_answer: any;
  correct_answer?: any;
  explanation?: string;
}

export interface QuizAttemptResult extends QuizAttempt {
  question_results: QuestionResult[];
  quiz_title: string;
  show_answers: boolean;
}

export interface UserQuizStats {
  total_attempts: number;
  quizzes_passed: number;
  quizzes_failed: number;
  average_score: number;
  best_score: number;
  total_xp_earned: number;
  recent_attempts: QuizAttempt[];
}

export interface QuizLeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  display_name?: string;
  best_score: number;
  attempts: number;
  best_time?: number;
}

export interface QuizLeaderboard {
  quiz_id: string;
  quiz_title: string;
  entries: QuizLeaderboardEntry[];
  total_participants: number;
}

// Form types for creating/updating
export interface QuizCreateInput {
  id: string;
  title: string;
  description?: string;
  instructions?: string;
  category?: string;
  tags?: string[];
  difficulty?: QuizDifficulty;
  time_limit_minutes?: number;
  passing_score?: number;
  max_attempts?: number;
  question_order?: 'sequential' | 'random';
  show_answers_after?: boolean;
  allow_review?: boolean;
  xp_reward?: number;
  xp_perfect?: number;
  course_id?: string;
  module_id?: string;
  status?: QuizStatus;
  is_featured?: boolean;
  related_skills?: string[];
  questions?: QuestionCreateInput[];
}

export interface QuestionCreateInput {
  question_type: QuestionType;
  question_text: string;
  question_html?: string;
  options?: QuestionOption[];
  correct_answer: any;
  explanation?: string;
  code_language?: string;
  code_template?: string;
  points?: number;
  order_index?: number;
  image_url?: string;
}

export interface QuizSubmitInput {
  answers: Record<string, any>;
}
