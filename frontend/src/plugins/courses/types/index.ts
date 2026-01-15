// src/state/types/course.types.ts
/**
 * Course Types with Content Block System
 * Matches backend models for flexible course creation
 */

import { ReactNode } from 'react';

// ============================================================================
// ENUMS - Match backend exactly
// ============================================================================

export type CourseLevel = 'beginner' | 'intermediate' | 'advanced';
export type CourseStatus = 'draft' | 'published' | 'archived';
export type SectionType = 'theory' | 'practice' | 'quiz' | 'challenge' | 'video' | 'exercise';
export type SectionStatus = 'locked' | 'available' | 'in-progress' | 'completed';
export type EnrollmentStatus = 'active' | 'completed' | 'dropped';

// Content Block Types (10 types)
export type ContentBlockType = 
  | 'text' 
  | 'heading'
  | 'quiz' 
  | 'video' 
  | 'code' 
  | 'image' 
  | 'callout' 
  | 'timeline'
  | 'interactive'
  | 'divider';

// Question Types (6 types)
export type QuestionType = 
  | 'multiple_choice' 
  | 'multiple_select'
  | 'true_false' 
  | 'short_answer' 
  | 'code_challenge'
  | 'fill_blank';

// ============================================================================
// CONTENT BLOCK DEFINITIONS
// ============================================================================

export interface TextBlockContent {
  text: string;
  format?: 'plain' | 'markdown' | 'html';
}

export interface HeadingBlockContent {
  text: string;
  level: 1 | 2 | 3 | 4 | 5 | 6;
}

export interface QuizQuestion {
  id: string;
  type: QuestionType;
  question: string;
  options?: string[];
  correct_answer: string | string[];
  explanation?: string;
  points: number;
  code_snippet?: string;
  language?: string;
}

export interface QuizBlockContent {
  questions: QuizQuestion[];
  passing_score?: number;
  max_attempts?: number;
  shuffle_questions?: boolean;
  shuffle_options?: boolean;
}

export interface VideoBlockContent {
  url: string;
  provider: 'youtube' | 'vimeo' | 'direct';
  thumbnail?: string;
  duration?: number;
  caption?: string;
}

export interface CodeBlockContent {
  code: string;
  language: string;
  filename?: string;
  highlights?: number[];
  runnable?: boolean;
  editable?: boolean;
}

export interface ImageBlockContent {
  url: string;
  alt: string;
  caption?: string;
  width?: number;
  height?: number;
}

export interface CalloutBlockContent {
  type: 'info' | 'warning' | 'success' | 'error' | 'tip';
  title?: string;
  content: string;
}

export interface TimelineItem {
  id: string;
  title: string;
  date?: string;
  description: string;
  icon?: string;
}

export interface TimelineBlockContent {
  items: TimelineItem[];
  orientation?: 'vertical' | 'horizontal';
}

export interface InteractiveBlockContent {
  component_name: string;
  props?: Record<string, any>;
  iframe_url?: string;
}

export interface DividerBlockContent {
  style?: 'solid' | 'dashed' | 'dotted';
  spacing?: 'small' | 'medium' | 'large';
}

// Union type for all content types
export type BlockContent = 
  | TextBlockContent 
  | HeadingBlockContent
  | QuizBlockContent 
  | VideoBlockContent 
  | CodeBlockContent 
  | ImageBlockContent 
  | CalloutBlockContent
  | TimelineBlockContent
  | InteractiveBlockContent
  | DividerBlockContent;

// ============================================================================
// CONTENT BLOCK
// ============================================================================

export interface ContentBlock {
  id?: string;
  type: ContentBlockType;
  content: BlockContent;
  order: number;
  metadata?: Record<string, any>;
}

// ============================================================================
// COURSE STRUCTURE (Matches Backend)
// ============================================================================

export interface Course {
  id: string;
  title: string;
  description: string;
  short_description?: string;
  image?: string;
  preview_video_url?: string;
  level: CourseLevel;
  category?: string; // Legacy field (kept for backwards compatibility)
  category_id?: number | null; // Global category ID
  skills?: string[];
  tags?: string[];
  duration?: string;
  estimated_hours: number;
  requirements?: string[];
  objectives?: string[];
  instructor_id: number;
  instructor_name?: string;
  status: CourseStatus;
  is_featured: boolean;
  is_premium: boolean;
  price: number;
  currency: string;
  enrollment_count: number;
  completion_count: number;
  difficulty_rating: number;
  created_at: string;
  updated_at: string;
  published_at?: string;
  modules?: CourseModule[];
  related_skills?: string[];  // Skills that receive XP on completion
  xp_reward?: number;  // Manual XP override (null = auto-calculate)
}

export interface CourseModule {
  id: string;
  course_id: string;
  title: string;
  description?: string;
  duration?: string;
  estimated_minutes: number;
  order_index: number;
  prerequisites?: string[];
  component?: string;
  difficulty_level: number;
  status: SectionStatus;
  created_at: string;
  updated_at: string;
  sections?: ModuleSection[];
}

export interface ModuleSection {
  id: string;
  module_id: string;
  title: string;
  description?: string;
  time_estimate?: string;
  type: SectionType;
  content_blocks: ContentBlock[];
  order_index: number;
  points: number;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// ENROLLMENT & PROGRESS
// ============================================================================

export interface CourseEnrollment {
  id: number;
  user_id: number;
  course_id: string;
  progress: number;
  current_module_id?: string;
  completed_modules?: string[];
  status: EnrollmentStatus;
  is_complete: boolean;
  bookmarks?: string[];
  notes?: Record<string, string>;
  time_spent: number;
  achievements?: string[];
  enrolled_at: string;
  started_at?: string;
  completed_at?: string;
  last_accessed?: string;
}

export interface ModuleProgress {
  id: number;
  enrollment_id: number;
  module_id: string;
  completed: boolean;
  completed_at?: string;
  time_spent: number;
  last_position?: string;
  completed_sections?: string[];
  quiz_scores?: Record<string, number>;
  attempts: number;
  bookmarked: boolean;
  notes?: string;
  started_at: string;
  last_accessed?: string;
}

// ============================================================================
// API REQUEST/RESPONSE TYPES
// ============================================================================

export interface CourseListResponse {
  courses: Course[];
  total: number;
  page: number;
  page_size: number;
}

export interface CourseFilters {
  level?: CourseLevel;
  category?: string;
  status?: CourseStatus;
  is_featured?: boolean;
  is_premium?: boolean;
  search?: string;
  page?: number;
  page_size?: number;
}

export interface CreateCourseRequest {
  id: string;
  title: string;
  description: string;
  short_description?: string;
  level: CourseLevel;
  category?: string;
  skills?: string[];
  tags?: string[];
  estimated_hours?: number;
  requirements?: string[];
  objectives?: string[];
  is_premium?: boolean;
  price?: number;
}

export interface UpdateCourseRequest extends Partial<CreateCourseRequest> {
  status?: CourseStatus;
  is_featured?: boolean;
}

export interface CreateModuleRequest {
  id: string;
  title: string;
  description?: string;
  duration?: string;
  estimated_minutes?: number;
  order_index: number;
  prerequisites?: string[];
}

export interface CreateSectionRequest {
  id: string;
  title: string;
  description?: string;
  time_estimate?: string;
  type: SectionType;
  content_blocks: ContentBlock[];
  order_index: number;
  points?: number;
}

export interface UpdateSectionRequest extends Partial<CreateSectionRequest> {}

export interface EnrollmentRequest {
  course_id: string;
}

export interface ProgressUpdateRequest {
  completed_sections?: string[];
  time_spent?: number;
  completed?: boolean;
  last_position?: string;
  quiz_scores?: Record<string, number>;
  notes?: string;
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

export interface BulkCourseCreate {
  course: CreateCourseRequest;
  modules: (CreateModuleRequest & {
    sections: CreateSectionRequest[];
  })[];
}

// ============================================================================
// UI/COMPONENT TYPES (Legacy - keeping for backward compatibility)
// ============================================================================

export interface CourseSection {
  id: string;
  title: string;
  type: SectionType;
  status: SectionStatus;
  duration: number;
  points: number;
  prerequisites?: string[];
  content?: ReactNode;
}

export interface SectionCompletion {
  completed: boolean;
  timestamp: string;
  score?: number;
  timeSpent: number;
}

export interface CourseProgress {
  moduleId: string;
  progress: number;
  currentSection: string;
  completedSections: string[];
  sectionProgress: Record<string, SectionCompletion>;
  earnedPoints: number;
  timeSpent: number;
  lastAccessed: string;
  assessmentScores: Record<string, number>;
}

export interface ModuleState {
  completedSections: string[];
  currentSectionIndex: number;
  earnedPoints: number;
  timeSpent: number;
  lastAccessed: string;
  isCompleted: boolean;
}

export interface ComponentProps {
  onComplete: () => void;
  isCompleted?: boolean;
}

export interface QuizProps extends ComponentProps {
  question: string;
  options: string[];
  correctAnswer: string;
  explanation: string;
}

export interface CourseState {
  courses: Record<string, CourseProgress>;
  activeModule?: string;
  activeSection?: string;
}

export type CourseAction =
  | { type: 'INIT_COURSE'; payload: { courseId: string } }
  | { 
      type: 'UPDATE_PROGRESS'; 
      payload: { 
        courseId: string; 
        progress: Partial<CourseProgress> 
      } 
    }
  | { 
      type: 'COMPLETE_SECTION'; 
      payload: { 
        courseId: string; 
        sectionId: string;
        completion: SectionCompletion;
      } 
    }
  | { 
      type: 'COMPLETE_MODULE'; 
      payload: { 
        courseId: string; 
        moduleId: string;
        finalScore: number;
      } 
    }
  | {
      type: 'SET_ACTIVE_SECTION';
      payload: {
        courseId: string;
        moduleId: string;
        sectionId: string;
      }
    }
  | {
      type: 'UPDATE_SECTION_PROGRESS';
      payload: {
        courseId: string;
        sectionId: string;
        progress: Partial<SectionCompletion>;
      }
    };

export interface ModuleLayoutProps {
  moduleId: number;
  title: string;
  description: string;
  sections: CourseSection[];
  children: ReactNode;
  onComplete: () => void;
  progress: {
    completedSections: string[];
    currentSection: string;
    earnedPoints: number;
    totalPoints: number;
    timeSpent: number;
  };
  onNextSection?: () => void;
  onPrevSection?: () => void;
}

export interface AIComponentProps extends ComponentProps {
  title?: string;
  description?: string;
  showProgress?: boolean;
  minTimeRequired?: number;
}

export interface InteractiveComponentProps extends AIComponentProps {
  onInteraction?: () => void;
  requiredInteractions?: number;
}

export interface ExerciseProps extends InteractiveComponentProps {
  exerciseData: any;
  validateSolution: (solution: any) => boolean;
  onSubmit: (solution: any) => void;
}

// ============================================================================
// CONTENT BLOCK TEMPLATES (For Admin UI)
// ============================================================================

export interface ContentBlockTemplate {
  type: ContentBlockType;
  name: string;
  description: string;
  icon: string;
  defaultContent: BlockContent;
}

export const CONTENT_BLOCK_TEMPLATES: ContentBlockTemplate[] = [
  {
    type: 'text',
    name: 'Text Block',
    description: 'Rich text content with markdown support',
    icon: '📝',
    defaultContent: {
      text: 'Enter your text here...',
      format: 'markdown'
    } as TextBlockContent
  },
  {
    type: 'heading',
    name: 'Heading',
    description: 'Section heading (H1-H6)',
    icon: '📌',
    defaultContent: {
      text: 'Section Heading',
      level: 2
    } as HeadingBlockContent
  },
  {
    type: 'quiz',
    name: 'Quiz',
    description: 'Interactive quiz with multiple question types',
    icon: '❓',
    defaultContent: {
      questions: [],
      passing_score: 70,
      max_attempts: 3
    } as QuizBlockContent
  },
  {
    type: 'video',
    name: 'Video',
    description: 'Embedded video (YouTube, Vimeo, or direct)',
    icon: '🎥',
    defaultContent: {
      url: '',
      provider: 'youtube'
    } as VideoBlockContent
  },
  {
    type: 'code',
    name: 'Code Block',
    description: 'Syntax-highlighted code with optional execution',
    icon: '💻',
    defaultContent: {
      code: '// Your code here',
      language: 'javascript',
      runnable: false,
      editable: false
    } as CodeBlockContent
  },
  {
    type: 'image',
    name: 'Image',
    description: 'Image with optional caption',
    icon: '🖼️',
    defaultContent: {
      url: '',
      alt: 'Image description'
    } as ImageBlockContent
  },
  {
    type: 'callout',
    name: 'Callout',
    description: 'Highlighted callout box (info, warning, tip, etc.)',
    icon: '💡',
    defaultContent: {
      type: 'info',
      title: 'Note',
      content: 'Important information goes here'
    } as CalloutBlockContent
  },
  {
    type: 'timeline',
    name: 'Timeline',
    description: 'Visual timeline of events or steps',
    icon: '📅',
    defaultContent: {
      items: [],
      orientation: 'vertical'
    } as TimelineBlockContent
  },
  {
    type: 'interactive',
    name: 'Interactive Component',
    description: 'Custom interactive React component',
    icon: '🎮',
    defaultContent: {
      component_name: '',
      props: {}
    } as InteractiveBlockContent
  },
  {
    type: 'divider',
    name: 'Divider',
    description: 'Visual separator between sections',
    icon: '➖',
    defaultContent: {
      style: 'solid',
      spacing: 'medium'
    } as DividerBlockContent
  }
];