// src/services/api/types.ts
/**
 * TypeScript interfaces for API requests and responses
 */

// ============================================================================
// USER & AUTH TYPES
// ============================================================================

export interface User {
  id: number;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  avatar_url?: string;
  bio?: string;
  google_id?: string;
  
  // Role & status
  role: 'STUDENT' | 'VOLUNTEER' | 'INSTRUCTOR' | 'ADMIN';
  is_admin: boolean;
  is_active: boolean;
  is_verified: boolean;
  
  // Subscription
  subscription_status: 'FREE' | 'ACTIVE' | 'CANCELLED' | 'EXPIRED' | 'PAST_DUE';
  subscription_plan?: 'BASIC' | 'PRO' | 'ENTERPRISE';
  subscription_expires?: string;
  
  // Gamification
  total_points: number;
  level: number;
  
  // Timestamps
  created_at: string;
  last_login?: string;
}

export interface LoginCredentials {
  username: string; // email
  password: string;
}

export interface LoginResponse {
  message: string;
  user: User;
  csrf_token: string;
  access_token: string; // JWT token for WebSocket authentication
  token_type: string;
}

export interface UserStats {
  total_points: number;
  level: number;
  courses_enrolled: number;
  courses_completed: number;
  quizzes_taken: number;
  achievements_earned: number;
  current_streak: number;
  total_time_minutes: number;
}

export interface ProfileUpdate {
  first_name?: string;
  last_name?: string;
  bio?: string;
  avatar_url?: string;
}

export interface PasswordChange {
  current_password: string;
  new_password: string;
}

// ============================================================================
// CATEGORY TYPES
// ============================================================================

export interface Category {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  parent_id: number | null;
  color: string;
  icon: string | null;
  meta_title: string | null;
  meta_description: string | null;
  display_order: number;
  created_at: string;
  updated_at: string | null;
  post_count?: number;
}

export interface CategoryCreate {
  name: string;
  description?: string;
  parent_id?: number;
  color?: string;
  icon?: string;
  meta_title?: string;
  meta_description?: string;
}

export interface CategoryUpdate {
  name?: string;
  description?: string;
  parent_id?: number;
  color?: string;
  icon?: string;
  meta_title?: string;
  meta_description?: string;
  display_order?: number;
}

// ============================================================================
// GLOBAL CATEGORY TYPES (Unified system for all content types)
// ============================================================================

export type ContentType = 'courses' | 'tutorials' | 'quizzes' | 'games' | 'typing-challenges' | 'blog';

export interface GlobalCategorySimple {
  id: number;
  slug: string;
  name: string;
  icon: string | null;
  color: string;
}

export interface GlobalCategory {
  id: number;
  slug: string;
  name: string;
  description: string | null;
  parent_id: number | null;
  applies_to: ContentType[];
  icon: string | null;
  color: string;
  display_order: number;
  meta_title: string | null;
  meta_description: string | null;
  is_active: boolean;
  usage_count: number;
  created_at: string;
  updated_at: string | null;
}

export interface GlobalCategoryWithChildren extends GlobalCategory {
  children: GlobalCategory[];
}

export interface GlobalCategoryContentCounts {
  category_id: number;
  course_count: number;
  tutorial_count: number;
  quiz_count: number;
  game_count: number;
  typing_challenge_count: number;
  blog_post_count: number;
  total_count: number;
}

export interface GlobalCategoryCreate {
  slug: string;
  name: string;
  description?: string;
  parent_id?: number;
  applies_to: ContentType[];
  icon?: string;
  color?: string;
  display_order?: number;
  meta_title?: string;
  meta_description?: string;
  is_active?: boolean;
}

export interface GlobalCategoryUpdate {
  slug?: string;
  name?: string;
  description?: string;
  parent_id?: number;
  applies_to?: ContentType[];
  icon?: string;
  color?: string;
  display_order?: number;
  meta_title?: string;
  meta_description?: string;
  is_active?: boolean;
}

export interface GlobalCategoryListResponse {
  categories: GlobalCategory[];
  total: number;
  page: number;
  page_size: number;
}

export interface GlobalCategoryTreeResponse {
  categories: GlobalCategoryWithChildren[];
  total: number;
}

export interface GlobalCategoryReorder {
  category_orders: Array<{ id: number; display_order: number }>;
}

export interface GlobalCategoryBulkDelete {
  category_ids: number[];
}

// ============================================================================
// TAG TYPES
// ============================================================================

export interface Tag {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  color: string;
  created_at: string;
  post_count?: number;
}

export interface TagCreate {
  name: string;
  description?: string;
  color?: string;
}

export interface TagUpdate {
  name?: string;
  description?: string;
  color?: string;
}

// ============================================================================
// MEDIA TYPES
// ============================================================================

export interface Media {
  id: number;
  filename: string;
  original_filename: string;
  file_url: string;
  file_size: number;
  mime_type: string;
  width: number | null;
  height: number | null;
  alt_text: string | null;
  caption: string | null;
  uploaded_by: number | null;
  created_at: string;
}

export interface MediaUpdate {
  alt_text?: string;
  caption?: string;
}

export interface MediaListResponse {
  media: Media[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// ============================================================================
// BLOG POST TYPES
// ============================================================================

export interface BlogPost {
  id: number;
  title: string;
  slug: string;
  content: string;
  excerpt: string;
  meta_title: string;
  meta_description: string;
  meta_keywords: string;
  canonical_url: string | null;
  featured_image: string | null | undefined;
  featured_image_alt: string | null;
  featured_image_caption: string | null;
  published: boolean;
  published_at: string | null;
  scheduled_for: string | null;
  is_featured: boolean;
  allow_comments: boolean;
  author_id: number;
  author?: User;
  view_count: number;
  read_time_minutes: number;
  category?: Category; // Single category for legacy compatibility
  tags: Tag[];
  categories: Category[];
  created_at: string;
  updated_at: string;
}

export interface BlogPostCreate {
  title: string;
  content: string;
  slug?: string;
  excerpt?: string;
  meta_title?: string;
  meta_description?: string;
  meta_keywords?: string;
  canonical_url?: string;
  featured_image?: string;
  featured_image_alt?: string;
  featured_image_caption?: string;
  published?: boolean;
  scheduled_for?: string;
  is_featured?: boolean;
  allow_comments?: boolean;
  tag_ids?: number[];
  category_ids?: number[];
}

export interface BlogPostUpdate {
  title?: string;
  content?: string;
  slug?: string;
  excerpt?: string;
  meta_title?: string;
  meta_description?: string;
  meta_keywords?: string;
  canonical_url?: string;
  featured_image?: string;
  featured_image_alt?: string;
  featured_image_caption?: string;
  published?: boolean;
  scheduled_for?: string;
  is_featured?: boolean;
  allow_comments?: boolean;
  tag_ids?: number[];
  category_ids?: number[];
}

export interface BlogPostListResponse {
  posts: BlogPost[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface BlogPostFilters {
  page?: number;
  page_size?: number;
  per_page?: number; // Alternative name for page_size
  search?: string;
  category?: string; // Category slug or name
  category_id?: number;
  tag?: string;
  published?: boolean;
  is_featured?: boolean;
  featured_only?: boolean;
  sort_by?: 'created_at' | 'published_at' | 'view_count' | 'title';
  sort_order?: 'asc' | 'desc';
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

export interface BulkPostUpdate {
  post_ids: number[];
  published?: boolean;
  is_featured?: boolean;
  category_ids?: number[];
  tag_ids?: number[];
}

export interface BulkUpdateResponse {
  message: string;
  updated_count: number;
}