// frontend/src/plugins/shared/types/index.ts
/**
 * Shared types for XP, Achievements, and Progress systems
 */

// ============== XP Types ==============

export interface LevelProgress {
  level: number;
  total_xp: number;
  xp_for_current_level: number;
  xp_in_current_level: number;
  xp_for_next_level: number;
  progress_percent: number;
  xp_to_next_level: number;
}

export interface XPLeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  display_name?: string;
  total_xp: number;
  level: number;
  streak: number;
}

export interface XPAwardResponse {
  xp_awarded: number;
  total_xp: number;
  old_level: number;
  new_level: number;
  level_up: boolean;
  action: string;
  reason?: string;
}

// ============== Achievement Types ==============

export type AchievementCategory = 'tutorials' | 'courses' | 'typing' | 'social' | 'streak' | 'special';
export type AchievementRarity = 'common' | 'uncommon' | 'rare' | 'epic' | 'legendary';

export interface UnlockCondition {
  type: 'count' | 'value' | 'streak' | 'special';
  action?: string;
  count?: number;
  metric?: string;
  operator?: '>=' | '>' | '==' | '<' | '<=';
  value?: number;
  days?: number;
  trigger?: string;
}

export interface Achievement {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: AchievementCategory;
  rarity: AchievementRarity;
  xp_reward: number;
  unlock_condition: UnlockCondition;
  is_hidden: boolean;
  is_active: boolean;
  sort_order: number;
  created_at: string;
  updated_at: string;
  unlock_count?: number;
}

export interface AchievementProgress {
  achievement_id: string;
  name: string;
  description: string;
  icon: string;
  category: AchievementCategory;
  rarity: AchievementRarity;
  xp_reward?: number;
  is_unlocked: boolean;
  unlocked_at?: string;
  progress: number;
  progress_max: number;
  progress_percent: number;
}

export interface AchievementUnlock {
  achievement_id: string;
  name: string;
  description: string;
  icon: string;
  rarity: AchievementRarity;
  xp_reward: number;
  unlocked_at: string;
  is_new: boolean;
}

// ============== Activity Types ==============

export type ActivityType =
  | 'tutorial_start'
  | 'tutorial_step'
  | 'tutorial_complete'
  | 'course_enroll'
  | 'lesson_complete'
  | 'module_complete'
  | 'course_complete'
  | 'typing_game'
  | 'typing_pvp'
  | 'achievement_unlock'
  | 'level_up'
  | 'streak_milestone'
  | 'login';

export interface Activity {
  id: number;
  user_id: number;
  activity_type: ActivityType;
  reference_type?: string;
  reference_id?: string;
  title: string;
  metadata?: Record<string, unknown>;
  xp_earned: number;
  created_at: string;
}

export interface ActivityTimeline {
  activities: Activity[];
  total: number;
  has_more: boolean;
}

// ============== Dashboard Types ==============

export interface UserStats {
  total_xp: number;
  level: number;
  level_progress: LevelProgress;
  level_title?: string;
  current_streak: number;
  longest_streak?: number;
  tutorials_completed: number;
  courses_completed: number;
  typing_games_played: number;
  achievements_unlocked: number;
  best_wpm?: number;
  avg_accuracy?: number;
  xp_rank?: number;
  typing_rank?: number;
}

export interface InProgressItem {
  type: 'tutorial' | 'course';
  id: number | string;
  title: string;
  progress_percent: number;
  last_accessed: string;
}

export interface DashboardData {
  stats: UserStats;
  recent_achievements: AchievementUnlock[];
  recent_activities: Activity[];
  in_progress: InProgressItem[];
  suggested_content: Record<string, unknown>[];
}

// ============== Level Config Types ==============

export interface LevelConfig {
  id: number;
  level: number;
  xp_required: number;
  title?: string;
  badge_color?: string;
  perks?: string[];
  created_at: string;
  updated_at: string;
}

// ============== Admin Types ==============

export interface AchievementStats {
  total_achievements: number;
  active_achievements: number;
  total_unlocks: number;
  unlocks_today: number;
  most_unlocked: Array<{
    id: string;
    name: string;
    unlock_count: number;
  }>;
  rarest_unlocked: Array<{
    id: string;
    name: string;
    rarity: AchievementRarity;
    unlock_count: number;
  }>;
}

export interface CreateAchievementInput {
  id: string;
  name: string;
  description: string;
  icon?: string;
  category: AchievementCategory;
  rarity?: AchievementRarity;
  xp_reward?: number;
  unlock_condition: UnlockCondition;
  is_hidden?: boolean;
  is_active?: boolean;
  sort_order?: number;
}

export interface UpdateAchievementInput {
  name?: string;
  description?: string;
  icon?: string;
  category?: AchievementCategory;
  rarity?: AchievementRarity;
  xp_reward?: number;
  unlock_condition?: UnlockCondition;
  is_hidden?: boolean;
  is_active?: boolean;
  sort_order?: number;
}

// ============== Utility Types ==============

export const RARITY_COLORS: Record<AchievementRarity, string> = {
  common: 'bg-gray-100 text-gray-700 border-gray-300',
  uncommon: 'bg-green-100 text-green-700 border-green-300',
  rare: 'bg-blue-100 text-blue-700 border-blue-300',
  epic: 'bg-purple-100 text-purple-700 border-purple-300',
  legendary: 'bg-yellow-100 text-yellow-700 border-yellow-300',
};

export const RARITY_COLORS_DARK: Record<AchievementRarity, string> = {
  common: 'dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600',
  uncommon: 'dark:bg-green-900/50 dark:text-green-400 dark:border-green-700',
  rare: 'dark:bg-blue-900/50 dark:text-blue-400 dark:border-blue-700',
  epic: 'dark:bg-purple-900/50 dark:text-purple-400 dark:border-purple-700',
  legendary: 'dark:bg-yellow-900/50 dark:text-yellow-400 dark:border-yellow-700',
};

export const CATEGORY_ICONS: Record<AchievementCategory, string> = {
  tutorials: 'book-open',
  courses: 'graduation-cap',
  typing: 'keyboard',
  social: 'users',
  streak: 'flame',
  special: 'star',
};
