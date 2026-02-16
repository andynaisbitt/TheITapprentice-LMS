// frontend/src/plugins/skills/types/index.ts
/**
 * Skill System Types
 * OSRS-style skill progression with 12 IT skills
 */

// Skill tier definitions
export type SkillTier = 'Novice' | 'Apprentice' | 'Journeyman' | 'Expert' | 'Master' | 'Grandmaster';

export interface TierInfo {
  name: SkillTier;
  minLevel: number;
  maxLevel: number;
  color: string;
}

// Skill categories
export type SkillCategory = 'foundation' | 'systems' | 'development' | 'cloud_security';

// Core skill definition
export interface Skill {
  id: number;
  name: string;
  slug: string;
  description: string;
  icon: string;
  category: SkillCategory;
  color: string;
  displayOrder: number;
  isActive: boolean;
}

// User's progress on a skill
export interface UserSkillProgress {
  skillId: number;
  skillName: string;
  skillSlug: string;
  skillIcon: string;
  skillCategory: string;
  currentXp: number;
  currentLevel: number;
  xpToNextLevel: number;
  xpForNextLevel: number;
  xpProgressPercentage: number;
  totalActivitiesCompleted: number;
  lastActivityAt: string | null;
  tier: SkillTier;
  tierColor: string;
  // Milestone achievements
  level10Achieved: boolean;
  level30Achieved: boolean;
  level50Achieved: boolean;
  level75Achieved: boolean;
  level99Achieved: boolean;
}

// Overview of all user skills
export interface UserSkillsOverview {
  skills: UserSkillProgress[];
  totalLevel: number;
  maxTotalLevel: number;
  itLevel: number;
  maxItLevel: number;
  specialization: string;
  specializationPath: string;
  averageLevel: number;
  totalXp: number;
  skillsAt99: number;
  skillsAt50Plus: number;
}

// XP gain response from server
export interface SkillXPGainResponse {
  skillSlug: string;
  skillName: string;
  xpGained: number;
  totalXp: number;
  oldLevel: number;
  newLevel: number;
  levelUp: boolean;
  newTier?: SkillTier;
  tierChanged?: boolean;
  achievementsUnlocked?: string[];
}

// XP log entry
export interface SkillXPLogEntry {
  id: string;
  skillId: number;
  skillName: string;
  skillSlug: string;
  xpGained: number;
  sourceType: 'tutorial' | 'course' | 'quiz' | 'typing_game' | 'achievement' | 'manual';
  sourceId?: string;
  sourceMetadata?: Record<string, unknown>;
  levelBefore: number;
  levelAfter: number;
  createdAt: string;
}

// Leaderboard entry
export interface SkillLeaderboardEntry {
  rank: number;
  userId: number;
  username: string;
  avatarUrl?: string;
  level: number;
  xp: number;
  tier: SkillTier;
  tierColor: string;
}

export interface SkillLeaderboard {
  skillSlug: string;
  skillName: string;
  entries: SkillLeaderboardEntry[];
  totalParticipants: number;
  userRank?: number;
}

// Global leaderboard (IT Level)
export interface GlobalLeaderboardEntry {
  rank: number;
  userId: number;
  username: string;
  avatarUrl?: string;
  itLevel: number;
  totalLevel: number;
  totalXp: number;
  specialization: string;
  skillsAt99: number;
}

export interface GlobalLeaderboard {
  entries: GlobalLeaderboardEntry[];
  totalParticipants: number;
  userRank?: number;
}

// XP calculator response
export interface XPCalculatorResponse {
  level: number;
  totalXpRequired: number;
  tier: SkillTier;
  tierColor: string;
  xpToNextLevel: number;
  progressInTier: number;
}

// All tiers response
export interface TiersResponse {
  tiers: TierInfo[];
}

// Skill activities (linked content)
export interface SkillActivityItem {
  id: string;
  title: string;
  description: string | null;
  activityType: 'course' | 'quiz' | 'tutorial' | 'typing_practice';
  difficulty: string | null;
  xpReward: number;
  url: string;
  estimatedTime: string | null;
  category: string | null;
}

export interface SkillActivitiesResponse {
  skillSlug: string;
  skillName: string;
  courses: SkillActivityItem[];
  quizzes: SkillActivityItem[];
  tutorials: SkillActivityItem[];
  typingPractice: SkillActivityItem[];
  totalCount: number;
}

// API response wrappers
export interface SkillsListResponse {
  skills: Skill[];
  totalCount: number;
}
