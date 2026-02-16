// frontend/src/plugins/skills/services/skillsApi.ts
/**
 * Skills API Service
 * Endpoints for skill progression, XP, and leaderboards
 */

import { apiClient } from '../../../services/api/client';
import type {
  Skill,
  UserSkillsOverview,
  SkillXPLogEntry,
  SkillLeaderboard,
  GlobalLeaderboard,
  XPCalculatorResponse,
  TiersResponse,
  SkillsListResponse,
  SkillActivitiesResponse,
  SkillActivityItem,
} from '../types';

const BASE_URL = '/api/v1/skills';

// Transform snake_case to camelCase
function transformSkillProgress(data: any): UserSkillsOverview {
  return {
    skills: data.skills.map((s: any) => ({
      skillId: s.skill_id,
      skillName: s.skill_name,
      skillSlug: s.skill_slug,
      skillIcon: s.skill_icon,
      skillCategory: s.skill_category,
      currentXp: s.current_xp,
      currentLevel: s.current_level,
      xpToNextLevel: s.xp_to_next_level,
      xpForNextLevel: s.xp_for_next_level,
      xpProgressPercentage: s.xp_progress_percentage,
      totalActivitiesCompleted: s.total_activities_completed,
      lastActivityAt: s.last_activity_at,
      tier: s.tier,
      tierColor: s.tier_color,
      level10Achieved: s.level_10_achieved,
      level30Achieved: s.level_30_achieved,
      level50Achieved: s.level_50_achieved,
      level75Achieved: s.level_75_achieved,
      level99Achieved: s.level_99_achieved,
    })),
    totalLevel: data.total_level,
    maxTotalLevel: data.max_total_level,
    itLevel: data.it_level,
    maxItLevel: data.max_it_level,
    specialization: data.specialization,
    specializationPath: data.specialization_path,
    averageLevel: data.average_level,
    totalXp: data.total_xp,
    skillsAt99: data.skills_at_99,
    skillsAt50Plus: data.skills_at_50_plus,
  };
}

function transformLeaderboardEntry(entry: any) {
  return {
    rank: entry.rank,
    userId: entry.user_id,
    username: entry.display_name || entry.username,
    avatarUrl: entry.avatar_url,
    level: entry.skill_level,
    xp: entry.skill_xp,
    tier: entry.tier || null,
    tierColor: entry.tier_color || '#6366f1',
  };
}

function transformGlobalLeaderboardEntry(entry: any) {
  return {
    rank: entry.rank,
    userId: entry.user_id,
    username: entry.username,
    avatarUrl: entry.avatar_url,
    itLevel: entry.it_level,
    totalLevel: entry.total_level,
    totalXp: entry.total_xp,
    specialization: entry.specialization,
    skillsAt99: entry.skills_at_99,
  };
}

export const skillsApi = {
  // ==================== Skills List ====================

  /**
   * Get all skills
   */
  async getAllSkills(): Promise<SkillsListResponse> {
    const response = await apiClient.get<any[]>(`${BASE_URL}/`);
    return {
      skills: response.data.map((s) => ({
        id: s.id,
        name: s.name,
        slug: s.slug,
        description: s.description,
        icon: s.icon,
        category: s.category,
        color: s.color,
        displayOrder: s.display_order,
        isActive: s.is_active,
      })),
      totalCount: response.data.length,
    };
  },

  /**
   * Get single skill by slug
   */
  async getSkill(slug: string): Promise<Skill> {
    const response = await apiClient.get<any>(`${BASE_URL}/slug/${slug}`);
    const s = response.data;
    return {
      id: s.id,
      name: s.name,
      slug: s.slug,
      description: s.description,
      icon: s.icon,
      category: s.category,
      color: s.color,
      displayOrder: s.display_order,
      isActive: s.is_active,
    };
  },

  // ==================== User Progress ====================

  /**
   * Get current user's skills overview
   */
  async getMySkills(): Promise<UserSkillsOverview> {
    const response = await apiClient.get<any>(`${BASE_URL}/me/overview`);
    return transformSkillProgress(response.data);
  },

  /**
   * Get another user's skills overview (public)
   */
  async getUserSkills(userId: number): Promise<UserSkillsOverview> {
    const response = await apiClient.get<any>(`${BASE_URL}/users/${userId}`);
    return transformSkillProgress(response.data);
  },

  /**
   * Get XP history for current user
   */
  async getMyXPHistory(
    skillSlug: string,
    limit: number = 20
  ): Promise<{ entries: SkillXPLogEntry[]; total: number }> {
    const response = await apiClient.get<any>(
      `${BASE_URL}/me/${skillSlug}/history?limit=${limit}`
    );
    return {
      entries: response.data.entries.map((e: any) => ({
        id: e.id,
        skillName: e.skill_name,
        skillSlug: e.skill_slug,
        xpGained: e.xp_gained,
        sourceType: e.source_type,
        sourceId: e.source_id,
        sourceMetadata: e.source_metadata,
        levelBefore: e.level_before,
        levelAfter: e.level_after,
        createdAt: e.earned_at,
      })),
      total: response.data.total_xp_gained,
    };
  },

  // ==================== Leaderboards ====================

  /**
   * Get leaderboard for a specific skill
   */
  async getSkillLeaderboard(
    skillSlug: string,
    limit: number = 100
  ): Promise<SkillLeaderboard> {
    const response = await apiClient.get<any>(
      `${BASE_URL}/${skillSlug}/leaderboard?limit=${limit}`
    );
    return {
      skillSlug: response.data.skill_slug,
      skillName: response.data.skill_name,
      entries: response.data.entries.map(transformLeaderboardEntry),
      totalParticipants: response.data.total_participants,
      userRank: response.data.user_rank,
    };
  },

  /**
   * Get global IT Level leaderboard
   */
  async getGlobalLeaderboard(limit: number = 100): Promise<GlobalLeaderboard> {
    const response = await apiClient.get<any>(
      `${BASE_URL}/leaderboards/global?limit=${limit}`
    );
    return {
      entries: response.data.entries.map(transformGlobalLeaderboardEntry),
      totalParticipants: response.data.total_participants,
      userRank: response.data.user_rank,
    };
  },

  // ==================== Skill Activities ====================

  /**
   * Get courses, quizzes, tutorials, and typing practice linked to a skill
   */
  async getSkillActivities(
    slug: string,
    limit: number = 5
  ): Promise<SkillActivitiesResponse> {
    const response = await apiClient.get<any>(
      `${BASE_URL}/slug/${slug}/activities?limit=${limit}`
    );
    const d = response.data;
    const transformItem = (item: any): SkillActivityItem => ({
      id: item.id,
      title: item.title,
      description: item.description,
      activityType: item.activity_type,
      difficulty: item.difficulty,
      xpReward: item.xp_reward,
      url: item.url,
      estimatedTime: item.estimated_time,
      category: item.category,
    });
    return {
      skillSlug: d.skill_slug,
      skillName: d.skill_name,
      courses: (d.courses || []).map(transformItem),
      quizzes: (d.quizzes || []).map(transformItem),
      tutorials: (d.tutorials || []).map(transformItem),
      typingPractice: (d.typing_practice || []).map(transformItem),
      totalCount: d.total_count,
    };
  },

  // ==================== Utilities ====================

  /**
   * Get all tier definitions
   */
  async getTiers(): Promise<TiersResponse> {
    const response = await apiClient.get<any>(`${BASE_URL}/utils/tiers`);
    return {
      tiers: response.data.tiers.map((t: any) => ({
        name: t.name,
        minLevel: t.min_level,
        maxLevel: t.max_level,
        color: t.color,
      })),
    };
  },

  /**
   * Calculate XP requirements for a level
   */
  async calculateXP(level: number): Promise<XPCalculatorResponse> {
    const response = await apiClient.get<any>(
      `${BASE_URL}/utils/xp-calculator?level=${level}`
    );
    return {
      level: response.data.level,
      totalXpRequired: response.data.total_xp_required,
      tier: response.data.tier,
      tierColor: response.data.tier_color,
      xpToNextLevel: response.data.xp_to_next_level,
      progressInTier: response.data.progress_in_tier,
    };
  },
};

export default skillsApi;
