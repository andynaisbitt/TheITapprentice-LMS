// frontend/src/plugins/shared/services/progressApi.ts
/**
 * API service for XP, Achievements, and Progress systems
 */

import { apiClient as api } from '../../../services/api/client';
import type {
  LevelProgress,
  XPLeaderboardEntry,
  AchievementProgress,
  Achievement,
  AchievementUnlock,
  AchievementStats,
  ActivityTimeline,
  DashboardData,
  CreateAchievementInput,
  UpdateAchievementInput,
  AchievementCategory,
} from '../types';

const BASE_URL = '/progress';

export const progressApi = {
  // ============== XP Endpoints ==============

  /**
   * Get current user's XP and level progress
   */
  async getMyXPProgress(): Promise<LevelProgress> {
    const response = await api.get<LevelProgress>(`${BASE_URL}/xp/me`);
    return response.data;
  },

  /**
   * Get a user's XP and level progress
   */
  async getUserXPProgress(userId: number): Promise<LevelProgress> {
    const response = await api.get<LevelProgress>(`${BASE_URL}/xp/user/${userId}`);
    return response.data;
  },

  /**
   * Get XP leaderboard
   */
  async getXPLeaderboard(limit = 10, offset = 0): Promise<XPLeaderboardEntry[]> {
    const response = await api.get<XPLeaderboardEntry[]>(`${BASE_URL}/xp/leaderboard`, {
      params: { limit, offset },
    });
    return response.data;
  },

  // ============== Achievement Endpoints ==============

  /**
   * Get current user's achievements with progress
   */
  async getMyAchievements(category?: AchievementCategory): Promise<AchievementProgress[]> {
    const params = category ? { category } : {};
    const response = await api.get<AchievementProgress[]>(`${BASE_URL}/achievements`, { params });
    return response.data;
  },

  /**
   * Get all available achievements
   */
  async getAllAchievements(
    category?: AchievementCategory,
    includeInactive = false
  ): Promise<Achievement[]> {
    const params: Record<string, unknown> = {};
    if (category) params.category = category;
    if (includeInactive) params.include_inactive = true;

    const response = await api.get<Achievement[]>(`${BASE_URL}/achievements/all`, { params });
    return response.data;
  },

  /**
   * Get a user's achievements (public profile)
   */
  async getUserAchievements(userId: number): Promise<AchievementProgress[]> {
    const response = await api.get<AchievementProgress[]>(
      `${BASE_URL}/achievements/user/${userId}`
    );
    return response.data;
  },

  // ============== Activity Endpoints ==============

  /**
   * Get current user's activity timeline
   */
  async getMyActivities(limit = 20, offset = 0): Promise<ActivityTimeline> {
    const response = await api.get<ActivityTimeline>(`${BASE_URL}/activities/me`, {
      params: { limit, offset },
    });
    return response.data;
  },

  /**
   * Get a user's activity timeline (public profile)
   */
  async getUserActivities(userId: number, limit = 20, offset = 0): Promise<ActivityTimeline> {
    const response = await api.get<ActivityTimeline>(`${BASE_URL}/activities/user/${userId}`, {
      params: { limit, offset },
    });
    return response.data;
  },

  // ============== Dashboard Endpoints ==============

  /**
   * Get current user's dashboard data
   */
  async getMyDashboard(): Promise<DashboardData> {
    const response = await api.get<DashboardData>(`${BASE_URL}/dashboard/me`);
    return response.data;
  },

  // ============== Admin Endpoints ==============

  /**
   * Admin: Get all achievements including inactive
   */
  async adminGetAllAchievements(category?: AchievementCategory): Promise<Achievement[]> {
    const params = category ? { category } : {};
    const response = await api.get<Achievement[]>(`${BASE_URL}/admin/achievements`, { params });
    return response.data;
  },

  /**
   * Admin: Create new achievement
   */
  async adminCreateAchievement(data: CreateAchievementInput): Promise<Achievement> {
    const response = await api.post<Achievement>(`${BASE_URL}/admin/achievements`, data);
    return response.data;
  },

  /**
   * Admin: Update achievement
   */
  async adminUpdateAchievement(
    achievementId: string,
    data: UpdateAchievementInput
  ): Promise<Achievement> {
    const response = await api.put<Achievement>(
      `${BASE_URL}/admin/achievements/${achievementId}`,
      data
    );
    return response.data;
  },

  /**
   * Admin: Delete achievement
   */
  async adminDeleteAchievement(achievementId: string): Promise<{ success: boolean; message: string }> {
    const response = await api.delete<{ success: boolean; message: string }>(
      `${BASE_URL}/admin/achievements/${achievementId}`
    );
    return response.data;
  },

  /**
   * Admin: Get achievement statistics
   */
  async adminGetAchievementStats(): Promise<AchievementStats> {
    const response = await api.get<AchievementStats>(`${BASE_URL}/admin/achievements/stats`);
    return response.data;
  },

  /**
   * Admin: Manually award XP to a user
   */
  async adminAwardXP(
    userId: number,
    amount: number,
    reason: string
  ): Promise<{
    success: boolean;
    user_id: number;
    xp_awarded: number;
    new_total: number;
    old_level: number;
    new_level: number;
    reason: string;
  }> {
    const response = await api.post(`${BASE_URL}/admin/xp/award`, null, {
      params: { user_id: userId, amount, reason },
    });
    return response.data;
  },
};

export default progressApi;
