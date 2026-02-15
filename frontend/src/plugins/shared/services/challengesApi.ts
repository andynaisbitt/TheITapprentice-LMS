// frontend/src/plugins/shared/services/challengesApi.ts
/**
 * API service for Daily Challenges system
 */

import { apiClient as api } from '../../../services/api/client';
import type {
  DailyChallenge,
  DailyChallengesResponse,
  ChallengeStreak,
  ClaimRewardResponse,
  UseFreezeTokenResponse,
  ChallengeTemplate,
  ChallengeStats,
  ChallengeDifficulty,
  ChallengeType,
} from '../types';

const BASE_URL = '/api/v1/progress/challenges';

export interface ChallengeHistoryEntry {
  challenge_id: string;
  title: string;
  difficulty: ChallengeDifficulty;
  challenge_type: ChallengeType;
  challenge_date: string;
  is_completed: boolean;
  is_claimed: boolean;
  xp_earned: number;
  completed_at?: string;
}

export interface ChallengeHistoryResponse {
  history: ChallengeHistoryEntry[];
  total: number;
  has_more: boolean;
}

export interface CreateChallengeTemplateInput {
  title: string;
  description?: string;
  challenge_type: ChallengeType;
  difficulty: ChallengeDifficulty;
  target_count: number;
  base_xp_reward: number;
  icon?: string;
  is_active?: boolean;
}

export interface UpdateChallengeTemplateInput {
  title?: string;
  description?: string;
  challenge_type?: ChallengeType;
  difficulty?: ChallengeDifficulty;
  target_count?: number;
  base_xp_reward?: number;
  icon?: string;
  is_active?: boolean;
}

export const challengesApi = {
  // ============== User Endpoints ==============

  /**
   * Get today's daily challenges with user progress
   */
  async getTodaysChallenges(): Promise<DailyChallengesResponse> {
    const response = await api.get<DailyChallengesResponse>(`${BASE_URL}/daily`);
    return response.data;
  },

  /**
   * Get user's challenge streak info
   */
  async getStreak(): Promise<ChallengeStreak> {
    const response = await api.get<ChallengeStreak>(`${BASE_URL}/streak`);
    return response.data;
  },

  /**
   * Claim reward for a completed challenge
   */
  async claimReward(challengeId: string): Promise<ClaimRewardResponse> {
    const response = await api.post<ClaimRewardResponse>(
      `${BASE_URL}/daily/${challengeId}/claim`
    );
    return response.data;
  },

  /**
   * Use a freeze token to protect streak
   */
  async useFreezeToken(): Promise<UseFreezeTokenResponse> {
    const response = await api.post<UseFreezeTokenResponse>(`${BASE_URL}/streak/freeze`);
    return response.data;
  },

  /**
   * Get challenge completion history
   */
  async getHistory(limit = 20, offset = 0): Promise<ChallengeHistoryResponse> {
    const response = await api.get<ChallengeHistoryResponse>(`${BASE_URL}/history`, {
      params: { limit, offset },
    });
    return response.data;
  },

  // ============== Admin Endpoints ==============

  /**
   * Admin: Get all challenge templates
   */
  async adminGetTemplates(includeInactive = false): Promise<ChallengeTemplate[]> {
    const params = includeInactive ? { include_inactive: true } : {};
    const response = await api.get<ChallengeTemplate[]>(
      `${BASE_URL.replace('/challenges', '')}/admin/challenges/templates`,
      { params }
    );
    return response.data;
  },

  /**
   * Admin: Create new challenge template
   */
  async adminCreateTemplate(data: CreateChallengeTemplateInput): Promise<ChallengeTemplate> {
    const response = await api.post<ChallengeTemplate>(
      `${BASE_URL.replace('/challenges', '')}/admin/challenges/templates`,
      data
    );
    return response.data;
  },

  /**
   * Admin: Update challenge template
   */
  async adminUpdateTemplate(
    templateId: string,
    data: UpdateChallengeTemplateInput
  ): Promise<ChallengeTemplate> {
    const response = await api.put<ChallengeTemplate>(
      `${BASE_URL.replace('/challenges', '')}/admin/challenges/templates/${templateId}`,
      data
    );
    return response.data;
  },

  /**
   * Admin: Delete challenge template
   */
  async adminDeleteTemplate(
    templateId: string
  ): Promise<{ success: boolean; message: string }> {
    const response = await api.delete<{ success: boolean; message: string }>(
      `${BASE_URL.replace('/challenges', '')}/admin/challenges/templates/${templateId}`
    );
    return response.data;
  },

  /**
   * Admin: Manually trigger daily challenge generation
   */
  async adminGenerateChallenges(): Promise<DailyChallenge[]> {
    const response = await api.post<DailyChallenge[]>(
      `${BASE_URL.replace('/challenges', '')}/admin/challenges/generate`
    );
    return response.data;
  },

  /**
   * Admin: Get challenge system statistics
   */
  async adminGetStats(): Promise<ChallengeStats> {
    const response = await api.get<ChallengeStats>(
      `${BASE_URL.replace('/challenges', '')}/admin/challenges/stats`
    );
    return response.data;
  },
};

export default challengesApi;
