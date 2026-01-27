// frontend/src/plugins/typing-game/services/typingGameApi.ts
/**
 * API service for Typing Game plugin
 */

import {
  TypingWordList,
  TypingWordListSummary,
  TypingGameStartRequest,
  TypingGameStartResponse,
  TypingGameSubmitRequest,
  TypingGameSubmitRequestV2,
  TypingGameResultsResponse,
  TypingGameHistoryResponse,
  UserTypingStats,
  PVPFindMatchRequest,
  PVPMatch,
  PVPMatchDetail,
  PVPRoundSubmitRequest,
  PVPRoundResultResponse,
  UserPVPStats,
  LeaderboardResponse,
} from '../types';
import { apiClient } from '../../../services/api/client';

const API_BASE = '/api/v1/games/typing';

// Helper for API calls using apiClient (axios) for proper auth/CSRF handling
async function apiCall<T>(
  endpoint: string,
  options: { method?: string; body?: string } = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  if (options.method === 'POST') {
    const { data } = await apiClient.post<T>(url, options.body ? JSON.parse(options.body) : undefined);
    return data;
  } else if (options.method === 'PUT') {
    const { data } = await apiClient.put<T>(url, options.body ? JSON.parse(options.body) : undefined);
    return data;
  } else if (options.method === 'DELETE') {
    const { data } = await apiClient.delete<T>(url);
    return data;
  } else {
    const { data } = await apiClient.get<T>(url);
    return data;
  }
}

// ==================== WORD LISTS ====================

export async function getWordLists(params?: {
  difficulty?: string;
  theme?: string;
  skip?: number;
  limit?: number;
}): Promise<TypingWordList[]> {
  const searchParams = new URLSearchParams();
  if (params?.difficulty) searchParams.set('difficulty', params.difficulty);
  if (params?.theme) searchParams.set('theme', params.theme);
  if (params?.skip) searchParams.set('skip', String(params.skip));
  if (params?.limit) searchParams.set('limit', String(params.limit));

  const query = searchParams.toString();
  return apiCall<TypingWordList[]>(`/word-lists${query ? `?${query}` : ''}`);
}

export async function getFeaturedWordLists(): Promise<TypingWordListSummary[]> {
  return apiCall<TypingWordListSummary[]>('/word-lists/featured');
}

export async function getWordList(wordListId: string): Promise<TypingWordList> {
  return apiCall<TypingWordList>(`/word-lists/${wordListId}`);
}

// ==================== GAME SESSIONS ====================

export async function startGame(
  request: TypingGameStartRequest
): Promise<TypingGameStartResponse> {
  return apiCall<TypingGameStartResponse>('/start', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export async function submitGame(
  request: TypingGameSubmitRequest
): Promise<TypingGameResultsResponse> {
  return apiCall<TypingGameResultsResponse>('/submit', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

/**
 * Submit game with enhanced V2 endpoint including anti-cheat data
 */
export async function submitGameV2(
  request: TypingGameSubmitRequestV2
): Promise<TypingGameResultsResponse> {
  return apiCall<TypingGameResultsResponse>('/submit/v2', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export async function getGameHistory(
  page: number = 1,
  pageSize: number = 10
): Promise<TypingGameHistoryResponse> {
  return apiCall<TypingGameHistoryResponse>(
    `/history?page=${page}&page_size=${pageSize}`
  );
}

// ==================== USER STATS ====================

export async function getMyStats(): Promise<UserTypingStats> {
  // Add cache-busting timestamp to ensure fresh data
  return apiCall<UserTypingStats>(`/stats/me?_t=${Date.now()}`);
}

export async function getUserStats(userId: number): Promise<UserTypingStats> {
  return apiCall<UserTypingStats>(`/stats/${userId}`);
}

// ==================== LEADERBOARD ====================

export async function getLeaderboard(
  type: 'wpm' | 'accuracy' | 'pvp' = 'wpm',
  limit: number = 100
): Promise<LeaderboardResponse> {
  // Add cache-busting timestamp to ensure fresh data
  return apiCall<LeaderboardResponse>(
    `/leaderboard?leaderboard_type=${type}&limit=${limit}&_t=${Date.now()}`
  );
}

// ==================== STREAK & CHALLENGES ====================

export interface StreakInfo {
  current_streak: number;
  longest_streak: number;
  last_play_date: string | null;
  games_today: number;
  freeze_available: boolean;
  streak_at_risk: boolean;
  freeze_will_auto_apply: boolean;
  played_today: boolean;
}

export interface DailyChallenge {
  challenge_id: string;
  challenge_type: string;
  name: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard';
  target_value: number;
  current_value: number;
  progress_percent: number;
  is_completed: boolean;
  is_claimed: boolean;
  xp_reward: number;
}

export interface DailyChallengesResponse {
  challenges: DailyChallenge[];
  streak: StreakInfo;
  date: string;
}

export async function getMyStreak(): Promise<StreakInfo> {
  return apiCall<StreakInfo>('/streak/me');
}

export async function useStreakFreeze(): Promise<{ success: boolean; message: string }> {
  return apiCall<{ success: boolean; message: string }>('/streak/freeze', {
    method: 'POST',
  });
}

export async function getDailyChallenges(): Promise<DailyChallengesResponse> {
  return apiCall<DailyChallengesResponse>('/challenges/daily');
}

export async function claimChallengeReward(
  challengeId: string
): Promise<{ success: boolean; xp_earned: number; message?: string }> {
  return apiCall<{ success: boolean; xp_earned: number; message?: string }>(
    `/challenges/${challengeId}/claim`,
    { method: 'POST' }
  );
}

// ==================== PVP SETTINGS ====================

export async function getPVPSettings(): Promise<{ pvp_enabled: boolean }> {
  return apiCall<{ pvp_enabled: boolean }>('/pvp/settings');
}

export async function updatePVPSettings(enabled: boolean): Promise<{ pvp_enabled: boolean; message: string }> {
  return apiCall<{ pvp_enabled: boolean; message: string }>(`/admin/pvp/settings?enabled=${enabled}`, {
    method: 'PUT',
  });
}

// ==================== PVP ====================

export async function findPVPMatch(
  request: PVPFindMatchRequest = {}
): Promise<PVPMatch> {
  return apiCall<PVPMatch>('/pvp/find-match', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export async function getPVPMatch(matchId: string): Promise<PVPMatchDetail> {
  return apiCall<PVPMatchDetail>(`/pvp/match/${matchId}`);
}

export async function submitPVPRound(
  request: PVPRoundSubmitRequest
): Promise<PVPRoundResultResponse> {
  return apiCall<PVPRoundResultResponse>('/pvp/submit-round', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export async function getMyPVPStats(): Promise<UserPVPStats> {
  return apiCall<UserPVPStats>('/pvp/stats/me');
}

export async function cancelPVPMatch(matchId: string): Promise<{ message: string }> {
  return apiCall<{ message: string }>(`/pvp/cancel/${matchId}`, {
    method: 'POST',
  });
}

// ==================== TYPING GAME API OBJECT ====================

export const typingGameApi = {
  // Word Lists
  getWordLists,
  getFeaturedWordLists,
  getWordList,

  // Game Sessions
  startGame,
  submitGame,
  submitGameV2,
  getGameHistory,

  // User Stats
  getMyStats,
  getUserStats,

  // Leaderboard
  getLeaderboard,

  // Streak & Challenges
  getMyStreak,
  useStreakFreeze,
  getDailyChallenges,
  claimChallengeReward,

  // PVP Settings
  getPVPSettings,
  updatePVPSettings,

  // PVP
  findPVPMatch,
  getPVPMatch,
  submitPVPRound,
  getMyPVPStats,
  cancelPVPMatch,
};

export default typingGameApi;
