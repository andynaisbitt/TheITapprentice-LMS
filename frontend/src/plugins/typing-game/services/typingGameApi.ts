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

const API_BASE = '/api/v1/games/typing';

// Helper for API calls
async function apiCall<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || `API error: ${response.status}`);
  }

  return response.json();
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
  return apiCall<UserTypingStats>('/stats/me');
}

export async function getUserStats(userId: number): Promise<UserTypingStats> {
  return apiCall<UserTypingStats>(`/stats/${userId}`);
}

// ==================== LEADERBOARD ====================

export async function getLeaderboard(
  type: 'wpm' | 'accuracy' | 'pvp' = 'wpm',
  limit: number = 100
): Promise<LeaderboardResponse> {
  return apiCall<LeaderboardResponse>(
    `/leaderboard?leaderboard_type=${type}&limit=${limit}`
  );
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
  getGameHistory,

  // User Stats
  getMyStats,
  getUserStats,

  // Leaderboard
  getLeaderboard,

  // PVP
  findPVPMatch,
  getPVPMatch,
  submitPVPRound,
  getMyPVPStats,
  cancelPVPMatch,
};

export default typingGameApi;
