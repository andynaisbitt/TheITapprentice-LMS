// frontend/src/plugins/typing-game/types/index.ts
/**
 * TypeScript types for the Typing Game plugin
 */

// ==================== ENUMS ====================

export type GameMode = 'practice' | 'challenge' | 'pvp';
export type Difficulty = 'easy' | 'medium' | 'hard' | 'expert';
export type MatchStatus = 'WAITING' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';

// ==================== WORD LISTS ====================

export interface TypingWordList {
  id: string;
  name: string;
  description?: string;
  difficulty: Difficulty;
  theme: string;
  words: string[];
  related_skills: string[];
  unlock_level: number;
  is_active: boolean;
  is_featured: boolean;
  display_order: number;
  times_played: number;
  avg_wpm: number;
  avg_accuracy: number;
  created_at: string;
  updated_at: string;
  is_unlocked?: boolean;
  user_best_wpm?: number;
  user_times_played?: number;
}

export interface TypingWordListSummary {
  id: string;
  name: string;
  difficulty: Difficulty;
  theme: string;
  word_count: number;
  unlock_level: number;
  is_unlocked: boolean;
  is_featured: boolean;
}

// ==================== GAME SESSIONS ====================

export interface TypingGameStartRequest {
  word_list_id?: string;
  mode?: GameMode;
  word_count?: number;
}

export interface TypingGameStartResponse {
  session_id: string;
  text: string;
  checksum: string;
  word_list_name?: string;
  difficulty: Difficulty;
  word_count: number;
  related_skills: string[];
}

export interface TypingGameSubmitRequest {
  session_id: string;
  user_input: string;
  time_elapsed: number;
  checksum: string;
}

export interface TypingPerformanceMetrics {
  wpm: number;
  raw_wpm: number;
  accuracy: number;
  error_count: number;
  total_characters: number;
  time_elapsed: number;
}

export interface TypingGameResultsResponse {
  session_id: string;
  metrics: TypingPerformanceMetrics;
  xp_earned: number;
  is_personal_best_wpm: boolean;
  is_personal_best_accuracy: boolean;
  rank_change?: number;
}

export interface TypingGameSession {
  id: string;
  user_id: number;
  word_list_id?: string;
  mode: GameMode;
  wpm?: number;
  accuracy?: number;
  mistakes: number;
  time_taken?: number;
  is_completed: boolean;
  started_at: string;
  completed_at?: string;
}

// ==================== USER STATS ====================

export interface UserTypingStats {
  user_id: number;
  best_wpm: number;
  best_accuracy: number;
  avg_wpm: number;
  avg_accuracy: number;
  total_games_played: number;
  total_games_completed: number;
  total_words_typed: number;
  total_time_seconds: number;
  current_streak_days: number;
  longest_streak_days: number;
  first_game_at?: string;
  last_game_at?: string;
}

export interface TypingGameHistoryEntry {
  session_id: string;
  word_list_name?: string;
  difficulty: Difficulty;
  wpm: number;
  accuracy: number;
  time_elapsed: number;
  xp_earned: number;
  completed_at: string;
}

export interface TypingGameHistoryResponse {
  games: TypingGameHistoryEntry[];
  total_games: number;
  page: number;
  page_size: number;
}

// ==================== PVP ====================

export interface PVPFindMatchRequest {
  difficulty?: Difficulty;
}

export interface PVPMatch {
  id: string;
  player1_id: number;
  player2_id?: number;
  status: MatchStatus;
  difficulty: Difficulty;
  content?: string;
  word_count: number;
  total_rounds: number;
  current_round: number;
  created_at: string;
  started_at?: string;
}

export interface PVPMatchDetail extends PVPMatch {
  player1_wpm: number;
  player2_wpm: number;
  player1_accuracy: number;
  player2_accuracy: number;
  player1_score: number;
  player2_score: number;
  winner_id?: number;
  round_results?: RoundResult[];
  completed_at?: string;
}

export interface RoundResult {
  round: number;
  p1_wpm?: number;
  p2_wpm?: number;
  p1_accuracy?: number;
  p2_accuracy?: number;
  winner?: number;
}

export interface PVPRoundSubmitRequest {
  match_id: string;
  wpm: number;
  accuracy: number;
  time_elapsed: number;
  words_typed: number;
}

export interface PVPRoundResultResponse {
  round_number: number;
  winner: 'player' | 'opponent' | 'tie' | 'pending';
  player_wpm: number;
  opponent_wpm: number;
  player_accuracy: number;
  opponent_accuracy: number;
  match_status: 'in_progress' | 'completed';
  current_score: {
    player1: number;
    player2: number;
  };
  xp_earned?: number;
}

export interface UserPVPStats {
  user_id: number;
  current_rating: number;
  peak_rating: number;
  rating_tier: string;
  total_matches: number;
  wins: number;
  losses: number;
  ties: number;
  win_rate: number;
  best_wpm: number;
  avg_wpm: number;
  best_accuracy: number;
  avg_accuracy: number;
  current_win_streak: number;
  longest_win_streak: number;
  last_match_at?: string;
}

// ==================== LEADERBOARD ====================

export interface LeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  display_name?: string;
  best_wpm: number;
  avg_wpm: number;
  avg_accuracy: number;
  games_played: number;
}

export interface LeaderboardResponse {
  leaderboard_type: string;
  period?: string;
  entries: LeaderboardEntry[];
  user_rank?: number;
  total_entries: number;
}

// ==================== GAME STATE ====================

export interface GameState {
  status: 'idle' | 'ready' | 'playing' | 'paused' | 'completed' | 'failed';
  currentRound: number;
  totalRounds: number;
  text: string;
  userInput: string;
  startTime?: number;
  endTime?: number;
  wpm: number;
  accuracy: number;
  errors: number;
  currentWordIndex: number;
  currentCharIndex: number;
}

export interface RoundConfig {
  roundNumber: number;
  name: string;
  timeLimit: number | null;  // null = no time limit
  description: string;
}

// Default round configuration for Quick Brown Fox game
export const QUICK_BROWN_FOX_ROUNDS: RoundConfig[] = [
  { roundNumber: 1, name: 'Warmup Round', timeLimit: null, description: 'Get familiar with the text!' },
  { roundNumber: 2, name: 'Speed Challenge', timeLimit: 20, description: 'Complete in 20 seconds!' },
  { roundNumber: 3, name: 'INSANE MODE', timeLimit: 10, description: 'Complete in 10 seconds or FAIL!' }
];

// ==================== COMPONENT PROPS ====================

export interface TypingInputProps {
  text: string;
  userInput: string;
  onInputChange: (input: string) => void;
  disabled?: boolean;
}

export interface WordDisplayProps {
  text: string;
  userInput: string;
  currentWordIndex: number;
}

export interface TimerProps {
  timeLimit: number | null;
  startTime?: number;
  onTimeUp?: () => void;
}

export interface StatsDisplayProps {
  wpm: number;
  accuracy: number;
  errors: number;
  timeElapsed: number;
}

export interface GameCompleteModalProps {
  isOpen: boolean;
  onClose: () => void;
  results: TypingGameResultsResponse;
  onPlayAgain?: () => void;
}
