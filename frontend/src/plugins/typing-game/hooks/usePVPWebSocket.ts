// frontend/src/plugins/typing-game/hooks/usePVPWebSocket.ts
/**
 * WebSocket hook for PVP typing game matches
 * Handles real-time communication during matches
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../../../state/contexts/AuthContext';

// WebSocket message types
export type WSMessageType =
  | 'match_joined'
  | 'opponent_joined'
  | 'opponent_progress'
  | 'player_ready'
  | 'round_started'
  | 'opponent_finished'
  | 'round_ended'
  | 'match_ended'
  | 'opponent_disconnected'
  | 'opponent_found'
  | 'chat'
  | 'error'
  | 'pong';

export interface WSMessage {
  type: WSMessageType;
  match_id?: string;
  timestamp?: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface OpponentProgress {
  user_id: number;
  progress: number;
  words_typed: number;
  current_wpm: number;
}

export interface MatchJoinedData {
  match_id: string;
  user_id: number;
  player_number: 1 | 2;
  match_status: string;
  current_round: number;
  total_rounds: number;
}

export interface RoundStartedData {
  match_id: string;
  text_content: string;
  time_limit: number;
  timestamp: string;
}

export interface RoundEndedData {
  match_id: string;
  round_number: number;
  results: {
    player1_wpm: number;
    player2_wpm: number;
    player1_accuracy: number;
    player2_accuracy: number;
    round_winner: number | null;
  };
}

export interface MatchEndedData {
  match_id: string;
  results: {
    winner_id: number | null;
    player1_score: number;
    player2_score: number;
    player1_total_wpm: number;
    player2_total_wpm: number;
    xp_earned: number;
    rating_change: number;
  };
  reason?: 'completed' | 'forfeit';
  forfeit_by?: number;
}

export interface UsePVPWebSocketOptions {
  matchId: string;
  onMatchJoined?: (data: MatchJoinedData) => void;
  onOpponentJoined?: (opponentId: number) => void;
  onOpponentProgress?: (progress: OpponentProgress) => void;
  onOpponentReady?: (userId: number) => void;
  onRoundStarted?: (data: RoundStartedData) => void;
  onOpponentFinished?: (data: { user_id: number; wpm: number; accuracy: number }) => void;
  onRoundEnded?: (data: RoundEndedData) => void;
  onMatchEnded?: (data: MatchEndedData) => void;
  onOpponentDisconnected?: (opponentId: number) => void;
  onOpponentFound?: (data: { match_id: string; opponent: Record<string, unknown> }) => void;
  onChat?: (data: { user_id: number; message: string; timestamp: string }) => void;
  onError?: (message: string) => void;
}

export interface UsePVPWebSocketReturn {
  isConnected: boolean;
  isConnecting: boolean;
  error: string | null;
  sendProgress: (progress: number, wordsTyped: number, currentWpm: number) => void;
  sendReady: () => void;
  sendRoundComplete: (wpm: number, accuracy: number) => void;
  sendForfeit: () => void;
  sendChat: (message: string) => void;
  sendPing: () => void;
  disconnect: () => void;
  reconnect: () => void;
}

export function usePVPWebSocket(options: UsePVPWebSocketOptions): UsePVPWebSocketReturn {
  const { isAuthenticated } = useAuth();
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 5;

  const {
    matchId,
    onMatchJoined,
    onOpponentJoined,
    onOpponentProgress,
    onOpponentReady,
    onRoundStarted,
    onOpponentFinished,
    onRoundEnded,
    onMatchEnded,
    onOpponentDisconnected,
    onOpponentFound,
    onChat,
    onError,
  } = options;

  // Cleanup function
  const cleanup = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (!matchId || !isAuthenticated) {
      setError('Missing match ID or not authenticated');
      return;
    }

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    setIsConnecting(true);
    setError(null);

    // Build WebSocket URL (cookies handle authentication)
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/pvp/${matchId}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[PVP WebSocket] Connected');
        setIsConnected(true);
        setIsConnecting(false);
        setError(null);
        reconnectAttemptsRef.current = 0;

        // Start ping interval to keep connection alive
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 30000);
      };

      ws.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data);
          console.log('[PVP WebSocket] Message:', message.type, message);

          switch (message.type) {
            case 'match_joined':
              onMatchJoined?.(message as unknown as MatchJoinedData);
              break;
            case 'opponent_joined':
              onOpponentJoined?.(message.opponent_id as number);
              break;
            case 'opponent_progress':
              onOpponentProgress?.(message.data as unknown as OpponentProgress);
              break;
            case 'player_ready':
              onOpponentReady?.(message.data?.user_id as number);
              break;
            case 'round_started':
              onRoundStarted?.(message as unknown as RoundStartedData);
              break;
            case 'opponent_finished':
              onOpponentFinished?.(message.data as unknown as { user_id: number; wpm: number; accuracy: number });
              break;
            case 'round_ended':
              onRoundEnded?.(message as unknown as RoundEndedData);
              break;
            case 'match_ended':
              onMatchEnded?.(message as unknown as MatchEndedData);
              break;
            case 'opponent_disconnected':
              onOpponentDisconnected?.(message.opponent_id as number);
              break;
            case 'opponent_found':
              onOpponentFound?.(message as unknown as { match_id: string; opponent: Record<string, unknown> });
              break;
            case 'chat':
              onChat?.(message as unknown as { user_id: number; message: string; timestamp: string });
              break;
            case 'error':
              onError?.(message.message as string);
              setError(message.message as string);
              break;
            case 'pong':
              // Connection is alive
              break;
            default:
              console.warn('[PVP WebSocket] Unknown message type:', message.type);
          }
        } catch (err) {
          console.error('[PVP WebSocket] Failed to parse message:', err);
        }
      };

      ws.onerror = (event) => {
        console.error('[PVP WebSocket] Error:', event);
        setError('WebSocket connection error');
      };

      ws.onclose = (event) => {
        console.log('[PVP WebSocket] Closed:', event.code, event.reason);
        setIsConnected(false);
        setIsConnecting(false);

        // Clear ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }

        // Attempt reconnect for unexpected disconnections
        if (event.code !== 1000 && event.code !== 4001 && event.code !== 4003 && event.code !== 4004) {
          if (reconnectAttemptsRef.current < maxReconnectAttempts) {
            const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 10000);
            reconnectAttemptsRef.current++;
            console.log(`[PVP WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current})`);
            reconnectTimeoutRef.current = setTimeout(connect, delay);
          } else {
            setError('Connection lost. Please refresh the page.');
          }
        }
      };
    } catch (err) {
      console.error('[PVP WebSocket] Failed to create WebSocket:', err);
      setError('Failed to connect to game server');
      setIsConnecting(false);
    }
  }, [matchId, isAuthenticated, onMatchJoined, onOpponentJoined, onOpponentProgress, onOpponentReady, onRoundStarted, onOpponentFinished, onRoundEnded, onMatchEnded, onOpponentDisconnected, onOpponentFound, onChat, onError]);

  // Send message helper
  const sendMessage = useCallback((message: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('[PVP WebSocket] Cannot send message, not connected');
    }
  }, []);

  // Send progress update
  const sendProgress = useCallback((progress: number, wordsTyped: number, currentWpm: number) => {
    sendMessage({
      type: 'progress',
      progress,
      words_typed: wordsTyped,
      current_wpm: currentWpm,
    });
  }, [sendMessage]);

  // Send ready signal
  const sendReady = useCallback(() => {
    sendMessage({ type: 'round_ready' });
  }, [sendMessage]);

  // Send round complete signal
  const sendRoundComplete = useCallback((wpm: number, accuracy: number) => {
    sendMessage({
      type: 'round_complete',
      wpm,
      accuracy,
    });
  }, [sendMessage]);

  // Send forfeit
  const sendForfeit = useCallback(() => {
    sendMessage({ type: 'forfeit' });
  }, [sendMessage]);

  // Send chat message
  const sendChat = useCallback((message: string) => {
    sendMessage({
      type: 'chat',
      message,
    });
  }, [sendMessage]);

  // Send ping
  const sendPing = useCallback(() => {
    sendMessage({ type: 'ping' });
  }, [sendMessage]);

  // Disconnect
  const disconnect = useCallback(() => {
    cleanup();
    setIsConnected(false);
    setIsConnecting(false);
  }, [cleanup]);

  // Reconnect
  const reconnect = useCallback(() => {
    cleanup();
    reconnectAttemptsRef.current = 0;
    connect();
  }, [cleanup, connect]);

  // Connect on mount
  useEffect(() => {
    connect();
    return cleanup;
  }, [connect, cleanup]);

  return {
    isConnected,
    isConnecting,
    error,
    sendProgress,
    sendReady,
    sendRoundComplete,
    sendForfeit,
    sendChat,
    sendPing,
    disconnect,
    reconnect,
  };
}

export default usePVPWebSocket;
