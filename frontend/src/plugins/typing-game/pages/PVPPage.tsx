// frontend/src/plugins/typing-game/pages/PVPPage.tsx
/**
 * PVP Page - Main orchestrator for PVP typing game
 * Handles game flow: Lobby -> Game -> Round Results -> Match Results
 */

import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../../state/contexts/AuthContext';
import { typingGameApi } from '../services/typingGameApi';
import { usePVPWebSocket, MatchJoinedData, RoundStartedData, RoundEndedData, MatchEndedData } from '../hooks/usePVPWebSocket';
import { PVPMatchLobby } from '../components/PVPMatchLobby';
import { PVPGameInterface } from '../components/PVPGameInterface';
import { PVPRoundResults, RoundResultData } from '../components/PVPRoundResults';
import { PVPMatchResults, MatchResultData } from '../components/PVPMatchResults';
import type { PVPMatch, PVPMatchDetail } from '../types';

type GamePhase = 'lobby' | 'waiting' | 'playing' | 'round_results' | 'match_results';

export const PVPPage: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated, user } = useAuth();

  // Game state
  const [phase, setPhase] = useState<GamePhase>('lobby');
  const [currentMatch, setCurrentMatch] = useState<PVPMatch | PVPMatchDetail | null>(null);
  const [playerNumber, setPlayerNumber] = useState<1 | 2>(1);
  const [currentRound, setCurrentRound] = useState(1);
  const [roundText, setRoundText] = useState('');
  const [timeLimit, setTimeLimit] = useState(60);

  // Opponent info
  const [opponentInfo, setOpponentInfo] = useState<{ username: string; rating: number } | null>(null);

  // Results
  const [roundResult, setRoundResult] = useState<RoundResultData | null>(null);
  const [matchResult, setMatchResult] = useState<MatchResultData | null>(null);

  // Score tracking
  const [playerScore, setPlayerScore] = useState(0);
  const [opponentScore, setOpponentScore] = useState(0);
  const [roundResults, setRoundResults] = useState<Array<{
    playerWpm: number;
    opponentWpm: number;
    playerAccuracy: number;
    opponentAccuracy: number;
  }>>([]);

  // Redirect if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

  // WebSocket handlers
  const handleMatchJoined = useCallback((data: MatchJoinedData) => {
    console.log('[PVP] Match joined:', data);
    setPlayerNumber(data.player_number);
    setCurrentRound(data.current_round);
  }, []);

  const handleOpponentJoined = useCallback((opponentId: number) => {
    console.log('[PVP] Opponent joined:', opponentId);
    // Fetch opponent info
    // In a real implementation, we'd fetch opponent details from the API
    setOpponentInfo({ username: `Player ${opponentId}`, rating: 1200 });
  }, []);

  const handleOpponentFound = useCallback((data: { match_id: string; opponent: Record<string, unknown> }) => {
    console.log('[PVP] Opponent found:', data);
    setOpponentInfo({
      username: (data.opponent.username as string) || 'Opponent',
      rating: (data.opponent.rating as number) || 1200,
    });
  }, []);

  const handleRoundStarted = useCallback((data: RoundStartedData) => {
    console.log('[PVP] Round started:', data);
    setRoundText(data.text_content);
    setTimeLimit(data.time_limit);
    setPhase('playing');
  }, []);

  const handleRoundEnded = useCallback((data: RoundEndedData) => {
    console.log('[PVP] Round ended:', data);

    const { results, round_number } = data;
    const isPlayer1 = playerNumber === 1;

    const playerWpm = isPlayer1 ? results.player1_wpm : results.player2_wpm;
    const opponentWpm = isPlayer1 ? results.player2_wpm : results.player1_wpm;
    const playerAcc = isPlayer1 ? results.player1_accuracy : results.player2_accuracy;
    const opponentAcc = isPlayer1 ? results.player2_accuracy : results.player1_accuracy;

    // Determine round winner
    let winner: 'player' | 'opponent' | 'tie' = 'tie';
    if (results.round_winner !== null) {
      winner = results.round_winner === (isPlayer1 ? 1 : 2) ? 'player' : 'opponent';
    }

    // Update scores
    const newPlayerScore = winner === 'player' ? playerScore + 1 : playerScore;
    const newOpponentScore = winner === 'opponent' ? opponentScore + 1 : opponentScore;
    setPlayerScore(newPlayerScore);
    setOpponentScore(newOpponentScore);

    // Store round result
    setRoundResults(prev => [...prev, {
      playerWpm,
      opponentWpm,
      playerAccuracy: playerAcc,
      opponentAccuracy: opponentAcc,
    }]);

    // Set round result for display
    setRoundResult({
      roundNumber: round_number,
      playerWpm,
      opponentWpm,
      playerAccuracy: playerAcc,
      opponentAccuracy: opponentAcc,
      winner,
      currentScore: {
        player: newPlayerScore,
        opponent: newOpponentScore,
      },
    });

    setPhase('round_results');
  }, [playerNumber, playerScore, opponentScore]);

  const handleMatchEnded = useCallback((data: MatchEndedData) => {
    console.log('[PVP] Match ended:', data);

    const { results, reason, forfeit_by } = data;
    const isPlayer1 = playerNumber === 1;

    // Calculate averages from round results
    const totalRounds = roundResults.length || 1;
    const avgPlayerWpm = roundResults.reduce((sum, r) => sum + r.playerWpm, 0) / totalRounds;
    const avgOpponentWpm = roundResults.reduce((sum, r) => sum + r.opponentWpm, 0) / totalRounds;
    const avgPlayerAcc = roundResults.reduce((sum, r) => sum + r.playerAccuracy, 0) / totalRounds;
    const avgOpponentAcc = roundResults.reduce((sum, r) => sum + r.opponentAccuracy, 0) / totalRounds;

    // Determine winner
    let winner: 'player' | 'opponent' | 'tie' = 'tie';
    if (results.winner_id !== null) {
      winner = results.winner_id === user?.id ? 'player' : 'opponent';
    } else if (reason === 'forfeit' && forfeit_by) {
      winner = forfeit_by === user?.id ? 'opponent' : 'player';
    }

    setMatchResult({
      winner,
      playerScore: isPlayer1 ? results.player1_score : results.player2_score,
      opponentScore: isPlayer1 ? results.player2_score : results.player1_score,
      playerTotalWpm: Math.round(avgPlayerWpm),
      opponentTotalWpm: Math.round(avgOpponentWpm),
      playerAvgAccuracy: avgPlayerAcc,
      opponentAvgAccuracy: avgOpponentAcc,
      xpEarned: results.xp_earned || 0,
      ratingChange: results.rating_change || 0,
      newRating: (user as any)?.pvp_rating || 1200 + (results.rating_change || 0),
      roundResults: roundResults.map((r, i) => ({
        round: i + 1,
        p1_wpm: r.playerWpm,
        p2_wpm: r.opponentWpm,
        p1_accuracy: r.playerAccuracy,
        p2_accuracy: r.opponentAccuracy,
        winner: r.playerWpm > r.opponentWpm ? 1 : r.opponentWpm > r.playerWpm ? 2 : undefined,
      })),
      matchDuration: 180, // Placeholder - would be calculated from actual times
    });

    setPhase('match_results');
  }, [playerNumber, roundResults, user]);

  const handleOpponentDisconnected = useCallback(() => {
    console.log('[PVP] Opponent disconnected');
    // Handle opponent disconnect - usually results in a win
  }, []);

  // WebSocket connection (only when in a match)
  const wsHandlers = currentMatch ? {
    matchId: currentMatch.id,
    onMatchJoined: handleMatchJoined,
    onOpponentJoined: handleOpponentJoined,
    onOpponentFound: handleOpponentFound,
    onRoundStarted: handleRoundStarted,
    onRoundEnded: handleRoundEnded,
    onMatchEnded: handleMatchEnded,
    onOpponentDisconnected: handleOpponentDisconnected,
  } : null;

  // Handle match found from lobby
  const handleMatchFound = useCallback(async (match: PVPMatch) => {
    console.log('[PVP] Match found:', match);
    setCurrentMatch(match);
    setPhase('waiting');

    // Fetch full match details
    try {
      const matchDetail = await typingGameApi.getPVPMatch(match.id);
      setCurrentMatch(matchDetail);

      // If match is already in progress, start playing
      if (matchDetail.status === 'IN_PROGRESS' && matchDetail.content) {
        setRoundText(matchDetail.content);
        setPhase('playing');
      }
    } catch (error) {
      console.error('Failed to fetch match details:', error);
    }
  }, []);

  // Handle cancel from lobby
  const handleCancel = useCallback(() => {
    navigate('/games/typing');
  }, [navigate]);

  // Handle round complete
  const handleRoundComplete = useCallback(async (wpm: number, accuracy: number, timeElapsed: number) => {
    if (!currentMatch) return;

    try {
      // Submit round results to API
      const result = await typingGameApi.submitPVPRound({
        match_id: currentMatch.id,
        wpm,
        accuracy,
        time_elapsed: timeElapsed,
        words_typed: Math.floor(wpm * (timeElapsed / 60)),
      });

      console.log('[PVP] Round submitted:', result);

      // The WebSocket will notify us of round/match end
    } catch (error) {
      console.error('Failed to submit round:', error);
    }
  }, [currentMatch]);

  // Handle forfeit
  const handleForfeit = useCallback(() => {
    // WebSocket will handle the forfeit notification
    setPhase('match_results');
  }, []);

  // Handle continue after round results
  const handleContinueAfterRound = useCallback(() => {
    if (roundResult && currentMatch) {
      const totalRounds = (currentMatch as PVPMatchDetail).total_rounds || 3;
      if (roundResult.roundNumber >= totalRounds) {
        // Last round - show match results
        // The match ended handler should have been called
        setPhase('match_results');
      } else {
        // More rounds to play
        setCurrentRound(roundResult.roundNumber + 1);
        setRoundText(''); // Will be set by round_started event
        setPhase('waiting'); // Wait for next round to start
      }
    }
  }, [roundResult, currentMatch]);

  // Handle play again
  const handlePlayAgain = useCallback(() => {
    // Reset state
    setCurrentMatch(null);
    setPlayerNumber(1);
    setCurrentRound(1);
    setRoundText('');
    setPlayerScore(0);
    setOpponentScore(0);
    setRoundResults([]);
    setRoundResult(null);
    setMatchResult(null);
    setOpponentInfo(null);
    setPhase('lobby');
  }, []);

  // Handle back to lobby
  const handleBackToLobby = useCallback(() => {
    handlePlayAgain();
  }, [handlePlayAgain]);

  // Render based on phase
  const renderPhase = () => {
    switch (phase) {
      case 'lobby':
        return (
          <PVPMatchLobby
            onMatchFound={handleMatchFound}
            onCancel={handleCancel}
          />
        );

      case 'waiting':
        return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
            <div className="text-center">
              <div className="animate-spin w-16 h-16 border-4 border-blue-500 border-t-transparent rounded-full mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                Waiting for Round {currentRound} to Start...
              </h2>
              <p className="text-gray-600 dark:text-gray-400">
                Get ready to type!
              </p>
            </div>
          </div>
        );

      case 'playing':
        return currentMatch ? (
          <PVPGameInterface
            match={currentMatch}
            roundText={roundText}
            timeLimit={timeLimit}
            currentRound={currentRound}
            totalRounds={(currentMatch as PVPMatchDetail).total_rounds || 3}
            playerNumber={playerNumber}
            opponentInfo={opponentInfo || undefined}
            onRoundComplete={handleRoundComplete}
            onForfeit={handleForfeit}
          />
        ) : null;

      case 'round_results':
        return roundResult ? (
          <PVPRoundResults
            result={roundResult}
            totalRounds={(currentMatch as PVPMatchDetail)?.total_rounds || 3}
            playerName={user?.first_name || user?.username || 'You'}
            opponentName={opponentInfo?.username || 'Opponent'}
            onContinue={handleContinueAfterRound}
            isLastRound={roundResult.roundNumber >= ((currentMatch as PVPMatchDetail)?.total_rounds || 3)}
          />
        ) : null;

      case 'match_results':
        return matchResult ? (
          <PVPMatchResults
            result={matchResult}
            playerName={user?.first_name || user?.username || 'You'}
            opponentName={opponentInfo?.username || 'Opponent'}
            onPlayAgain={handlePlayAgain}
            onBackToLobby={handleBackToLobby}
          />
        ) : null;

      default:
        return null;
    }
  };

  return renderPhase();
};

export default PVPPage;
