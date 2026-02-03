// frontend/src/plugins/typing-game/components/PVPMatchResults.tsx
/**
 * PVP Match Results Component
 * Shows final match results with XP earned, rating change, and stats
 */

import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Trophy,
  Zap,
  Target,
  TrendingUp,
  TrendingDown,
  Star,
  Award,
  RotateCcw,
  Home,
  Crown,
  Medal,
  Frown
} from 'lucide-react';
import type { RoundResult } from '../types';

export interface MatchResultData {
  winner: 'player' | 'opponent' | 'tie';
  playerScore: number;
  opponentScore: number;
  playerTotalWpm: number;
  opponentTotalWpm: number;
  playerAvgAccuracy: number;
  opponentAvgAccuracy: number;
  xpEarned: number;
  ratingChange: number;
  newRating: number;
  roundResults: RoundResult[];
  matchDuration: number;
}

interface PVPMatchResultsProps {
  result: MatchResultData;
  playerName: string;
  opponentName: string;
  onPlayAgain: () => void;
  onBackToLobby: () => void;
}

export const PVPMatchResults: React.FC<PVPMatchResultsProps> = ({
  result,
  playerName,
  opponentName,
  onPlayAgain,
  onBackToLobby,
}) => {
  const {
    winner,
    playerScore,
    opponentScore,
    playerTotalWpm,
    opponentTotalWpm,
    playerAvgAccuracy,
    opponentAvgAccuracy,
    xpEarned,
    ratingChange,
    newRating,
    roundResults,
    matchDuration
  } = result;

  const isWinner = winner === 'player';
  const isTie = winner === 'tie';

  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-3xl mx-auto px-4">
        {/* Victory/Defeat Animation */}
        <motion.div
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 200, delay: 0.1 }}
          className="text-center mb-8"
        >
          {/* Big Icon */}
          <motion.div
            initial={{ y: -50 }}
            animate={{ y: 0 }}
            transition={{ type: 'spring', stiffness: 100, delay: 0.3 }}
            className={`inline-flex items-center justify-center w-32 h-32 rounded-full mb-4 ${
              isWinner
                ? 'bg-gradient-to-br from-yellow-400 to-amber-600'
                : isTie
                ? 'bg-gradient-to-br from-gray-400 to-gray-600'
                : 'bg-gradient-to-br from-gray-600 to-gray-800'
            }`}
          >
            {isWinner ? (
              <Trophy className="w-16 h-16 text-white" />
            ) : isTie ? (
              <Medal className="w-16 h-16 text-white" />
            ) : (
              <Frown className="w-16 h-16 text-white" />
            )}
          </motion.div>

          <motion.h1
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className={`text-5xl font-bold mb-2 ${
              isWinner
                ? 'text-yellow-500'
                : isTie
                ? 'text-gray-500'
                : 'text-gray-700 dark:text-gray-300'
            }`}
          >
            {isWinner ? 'Victory!' : isTie ? 'Draw!' : 'Defeat'}
          </motion.h1>

          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6 }}
            className="text-gray-600 dark:text-gray-400 text-lg"
          >
            {isWinner
              ? 'Congratulations on your win!'
              : isTie
              ? 'A close match!'
              : 'Better luck next time!'}
          </motion.p>
        </motion.div>

        {/* Final Score */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.7 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-6"
        >
          <div className="text-center text-sm text-gray-500 mb-4">Final Score</div>
          <div className="flex justify-center items-center gap-8">
            <div className="text-center">
              <div className={`text-5xl font-bold ${
                isWinner ? 'text-green-500' : 'text-gray-900 dark:text-white'
              }`}>
                {playerScore}
              </div>
              <div className="text-gray-600 dark:text-gray-400 mt-1">{playerName}</div>
              {isWinner && <Crown className="w-6 h-6 text-yellow-500 mx-auto mt-2" />}
            </div>
            <div className="text-3xl font-bold text-gray-400">-</div>
            <div className="text-center">
              <div className={`text-5xl font-bold ${
                winner === 'opponent' ? 'text-green-500' : 'text-gray-900 dark:text-white'
              }`}>
                {opponentScore}
              </div>
              <div className="text-gray-600 dark:text-gray-400 mt-1">{opponentName}</div>
              {winner === 'opponent' && <Crown className="w-6 h-6 text-yellow-500 mx-auto mt-2" />}
            </div>
          </div>
        </motion.div>

        {/* Rewards */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.8 }}
          className="grid grid-cols-2 gap-4 mb-6"
        >
          {/* XP Earned */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 text-center">
            <Star className="w-8 h-8 mx-auto mb-2 text-yellow-500" />
            <div className="text-3xl font-bold text-yellow-500">+{xpEarned}</div>
            <div className="text-sm text-gray-500">XP Earned</div>
          </div>

          {/* Rating Change */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 text-center">
            {ratingChange >= 0 ? (
              <TrendingUp className="w-8 h-8 mx-auto mb-2 text-green-500" />
            ) : (
              <TrendingDown className="w-8 h-8 mx-auto mb-2 text-red-500" />
            )}
            <div className={`text-3xl font-bold ${
              ratingChange >= 0 ? 'text-green-500' : 'text-red-500'
            }`}>
              {ratingChange >= 0 ? '+' : ''}{ratingChange}
            </div>
            <div className="text-sm text-gray-500">Rating ({newRating})</div>
          </div>
        </motion.div>

        {/* Stats Comparison */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.9 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-6"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 text-center">
            Match Statistics
          </h3>

          <div className="space-y-4">
            {/* Average WPM */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-blue-500" />
                <span className="text-gray-600 dark:text-gray-400">Avg WPM</span>
              </div>
              <div className="flex items-center gap-4">
                <span className={`font-bold ${
                  playerTotalWpm > opponentTotalWpm ? 'text-green-500' : 'text-gray-900 dark:text-white'
                }`}>
                  {playerTotalWpm}
                </span>
                <span className="text-gray-400">vs</span>
                <span className={`font-bold ${
                  opponentTotalWpm > playerTotalWpm ? 'text-green-500' : 'text-gray-900 dark:text-white'
                }`}>
                  {opponentTotalWpm}
                </span>
              </div>
            </div>

            {/* Average Accuracy */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-green-500" />
                <span className="text-gray-600 dark:text-gray-400">Avg Accuracy</span>
              </div>
              <div className="flex items-center gap-4">
                <span className={`font-bold ${
                  playerAvgAccuracy > opponentAvgAccuracy ? 'text-green-500' : 'text-gray-900 dark:text-white'
                }`}>
                  {playerAvgAccuracy.toFixed(1)}%
                </span>
                <span className="text-gray-400">vs</span>
                <span className={`font-bold ${
                  opponentAvgAccuracy > playerAvgAccuracy ? 'text-green-500' : 'text-gray-900 dark:text-white'
                }`}>
                  {opponentAvgAccuracy.toFixed(1)}%
                </span>
              </div>
            </div>

            {/* Match Duration */}
            <div className="flex items-center justify-between border-t dark:border-gray-700 pt-4">
              <span className="text-gray-600 dark:text-gray-400">Match Duration</span>
              <span className="font-bold text-gray-900 dark:text-white">
                {formatDuration(matchDuration)}
              </span>
            </div>
          </div>
        </motion.div>

        {/* Round Breakdown */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-6"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 text-center">
            Round Breakdown
          </h3>

          <div className="space-y-3">
            {roundResults.map((round, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                    round.winner === (idx === 0 ? 1 : 2) // Simplified - actual logic would use player ID
                      ? 'bg-green-100 dark:bg-green-900/50 text-green-600'
                      : round.winner === null
                      ? 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-600'
                      : 'bg-red-100 dark:bg-red-900/50 text-red-600'
                  }`}>
                    {idx + 1}
                  </div>
                  <span className="text-gray-900 dark:text-white font-medium">
                    Round {idx + 1}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-gray-600 dark:text-gray-400">
                    {round.p1_wpm || 0} vs {round.p2_wpm || 0} WPM
                  </span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Action Buttons */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 1.1 }}
          className="flex flex-col sm:flex-row gap-4 justify-center"
        >
          <button
            onClick={onPlayAgain}
            className="flex-1 sm:flex-none px-8 py-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-xl font-semibold text-lg hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
          >
            <RotateCcw className="w-5 h-5" />
            Play Again
          </button>

          <button
            onClick={onBackToLobby}
            className="flex-1 sm:flex-none px-8 py-4 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-xl font-semibold text-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors flex items-center justify-center gap-2"
          >
            <Home className="w-5 h-5" />
            Back to Lobby
          </button>
        </motion.div>

        {/* Leaderboard Link */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
          className="mt-6 text-center"
        >
          <Link
            to="/typing-practice/leaderboard"
            className="text-blue-500 hover:text-blue-600 text-sm font-medium flex items-center justify-center gap-1"
          >
            <Award className="w-4 h-4" />
            View Leaderboard
          </Link>
        </motion.div>
      </div>
    </div>
  );
};

export default PVPMatchResults;
