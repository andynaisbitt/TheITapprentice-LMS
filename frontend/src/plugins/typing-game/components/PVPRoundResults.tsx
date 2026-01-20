// frontend/src/plugins/typing-game/components/PVPRoundResults.tsx
/**
 * PVP Round Results Component
 * Shows results after each round with winner/loser animation
 */

import React from 'react';
import { motion } from 'framer-motion';
import {
  Trophy,
  Zap,
  Target,
  Clock,
  ChevronRight,
  User,
  Crown,
  Minus
} from 'lucide-react';

export interface RoundResultData {
  roundNumber: number;
  playerWpm: number;
  opponentWpm: number;
  playerAccuracy: number;
  opponentAccuracy: number;
  winner: 'player' | 'opponent' | 'tie';
  currentScore: {
    player: number;
    opponent: number;
  };
}

interface PVPRoundResultsProps {
  result: RoundResultData;
  totalRounds: number;
  playerName: string;
  opponentName: string;
  onContinue: () => void;
  isLastRound: boolean;
}

export const PVPRoundResults: React.FC<PVPRoundResultsProps> = ({
  result,
  totalRounds,
  playerName,
  opponentName,
  onContinue,
  isLastRound,
}) => {
  const { roundNumber, playerWpm, opponentWpm, playerAccuracy, opponentAccuracy, winner, currentScore } = result;

  const isPlayerWinner = winner === 'player';
  const isOpponentWinner = winner === 'opponent';
  const isTie = winner === 'tie';

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8 flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className="max-w-2xl w-full mx-4"
      >
        {/* Round Header */}
        <motion.div
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="text-center mb-8"
        >
          <div className="text-gray-500 dark:text-gray-400 text-sm mb-2">
            Round {roundNumber} of {totalRounds}
          </div>
          <h1 className={`text-4xl font-bold ${
            isPlayerWinner ? 'text-green-500' :
            isOpponentWinner ? 'text-red-500' :
            'text-yellow-500'
          }`}>
            {isPlayerWinner ? 'You Won!' :
             isOpponentWinner ? 'You Lost' :
             'Tie!'}
          </h1>
        </motion.div>

        {/* Winner Highlight */}
        <motion.div
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
          className={`mx-auto w-24 h-24 rounded-full flex items-center justify-center mb-8 ${
            isPlayerWinner ? 'bg-gradient-to-br from-green-400 to-green-600' :
            isOpponentWinner ? 'bg-gradient-to-br from-red-400 to-red-600' :
            'bg-gradient-to-br from-yellow-400 to-yellow-600'
          }`}
        >
          {isTie ? (
            <Minus className="w-12 h-12 text-white" />
          ) : (
            <Crown className="w-12 h-12 text-white" />
          )}
        </motion.div>

        {/* Results Card */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden"
        >
          {/* VS Header */}
          <div className="bg-gradient-to-r from-blue-500 via-purple-500 to-orange-500 p-4">
            <div className="flex justify-between items-center text-white">
              <div className="text-center flex-1">
                <div className="text-lg font-medium">{playerName}</div>
                <div className="text-sm opacity-80">You</div>
              </div>
              <div className="text-2xl font-bold px-4">VS</div>
              <div className="text-center flex-1">
                <div className="text-lg font-medium">{opponentName}</div>
                <div className="text-sm opacity-80">Opponent</div>
              </div>
            </div>
          </div>

          {/* Stats Comparison */}
          <div className="p-6 space-y-6">
            {/* WPM */}
            <div className="space-y-2">
              <div className="flex items-center justify-center gap-2 text-sm text-gray-500">
                <Zap className="w-4 h-4" />
                Words Per Minute
              </div>
              <div className="flex items-center justify-between">
                <motion.div
                  initial={{ x: -20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: 0.4 }}
                  className={`text-3xl font-bold ${
                    playerWpm > opponentWpm ? 'text-green-500' :
                    playerWpm < opponentWpm ? 'text-red-500' :
                    'text-gray-900 dark:text-white'
                  }`}
                >
                  {playerWpm}
                </motion.div>
                <div className="flex-1 mx-4 h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden flex">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(playerWpm / (playerWpm + opponentWpm)) * 100}%` }}
                    transition={{ delay: 0.5, duration: 0.5 }}
                    className="h-full bg-blue-500"
                  />
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(opponentWpm / (playerWpm + opponentWpm)) * 100}%` }}
                    transition={{ delay: 0.5, duration: 0.5 }}
                    className="h-full bg-orange-500"
                  />
                </div>
                <motion.div
                  initial={{ x: 20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: 0.4 }}
                  className={`text-3xl font-bold ${
                    opponentWpm > playerWpm ? 'text-green-500' :
                    opponentWpm < playerWpm ? 'text-red-500' :
                    'text-gray-900 dark:text-white'
                  }`}
                >
                  {opponentWpm}
                </motion.div>
              </div>
            </div>

            {/* Accuracy */}
            <div className="space-y-2">
              <div className="flex items-center justify-center gap-2 text-sm text-gray-500">
                <Target className="w-4 h-4" />
                Accuracy
              </div>
              <div className="flex items-center justify-between">
                <motion.div
                  initial={{ x: -20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className={`text-3xl font-bold ${
                    playerAccuracy > opponentAccuracy ? 'text-green-500' :
                    playerAccuracy < opponentAccuracy ? 'text-red-500' :
                    'text-gray-900 dark:text-white'
                  }`}
                >
                  {playerAccuracy.toFixed(1)}%
                </motion.div>
                <div className="flex-1 mx-4 h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden flex">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${playerAccuracy}%` }}
                    transition={{ delay: 0.6, duration: 0.5 }}
                    className="h-full bg-blue-500"
                    style={{ maxWidth: '50%' }}
                  />
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${opponentAccuracy}%` }}
                    transition={{ delay: 0.6, duration: 0.5 }}
                    className="h-full bg-orange-500"
                    style={{ maxWidth: '50%', marginLeft: 'auto' }}
                  />
                </div>
                <motion.div
                  initial={{ x: 20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className={`text-3xl font-bold ${
                    opponentAccuracy > playerAccuracy ? 'text-green-500' :
                    opponentAccuracy < playerAccuracy ? 'text-red-500' :
                    'text-gray-900 dark:text-white'
                  }`}
                >
                  {opponentAccuracy.toFixed(1)}%
                </motion.div>
              </div>
            </div>
          </div>

          {/* Current Score */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
            className="bg-gray-50 dark:bg-gray-900 p-4"
          >
            <div className="text-center text-sm text-gray-500 mb-2">Match Score</div>
            <div className="flex justify-center items-center gap-8">
              <div className="text-center">
                <div className={`text-4xl font-bold ${
                  currentScore.player > currentScore.opponent ? 'text-green-500' : 'text-gray-900 dark:text-white'
                }`}>
                  {currentScore.player}
                </div>
                <div className="text-sm text-gray-500">{playerName}</div>
              </div>
              <div className="text-2xl font-bold text-gray-400">-</div>
              <div className="text-center">
                <div className={`text-4xl font-bold ${
                  currentScore.opponent > currentScore.player ? 'text-green-500' : 'text-gray-900 dark:text-white'
                }`}>
                  {currentScore.opponent}
                </div>
                <div className="text-sm text-gray-500">{opponentName}</div>
              </div>
            </div>
          </motion.div>
        </motion.div>

        {/* Continue Button */}
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.8 }}
          className="mt-6 text-center"
        >
          <button
            onClick={onContinue}
            className="px-8 py-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-xl font-semibold text-lg hover:opacity-90 transition-opacity flex items-center justify-center gap-2 mx-auto"
          >
            {isLastRound ? 'See Final Results' : 'Next Round'}
            <ChevronRight className="w-5 h-5" />
          </button>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default PVPRoundResults;
