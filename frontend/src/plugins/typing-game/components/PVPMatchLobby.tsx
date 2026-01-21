// frontend/src/plugins/typing-game/components/PVPMatchLobby.tsx
/**
 * PVP Match Lobby Component
 * Handles matchmaking, waiting for opponents, and pre-match preparation
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Swords,
  Loader2,
  Users,
  Trophy,
  Target,
  Zap,
  Clock,
  X,
  RefreshCw,
  User,
  Shield
} from 'lucide-react';
import { typingGameApi } from '../services/typingGameApi';
import type { PVPMatch, Difficulty, UserPVPStats } from '../types';

export interface PVPGameSettings {
  rounds: 1 | 3 | 5;
  timePerRound: 30 | 60 | 90;
  allowBackspace: boolean;
  difficulty: Difficulty;
}

interface PVPMatchLobbyProps {
  onMatchFound: (match: PVPMatch, settings: PVPGameSettings) => void;
  onCancel: () => void;
}

export const PVPMatchLobby: React.FC<PVPMatchLobbyProps> = ({
  onMatchFound,
  onCancel,
}) => {
  const [isSearching, setIsSearching] = useState(false);
  const [currentMatch, setCurrentMatch] = useState<PVPMatch | null>(null);
  const [pvpStats, setPvpStats] = useState<UserPVPStats | null>(null);
  const [searchTime, setSearchTime] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [showSettings, setShowSettings] = useState(false);

  // Game settings
  const [settings, setSettings] = useState<PVPGameSettings>({
    rounds: 3,
    timePerRound: 60,
    allowBackspace: true,
    difficulty: 'medium',
  });

  // Fetch PVP stats on mount
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const stats = await typingGameApi.getMyPVPStats();
        setPvpStats(stats);
      } catch (err) {
        console.error('Failed to fetch PVP stats:', err);
      } finally {
        setLoadingStats(false);
      }
    };
    fetchStats();
  }, []);

  // Search time counter
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isSearching) {
      interval = setInterval(() => {
        setSearchTime((prev) => prev + 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isSearching]);

  // Poll for match status when waiting
  useEffect(() => {
    let pollInterval: NodeJS.Timeout;

    if (currentMatch && currentMatch.status === 'WAITING') {
      pollInterval = setInterval(async () => {
        try {
          const updatedMatch = await typingGameApi.getPVPMatch(currentMatch.id);
          if (updatedMatch.status === 'IN_PROGRESS' || updatedMatch.player2_id) {
            setCurrentMatch(updatedMatch);
            onMatchFound(updatedMatch, settings);
          }
        } catch (err) {
          console.error('Failed to poll match status:', err);
        }
      }, 2000);
    }

    return () => clearInterval(pollInterval);
  }, [currentMatch, onMatchFound, settings]);

  const handleFindMatch = useCallback(async () => {
    setIsSearching(true);
    setError(null);
    setSearchTime(0);

    try {
      const match = await typingGameApi.findPVPMatch({
        difficulty: settings.difficulty,
      });

      setCurrentMatch(match);

      // If match already has opponent, proceed immediately
      if (match.player2_id || match.status === 'IN_PROGRESS') {
        onMatchFound(match, settings);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to find match');
      setIsSearching(false);
    }
  }, [settings, onMatchFound]);

  const handleCancelSearch = useCallback(async () => {
    if (currentMatch) {
      try {
        await typingGameApi.cancelPVPMatch(currentMatch.id);
      } catch (err) {
        console.error('Failed to cancel match:', err);
      }
    }
    setIsSearching(false);
    setCurrentMatch(null);
    setSearchTime(0);
    onCancel();
  }, [currentMatch, onCancel]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const difficulties: { value: Difficulty; label: string; description: string; color: string }[] = [
    { value: 'easy', label: 'Easy', description: 'Relaxed pace', color: 'from-green-500 to-emerald-600' },
    { value: 'medium', label: 'Medium', description: 'Balanced challenge', color: 'from-blue-500 to-indigo-600' },
    { value: 'hard', label: 'Hard', description: 'Fast & precise', color: 'from-orange-500 to-red-600' },
    { value: 'expert', label: 'Expert', description: 'For the elite', color: 'from-purple-500 to-pink-600' },
  ];

  const getRatingTierColor = (tier: string) => {
    const tierColors: Record<string, string> = {
      'Bronze': 'text-orange-600',
      'Silver': 'text-gray-400',
      'Gold': 'text-yellow-500',
      'Platinum': 'text-cyan-400',
      'Diamond': 'text-blue-400',
      'Master': 'text-purple-500',
      'Grandmaster': 'text-red-500',
    };
    return tierColors[tier] || 'text-gray-500';
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8"
        >
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-red-500 to-orange-600 rounded-2xl mb-4 shadow-lg">
            <Swords className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            PVP Battle Arena
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Challenge other players in real-time typing battles
          </p>
        </motion.div>

        {/* Main Content */}
        <div className="grid md:grid-cols-2 gap-6">
          {/* Left Column - Stats & Rankings */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="space-y-4"
          >
            {/* Player Stats Card */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <Trophy className="w-5 h-5 text-yellow-500" />
                Your PVP Stats
              </h2>

              {loadingStats ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
                </div>
              ) : pvpStats ? (
                <div className="space-y-4">
                  {/* Rating Display */}
                  <div className="text-center p-4 bg-gradient-to-br from-gray-100 to-gray-50 dark:from-gray-700 dark:to-gray-800 rounded-lg">
                    <div className={`text-3xl font-bold ${getRatingTierColor(pvpStats.rating_tier)}`}>
                      {pvpStats.current_rating}
                    </div>
                    <div className="text-sm text-gray-600 dark:text-gray-400">
                      {pvpStats.rating_tier} Rank
                    </div>
                    <div className="text-xs text-gray-500 mt-1">
                      Peak: {pvpStats.peak_rating}
                    </div>
                  </div>

                  {/* Stats Grid */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="text-center p-3 bg-green-50 dark:bg-green-900/30 rounded-lg">
                      <div className="text-xl font-bold text-green-600 dark:text-green-400">
                        {pvpStats.wins}
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Wins</div>
                    </div>
                    <div className="text-center p-3 bg-red-50 dark:bg-red-900/30 rounded-lg">
                      <div className="text-xl font-bold text-red-600 dark:text-red-400">
                        {pvpStats.losses}
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Losses</div>
                    </div>
                    <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/30 rounded-lg">
                      <div className="text-xl font-bold text-blue-600 dark:text-blue-400">
                        {(pvpStats.win_rate * 100).toFixed(0)}%
                      </div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Win Rate</div>
                    </div>
                  </div>

                  {/* Performance Stats */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="flex items-center gap-2 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                      <Zap className="w-4 h-4 text-yellow-500" />
                      <div>
                        <div className="font-semibold text-gray-900 dark:text-white">
                          {pvpStats.best_wpm} WPM
                        </div>
                        <div className="text-xs text-gray-500">Best Speed</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                      <Target className="w-4 h-4 text-green-500" />
                      <div>
                        <div className="font-semibold text-gray-900 dark:text-white">
                          {pvpStats.avg_accuracy.toFixed(1)}%
                        </div>
                        <div className="text-xs text-gray-500">Avg Accuracy</div>
                      </div>
                    </div>
                  </div>

                  {/* Streak */}
                  {pvpStats.current_win_streak > 0 && (
                    <div className="flex items-center justify-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/30 rounded-lg">
                      <Shield className="w-4 h-4 text-yellow-500" />
                      <span className="text-sm font-medium text-yellow-700 dark:text-yellow-300">
                        {pvpStats.current_win_streak} Win Streak!
                      </span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <User className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No PVP matches yet</p>
                  <p className="text-sm">Start playing to build your rating!</p>
                </div>
              )}
            </div>
          </motion.div>

          {/* Right Column - Matchmaking */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
          >
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <Users className="w-5 h-5 text-blue-500" />
                Find Match
              </h2>

              <AnimatePresence mode="wait">
                {!isSearching ? (
                  <motion.div
                    key="select"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="space-y-4"
                  >
                    {/* Difficulty Selection */}
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Select Difficulty
                      </label>
                      <div className="grid grid-cols-2 gap-2">
                        {difficulties.map((diff) => (
                          <button
                            key={diff.value}
                            onClick={() => setSettings(s => ({ ...s, difficulty: diff.value }))}
                            className={`p-3 rounded-lg border-2 transition-all ${
                              settings.difficulty === diff.value
                                ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/30'
                                : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                            }`}
                          >
                            <div className="font-medium text-gray-900 dark:text-white">
                              {diff.label}
                            </div>
                            <div className="text-xs text-gray-500">{diff.description}</div>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Game Settings Toggle */}
                    <button
                      onClick={() => setShowSettings(!showSettings)}
                      className="w-full py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white flex items-center justify-center gap-2"
                    >
                      <RefreshCw className={`w-4 h-4 transition-transform ${showSettings ? 'rotate-180' : ''}`} />
                      {showSettings ? 'Hide' : 'Show'} Game Settings
                    </button>

                    {/* Expanded Settings Panel */}
                    <AnimatePresence>
                      {showSettings && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden"
                        >
                          <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-4">
                            {/* Rounds Selection */}
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Number of Rounds
                              </label>
                              <div className="flex gap-2">
                                {[1, 3, 5].map((r) => (
                                  <button
                                    key={r}
                                    onClick={() => setSettings(s => ({ ...s, rounds: r as 1 | 3 | 5 }))}
                                    className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${
                                      settings.rounds === r
                                        ? 'bg-blue-500 text-white'
                                        : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600'
                                    }`}
                                  >
                                    Best of {r}
                                  </button>
                                ))}
                              </div>
                            </div>

                            {/* Time Per Round */}
                            <div>
                              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Time Per Round
                              </label>
                              <div className="flex gap-2">
                                {[30, 60, 90].map((t) => (
                                  <button
                                    key={t}
                                    onClick={() => setSettings(s => ({ ...s, timePerRound: t as 30 | 60 | 90 }))}
                                    className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${
                                      settings.timePerRound === t
                                        ? 'bg-blue-500 text-white'
                                        : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600'
                                    }`}
                                  >
                                    {t}s
                                  </button>
                                ))}
                              </div>
                            </div>

                            {/* Backspace Toggle */}
                            <div className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-600">
                              <div>
                                <div className="font-medium text-gray-900 dark:text-white text-sm">
                                  Allow Corrections
                                </div>
                                <div className="text-xs text-gray-500">
                                  {settings.allowBackspace
                                    ? 'Players can use backspace to fix mistakes'
                                    : 'No backspace - mistakes are permanent'}
                                </div>
                              </div>
                              <button
                                onClick={() => setSettings(s => ({ ...s, allowBackspace: !s.allowBackspace }))}
                                className={`relative w-12 h-6 rounded-full transition-colors ${
                                  settings.allowBackspace
                                    ? 'bg-green-500'
                                    : 'bg-gray-300 dark:bg-gray-600'
                                }`}
                              >
                                <motion.div
                                  className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
                                  animate={{ left: settings.allowBackspace ? 28 : 4 }}
                                  transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                                />
                              </button>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* Error Message */}
                    {error && (
                      <div className="p-3 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-lg text-sm">
                        {error}
                      </div>
                    )}

                    {/* Find Match Button */}
                    <button
                      onClick={handleFindMatch}
                      className="w-full py-4 bg-gradient-to-r from-red-500 to-orange-600 text-white rounded-xl font-semibold text-lg hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
                    >
                      <Swords className="w-5 h-5" />
                      Find Opponent
                    </button>

                    {/* Match Info */}
                    <div className="text-center text-sm text-gray-500">
                      <p>You'll be matched with a player of similar skill level</p>
                      <p className="mt-1">
                        Best of {settings.rounds} rounds • {settings.timePerRound}s per round
                        {!settings.allowBackspace && ' • No corrections'}
                      </p>
                    </div>
                  </motion.div>
                ) : (
                  <motion.div
                    key="searching"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="text-center py-8"
                  >
                    {/* Searching Animation */}
                    <div className="relative inline-flex items-center justify-center w-24 h-24 mb-6">
                      <motion.div
                        className="absolute inset-0 rounded-full bg-gradient-to-r from-red-500 to-orange-600 opacity-20"
                        animate={{ scale: [1, 1.5, 1], opacity: [0.2, 0, 0.2] }}
                        transition={{ duration: 2, repeat: Infinity }}
                      />
                      <motion.div
                        className="absolute inset-2 rounded-full bg-gradient-to-r from-red-500 to-orange-600 opacity-30"
                        animate={{ scale: [1, 1.3, 1], opacity: [0.3, 0, 0.3] }}
                        transition={{ duration: 2, repeat: Infinity, delay: 0.3 }}
                      />
                      <div className="w-16 h-16 bg-gradient-to-r from-red-500 to-orange-600 rounded-full flex items-center justify-center">
                        <Loader2 className="w-8 h-8 text-white animate-spin" />
                      </div>
                    </div>

                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                      Searching for Opponent...
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400 mb-2">
                      {settings.difficulty.charAt(0).toUpperCase() + settings.difficulty.slice(1)} difficulty
                    </p>
                    <p className="text-xs text-gray-500 mb-4">
                      Best of {settings.rounds} • {settings.timePerRound}s rounds
                      {!settings.allowBackspace && ' • No corrections'}
                    </p>

                    {/* Search Time */}
                    <div className="flex items-center justify-center gap-2 text-gray-500 mb-6">
                      <Clock className="w-4 h-4" />
                      <span>{formatTime(searchTime)}</span>
                    </div>

                    {/* Cancel Button */}
                    <button
                      onClick={handleCancelSearch}
                      className="px-6 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg font-medium hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors flex items-center justify-center gap-2 mx-auto"
                    >
                      <X className="w-4 h-4" />
                      Cancel Search
                    </button>

                    {/* Tips while waiting */}
                    <div className="mt-8 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg text-left">
                      <h4 className="font-medium text-gray-900 dark:text-white mb-2">
                        Tips while you wait:
                      </h4>
                      <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                        <li>• Keep your fingers on the home row</li>
                        <li>• Focus on accuracy over speed</li>
                        <li>• Stay calm - rushed typing leads to errors</li>
                      </ul>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        </div>

        {/* Back Button */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="mt-6 text-center"
        >
          <button
            onClick={onCancel}
            className="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
          >
            Back to Typing Games
          </button>
        </motion.div>
      </div>
    </div>
  );
};

export default PVPMatchLobby;
