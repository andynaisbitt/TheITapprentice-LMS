// frontend/src/plugins/typing-game/pages/TypingAnalyticsDashboard.tsx
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  BarChart3, TrendingUp, Target, Keyboard, Clock,
  Award, Zap, AlertTriangle, Lightbulb, RefreshCw
} from 'lucide-react';
import { apiClient } from '../../../services/api/client';
import StreakDisplay from '../components/StreakDisplay';
import DailyChallengeCard from '../components/DailyChallengeCard';
import LetterAccuracyHeatmap from '../components/LetterAccuracyHeatmap';

interface AnalyticsSummary {
  typing_stats: {
    best_wpm: number;
    avg_wpm: number;
    best_accuracy: number;
    avg_accuracy: number;
    total_games: number;
    total_time_minutes: number;
    total_words_typed: number;
  };
  letter_analysis: {
    overall_accuracy: number;
    total_letters_tracked: number;
    weak_letters: Array<{
      character: string;
      accuracy: number;
      attempts: number;
      avg_time_ms: number | null;
      common_mistakes: Array<{ typed: string; count: number }>;
    }>;
    letter_heatmap: Array<{
      character: string;
      accuracy: number;
      attempts: number;
    }>;
  };
  pattern_analysis: {
    weak_patterns: Array<{
      pattern: string;
      accuracy: number;
      attempts: number;
      avg_time_ms: number | null;
    }>;
  };
  recommendations: Array<{
    type: string;
    target: string;
    accuracy: number;
    suggestion: string;
    priority: 'high' | 'medium' | 'low';
  }>;
}

interface DailyChallengesResponse {
  challenges: Array<{
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
  }>;
  streak: {
    current_streak: number;
    longest_streak: number;
    games_today: number;
    freeze_available: boolean;
    streak_at_risk: boolean;
    played_today: boolean;
  };
  date: string;
}

export function TypingAnalyticsDashboard() {
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null);
  const [dailyData, setDailyData] = useState<DailyChallengesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [claimingId, setClaimingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [analyticsRes, dailyRes] = await Promise.all([
        apiClient.get('/api/v1/games/typing/analytics/me'),
        apiClient.get('/api/v1/games/typing/challenges/daily'),
      ]);
      setAnalytics(analyticsRes.data);
      setDailyData(dailyRes.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load analytics');
    } finally {
      setLoading(false);
    }
  };

  const handleClaimReward = async (challengeId: string) => {
    setClaimingId(challengeId);
    try {
      await apiClient.post(`/api/v1/games/typing/challenges/${challengeId}/claim`);
      // Refresh data
      const dailyRes = await apiClient.get('/api/v1/games/typing/challenges/daily');
      setDailyData(dailyRes.data);
    } catch (err: any) {
      console.error('Failed to claim reward:', err);
    } finally {
      setClaimingId(null);
    }
  };

  const handleUseFreeze = async () => {
    try {
      await apiClient.post('/api/v1/games/typing/streak/freeze');
      const dailyRes = await apiClient.get('/api/v1/games/typing/challenges/daily');
      setDailyData(dailyRes.data);
    } catch (err: any) {
      console.error('Failed to use freeze:', err);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-gray-600 dark:text-gray-400">Loading your analytics...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-red-600 dark:text-red-400 mb-4">{error}</p>
          <button
            onClick={fetchData}
            className="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 flex items-center gap-2 mx-auto"
          >
            <RefreshCw className="w-4 h-4" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  const stats = analytics?.typing_stats;
  const letterAnalysis = analytics?.letter_analysis;
  const recommendations = analytics?.recommendations || [];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-4 md:p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
              <BarChart3 className="w-7 h-7 text-blue-500" />
              Typing Analytics
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Track your progress and improve your typing skills
            </p>
          </div>
          <button
            onClick={fetchData}
            className="p-2 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Refresh data"
          >
            <RefreshCw className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left column - Stats and Charts */}
          <div className="lg:col-span-2 space-y-6">
            {/* Quick Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl p-4 text-white"
              >
                <Zap className="w-6 h-6 mb-2 opacity-80" />
                <div className="text-2xl font-bold">{stats?.best_wpm || 0}</div>
                <div className="text-sm opacity-80">Best WPM</div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl p-4 text-white"
              >
                <Target className="w-6 h-6 mb-2 opacity-80" />
                <div className="text-2xl font-bold">{stats?.best_accuracy?.toFixed(1) || 0}%</div>
                <div className="text-sm opacity-80">Best Accuracy</div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl p-4 text-white"
              >
                <Keyboard className="w-6 h-6 mb-2 opacity-80" />
                <div className="text-2xl font-bold">{stats?.total_games || 0}</div>
                <div className="text-sm opacity-80">Games Played</div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="bg-gradient-to-br from-orange-500 to-amber-600 rounded-xl p-4 text-white"
              >
                <Clock className="w-6 h-6 mb-2 opacity-80" />
                <div className="text-2xl font-bold">{stats?.total_time_minutes || 0}</div>
                <div className="text-sm opacity-80">Minutes Practiced</div>
              </motion.div>
            </div>

            {/* Average stats row */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm">
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-sm mb-1">
                  <TrendingUp className="w-4 h-4" />
                  Average WPM
                </div>
                <div className="text-xl font-bold text-gray-900 dark:text-white">
                  {stats?.avg_wpm?.toFixed(1) || 0}
                </div>
              </div>
              <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm">
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-sm mb-1">
                  <Target className="w-4 h-4" />
                  Average Accuracy
                </div>
                <div className="text-xl font-bold text-gray-900 dark:text-white">
                  {stats?.avg_accuracy?.toFixed(1) || 0}%
                </div>
              </div>
              <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm">
                <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 text-sm mb-1">
                  <Award className="w-4 h-4" />
                  Words Typed
                </div>
                <div className="text-xl font-bold text-gray-900 dark:text-white">
                  {(stats?.total_words_typed || 0).toLocaleString()}
                </div>
              </div>
            </div>

            {/* Keyboard Heatmap */}
            {letterAnalysis && (
              <LetterAccuracyHeatmap letterStats={letterAnalysis.letter_heatmap} />
            )}

            {/* Recommendations */}
            {recommendations.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                  <Lightbulb className="w-5 h-5 text-yellow-500" />
                  Practice Recommendations
                </h3>
                <div className="space-y-3">
                  {recommendations.map((rec, index) => (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className={`p-3 rounded-lg border ${
                        rec.priority === 'high'
                          ? 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800'
                          : 'bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                            rec.priority === 'high'
                              ? 'bg-red-200 text-red-700 dark:bg-red-800 dark:text-red-200'
                              : 'bg-yellow-200 text-yellow-700 dark:bg-yellow-800 dark:text-yellow-200'
                          }`}>
                            {rec.priority}
                          </span>
                          <span className="ml-2 text-sm text-gray-600 dark:text-gray-400">
                            {rec.type === 'letter' ? 'Letter' : 'Pattern'}: <strong>{rec.target}</strong>
                          </span>
                        </div>
                        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                          {rec.accuracy}% accuracy
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        {rec.suggestion}
                      </p>
                    </motion.div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right column - Streak and Challenges */}
          <div className="space-y-6">
            {/* Streak */}
            {dailyData?.streak && (
              <StreakDisplay
                streak={dailyData.streak}
                onUseFreeze={handleUseFreeze}
              />
            )}

            {/* Daily Challenges */}
            <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-lg">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                Daily Challenges
              </h3>
              <div className="space-y-4">
                {dailyData?.challenges.map((challenge) => (
                  <DailyChallengeCard
                    key={challenge.challenge_id}
                    challenge={challenge}
                    onClaim={handleClaimReward}
                    claiming={claimingId === challenge.challenge_id}
                  />
                ))}
                {(!dailyData?.challenges || dailyData.challenges.length === 0) && (
                  <p className="text-center text-gray-500 dark:text-gray-400 py-8">
                    No challenges available today. Check back tomorrow!
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default TypingAnalyticsDashboard;
