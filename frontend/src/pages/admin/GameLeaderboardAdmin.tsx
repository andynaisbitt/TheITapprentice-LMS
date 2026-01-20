// src/pages/admin/GameLeaderboardAdmin.tsx
/**
 * Game Leaderboard Admin
 * View and manage typing game leaderboards
 */

import { useState, useEffect } from 'react';
import {
  Trophy,
  Medal,
  Search,
  Filter,
  Loader2,
  TrendingUp,
  Users,
  Keyboard,
  RotateCcw,
  Download,
  Ban,
} from 'lucide-react';

interface LeaderboardEntry {
  rank: number;
  user: {
    id: number;
    username: string;
    email: string;
  };
  best_wpm: number;
  avg_wpm: number;
  avg_accuracy: number;
  games_played: number;
  total_xp: number;
  last_played: string;
  is_suspicious: boolean;
}

interface LeaderboardStats {
  total_players: number;
  games_played_today: number;
  avg_wpm_global: number;
  top_wpm_today: number;
}

export const GameLeaderboardAdmin: React.FC = () => {
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [stats, setStats] = useState<LeaderboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'best_wpm' | 'avg_wpm' | 'games_played'>('best_wpm');
  const [period, setPeriod] = useState<'all' | 'month' | 'week' | 'today'>('all');

  useEffect(() => {
    loadLeaderboard();
  }, [sortBy, period]);

  const loadLeaderboard = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch(`/api/v1/games/typing/admin/leaderboard?sort=${sortBy}&period=${period}`);

      // Mock data
      setLeaderboard([
        { rank: 1, user: { id: 1, username: 'speedster_pro', email: 'speed@example.com' }, best_wpm: 145, avg_wpm: 128, avg_accuracy: 98.5, games_played: 342, total_xp: 15600, last_played: new Date(Date.now() - 1000 * 60 * 30).toISOString(), is_suspicious: false },
        { rank: 2, user: { id: 2, username: 'typing_ninja', email: 'ninja@example.com' }, best_wpm: 138, avg_wpm: 122, avg_accuracy: 97.8, games_played: 256, total_xp: 12400, last_played: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), is_suspicious: false },
        { rank: 3, user: { id: 3, username: 'keyboard_master', email: 'master@example.com' }, best_wpm: 132, avg_wpm: 118, avg_accuracy: 96.2, games_played: 198, total_xp: 9800, last_played: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(), is_suspicious: false },
        { rank: 4, user: { id: 4, username: 'quick_fingers', email: 'quick@example.com' }, best_wpm: 128, avg_wpm: 112, avg_accuracy: 95.4, games_played: 176, total_xp: 8200, last_played: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(), is_suspicious: false },
        { rank: 5, user: { id: 5, username: 'suspicious_user', email: 'sus@example.com' }, best_wpm: 200, avg_wpm: 195, avg_accuracy: 100, games_played: 5, total_xp: 500, last_played: new Date(Date.now() - 1000 * 60 * 60 * 1).toISOString(), is_suspicious: true },
        { rank: 6, user: { id: 6, username: 'code_typer', email: 'coder@example.com' }, best_wpm: 118, avg_wpm: 105, avg_accuracy: 94.8, games_played: 234, total_xp: 11200, last_played: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), is_suspicious: false },
        { rank: 7, user: { id: 7, username: 'word_warrior', email: 'warrior@example.com' }, best_wpm: 115, avg_wpm: 102, avg_accuracy: 93.5, games_played: 156, total_xp: 7400, last_played: new Date(Date.now() - 1000 * 60 * 60 * 36).toISOString(), is_suspicious: false },
        { rank: 8, user: { id: 8, username: 'daily_typer', email: 'daily@example.com' }, best_wpm: 108, avg_wpm: 95, avg_accuracy: 92.1, games_played: 412, total_xp: 18500, last_played: new Date(Date.now() - 1000 * 60 * 15).toISOString(), is_suspicious: false },
      ]);

      setStats({
        total_players: 1547,
        games_played_today: 342,
        avg_wpm_global: 62,
        top_wpm_today: 145,
      });
    } catch (error) {
      console.error('Failed to load leaderboard:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));

    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  };

  const handleBanUser = async (userId: number, username: string) => {
    if (!confirm(`Are you sure you want to ban "${username}" from the leaderboard?`)) return;
    // TODO: Implement ban API call
    alert(`User ${username} has been banned from the leaderboard`);
  };

  const handleResetStats = async (userId: number, username: string) => {
    if (!confirm(`Are you sure you want to reset stats for "${username}"? This cannot be undone.`)) return;
    // TODO: Implement reset API call
    alert(`Stats for ${username} have been reset`);
  };

  const getRankBadge = (rank: number) => {
    if (rank === 1) return <Medal className="w-5 h-5 text-yellow-500" />;
    if (rank === 2) return <Medal className="w-5 h-5 text-gray-400" />;
    if (rank === 3) return <Medal className="w-5 h-5 text-amber-600" />;
    return <span className="w-5 h-5 flex items-center justify-center text-sm font-bold text-gray-500">{rank}</span>;
  };

  const filteredLeaderboard = leaderboard.filter(entry => {
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      if (!entry.user.username.toLowerCase().includes(term) &&
          !entry.user.email.toLowerCase().includes(term)) {
        return false;
      }
    }
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Game Leaderboard
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            View and manage typing game rankings
          </p>
        </div>
        <button
          className="inline-flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors text-gray-700 dark:text-gray-300"
        >
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
            <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
              <Users className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {stats.total_players.toLocaleString()}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Players</p>
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
            <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
              <Keyboard className="w-6 h-6 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {stats.games_played_today}
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Games Today</p>
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <TrendingUp className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {stats.avg_wpm_global} WPM
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Global Average</p>
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl p-4 flex items-center gap-4">
            <div className="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
              <Trophy className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {stats.top_wpm_today} WPM
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">Top Score Today</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by username or email..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <select
          value={period}
          onChange={(e) => setPeriod(e.target.value as typeof period)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="all">All Time</option>
          <option value="month">This Month</option>
          <option value="week">This Week</option>
          <option value="today">Today</option>
        </select>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
          className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          <option value="best_wpm">Best WPM</option>
          <option value="avg_wpm">Average WPM</option>
          <option value="games_played">Games Played</option>
        </select>
      </div>

      {/* Leaderboard Table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider w-16">
                  Rank
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Player
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Best WPM
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Avg WPM
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Accuracy
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Games
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Total XP
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Last Played
                </th>
                <th className="px-4 py-3 w-20"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredLeaderboard.map((entry) => (
                <tr
                  key={entry.user.id}
                  className={`hover:bg-gray-50 dark:hover:bg-gray-700/50 ${
                    entry.is_suspicious ? 'bg-red-50 dark:bg-red-900/10' : ''
                  }`}
                >
                  <td className="px-4 py-4">
                    <div className="flex items-center justify-center">
                      {getRankBadge(entry.rank)}
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white text-sm font-semibold">
                        {entry.user.username[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
                          {entry.user.username}
                          {entry.is_suspicious && (
                            <span className="px-1.5 py-0.5 text-xs rounded bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400">
                              Suspicious
                            </span>
                          )}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {entry.user.email}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="font-bold text-lg text-primary">
                      {entry.best_wpm}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-center text-gray-900 dark:text-white">
                    {entry.avg_wpm}
                  </td>
                  <td className="px-4 py-4 text-center text-gray-900 dark:text-white">
                    {entry.avg_accuracy}%
                  </td>
                  <td className="px-4 py-4 text-center text-gray-600 dark:text-gray-300">
                    {entry.games_played}
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="text-primary font-medium">
                      {entry.total_xp.toLocaleString()}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-right text-sm text-gray-500 dark:text-gray-400">
                    {formatTimeAgo(entry.last_played)}
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleResetStats(entry.user.id, entry.user.username)}
                        className="p-2 text-gray-400 hover:text-yellow-500 transition-colors"
                        title="Reset Stats"
                      >
                        <RotateCcw className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleBanUser(entry.user.id, entry.user.username)}
                        className="p-2 text-gray-400 hover:text-red-500 transition-colors"
                        title="Ban from Leaderboard"
                      >
                        <Ban className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredLeaderboard.length === 0 && (
          <div className="text-center py-12">
            <Trophy className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-500 dark:text-gray-400">No players found</p>
          </div>
        )}
      </div>

      {/* Suspicious Activity Warning */}
      {leaderboard.some(e => e.is_suspicious) && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Ban className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-yellow-800 dark:text-yellow-200">
                Suspicious Activity Detected
              </p>
              <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                Some players have been flagged for unusually high scores with very few games played.
                Review and take action if necessary.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GameLeaderboardAdmin;
