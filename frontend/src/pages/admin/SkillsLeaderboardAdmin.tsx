// src/pages/admin/SkillsLeaderboardAdmin.tsx
/**
 * Skills Leaderboard Admin Page
 * View IT Level rankings, recent XP activity, and skill progression
 */

import { useState, useEffect } from 'react';
import {
  Trophy,
  Search,
  Loader2,
  Crown,
  Medal,
  TrendingUp,
  Zap,
  Clock,
  Filter,
  User,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { apiClient } from '../../services/api/client';

// Types
interface LeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  avatar_url?: string;
  it_level: number;
  total_level: number;
  total_xp: number;
  specialization: string;
}

interface RecentXPActivity {
  id: number;
  user_id: number;
  username: string;
  skill_name: string;
  skill_icon: string;
  xp_gained: number;
  source_type: string;
  level_before: number;
  level_after: number;
  earned_at: string;
}

interface Skill {
  id: number;
  name: string;
  slug: string;
  icon: string;
}

const SkillsLeaderboardAdmin: React.FC = () => {
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [recentActivity, setRecentActivity] = useState<RecentXPActivity[]>([]);
  const [skills, setSkills] = useState<Skill[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingActivity, setLoadingActivity] = useState(true);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [leaderboardType, setLeaderboardType] = useState<'it_level' | 'total_level'>('it_level');
  const [selectedSkill, setSelectedSkill] = useState<string>('');
  const [activityLimit, setActivityLimit] = useState(50);
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    loadSkills();
  }, []);

  useEffect(() => {
    loadLeaderboard();
  }, [leaderboardType, selectedSkill]);

  useEffect(() => {
    loadRecentActivity();
  }, [activityLimit]);

  const loadSkills = async () => {
    try {
      const response = await apiClient.get('/api/v1/skills/');
      setSkills(response.data);
    } catch (error) {
      console.error('Failed to load skills:', error);
    }
  };

  const loadLeaderboard = async () => {
    setLoading(true);
    try {
      let url = `/api/v1/skills/leaderboards/global?leaderboard_type=${leaderboardType}&limit=100`;
      if (selectedSkill) {
        url = `/api/v1/skills/leaderboards/${selectedSkill}/leaderboard?limit=100`;
      }
      const response = await apiClient.get(url);
      const data = response.data;
      setLeaderboard(Array.isArray(data) ? data : data.entries ?? []);
    } catch (error) {
      console.error('Failed to load leaderboard:', error);
      setLeaderboard([]);
    } finally {
      setLoading(false);
    }
  };

  const loadRecentActivity = async () => {
    setLoadingActivity(true);
    try {
      const response = await apiClient.get(`/api/v1/admin/skills/analytics/xp-logs/recent?limit=${activityLimit}`);
      setRecentActivity(response.data);
    } catch (error) {
      console.error('Failed to load recent activity:', error);
      setRecentActivity([]);
    } finally {
      setLoadingActivity(false);
    }
  };

  const getRankBadge = (rank: number) => {
    if (rank === 1) {
      return (
        <div className="flex items-center justify-center w-8 h-8 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full">
          <Crown className="w-4 h-4 text-white" />
        </div>
      );
    }
    if (rank === 2) {
      return (
        <div className="flex items-center justify-center w-8 h-8 bg-gradient-to-br from-gray-300 to-gray-500 rounded-full">
          <Medal className="w-4 h-4 text-white" />
        </div>
      );
    }
    if (rank === 3) {
      return (
        <div className="flex items-center justify-center w-8 h-8 bg-gradient-to-br from-orange-400 to-orange-600 rounded-full">
          <Medal className="w-4 h-4 text-white" />
        </div>
      );
    }
    return (
      <div className="flex items-center justify-center w-8 h-8 bg-gray-100 dark:bg-gray-700 rounded-full text-gray-600 dark:text-gray-400 font-medium text-sm">
        {rank}
      </div>
    );
  };

  const getSourceTypeColor = (source: string) => {
    const colors: Record<string, string> = {
      quiz: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
      tutorial: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
      course: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
      typing_game: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
      achievement: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-400',
    };
    return colors[source] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
  };

  const formatTimeAgo = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const filteredLeaderboard = leaderboard.filter(entry => {
    if (searchTerm) {
      return entry.username.toLowerCase().includes(searchTerm.toLowerCase());
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Trophy className="w-7 h-7 text-yellow-500" />
            Skills Leaderboard
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            View IT Level rankings and monitor XP activity
          </p>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="inline-flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
        >
          <Filter className="w-4 h-4" />
          Filters
          {showFilters ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Search User
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by username..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Leaderboard Type
              </label>
              <select
                value={leaderboardType}
                onChange={(e) => {
                  setLeaderboardType(e.target.value as 'it_level' | 'total_level');
                  setSelectedSkill('');
                }}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                <option value="it_level">IT Level</option>
                <option value="total_level">Total Level</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Filter by Skill
              </label>
              <select
                value={selectedSkill}
                onChange={(e) => setSelectedSkill(e.target.value)}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                <option value="">All Skills (Global)</option>
                {skills.map((skill) => (
                  <option key={skill.slug} value={skill.slug}>
                    {skill.icon} {skill.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Activity Limit
              </label>
              <select
                value={activityLimit}
                onChange={(e) => setActivityLimit(parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                <option value="25">Last 25</option>
                <option value="50">Last 50</option>
                <option value="100">Last 100</option>
                <option value="200">Last 200</option>
              </select>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Leaderboard */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-green-500" />
              {selectedSkill ? `${skills.find(s => s.slug === selectedSkill)?.name || 'Skill'} Rankings` : 'Global Rankings'}
            </h2>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredLeaderboard.length} users
            </span>
          </div>

          <div className="max-h-[600px] overflow-y-auto">
            {loading ? (
              <div className="flex justify-center py-12">
                <Loader2 className="w-8 h-8 animate-spin text-primary" />
              </div>
            ) : filteredLeaderboard.length > 0 ? (
              <div className="divide-y divide-gray-100 dark:divide-gray-700">
                {filteredLeaderboard.map((entry) => (
                  <div
                    key={entry.user_id}
                    className="flex items-center gap-4 p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                  >
                    {getRankBadge(entry.rank)}

                    <div className="flex-shrink-0">
                      {entry.avatar_url ? (
                        <img
                          src={entry.avatar_url}
                          alt={entry.username}
                          className="w-10 h-10 rounded-full object-cover"
                        />
                      ) : (
                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-white font-medium">
                          {entry.username[0].toUpperCase()}
                        </div>
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-gray-900 dark:text-white truncate">
                        {entry.username}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {entry.specialization}
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-lg font-bold text-blue-600 dark:text-blue-400">
                        {selectedSkill ? `Lv. ${entry.it_level}` : entry.it_level}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {selectedSkill ? `${entry.total_xp.toLocaleString()} XP` : `Total: ${entry.total_level}`}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12">
                <User className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                <p className="text-gray-500 dark:text-gray-400">No users found</p>
              </div>
            )}
          </div>
        </div>

        {/* Recent XP Activity */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h2 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-500" />
              Recent XP Activity
            </h2>
            <button
              onClick={loadRecentActivity}
              disabled={loadingActivity}
              className="text-sm text-primary hover:text-primary-dark flex items-center gap-1"
            >
              {loadingActivity ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                'Refresh'
              )}
            </button>
          </div>

          <div className="max-h-[600px] overflow-y-auto">
            {loadingActivity ? (
              <div className="flex justify-center py-12">
                <Loader2 className="w-8 h-8 animate-spin text-primary" />
              </div>
            ) : recentActivity.length > 0 ? (
              <div className="divide-y divide-gray-100 dark:divide-gray-700">
                {recentActivity.map((activity) => (
                  <div
                    key={activity.id}
                    className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-xl">{activity.skill_icon}</span>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-gray-900 dark:text-white">
                            {activity.username}
                          </span>
                          <span className="text-gray-500 dark:text-gray-400">earned</span>
                          <span className="font-semibold text-green-600 dark:text-green-400">
                            +{activity.xp_gained} XP
                          </span>
                          <span className="text-gray-500 dark:text-gray-400">in</span>
                          <span className="font-medium text-gray-900 dark:text-white">
                            {activity.skill_name}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 mt-1">
                          <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${getSourceTypeColor(activity.source_type)}`}>
                            {activity.source_type.replace('_', ' ')}
                          </span>

                          {activity.level_after > activity.level_before && (
                            <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gradient-to-r from-yellow-400 to-orange-500 text-white">
                              Level Up! {activity.level_before} → {activity.level_after}
                            </span>
                          )}

                          <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1 ml-auto">
                            <Clock className="w-3 h-3" />
                            {formatTimeAgo(activity.earned_at)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12">
                <Zap className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                <p className="text-gray-500 dark:text-gray-400">No recent activity</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SkillsLeaderboardAdmin;
