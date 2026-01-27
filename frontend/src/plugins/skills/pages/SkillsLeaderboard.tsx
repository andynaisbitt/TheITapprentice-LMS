// frontend/src/plugins/skills/pages/SkillsLeaderboard.tsx
/**
 * Skills Leaderboard Page - Global IT Level rankings
 */

import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../../state/contexts/AuthContext';
import { skillsApi } from '../services/skillsApi';
import type { GlobalLeaderboard, Skill } from '../types';
import { Trophy, Medal, Crown, Star, ArrowLeft, User } from 'lucide-react';

// Rank badge component
const RankBadge: React.FC<{ rank: number }> = ({ rank }) => {
  if (rank === 1) {
    return (
      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-yellow-300 to-yellow-500 flex items-center justify-center shadow-lg">
        <Crown className="w-6 h-6 text-yellow-900" />
      </div>
    );
  }
  if (rank === 2) {
    return (
      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-gray-200 to-gray-400 flex items-center justify-center shadow-lg">
        <Medal className="w-6 h-6 text-gray-700" />
      </div>
    );
  }
  if (rank === 3) {
    return (
      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-amber-400 to-amber-600 flex items-center justify-center shadow-lg">
        <Medal className="w-6 h-6 text-amber-900" />
      </div>
    );
  }
  return (
    <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center text-gray-600 dark:text-gray-400 font-bold">
      {rank}
    </div>
  );
};

export const SkillsLeaderboard: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const [leaderboard, setLeaderboard] = useState<GlobalLeaderboard | null>(null);
  const [skills, setSkills] = useState<Skill[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSkill, setSelectedSkill] = useState<string>('global');

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch all skills for dropdown
        const skillsData = await skillsApi.getAllSkills();
        setSkills(skillsData.skills);

        // Fetch global leaderboard
        const lb = await skillsApi.getGlobalLeaderboard(100);
        setLeaderboard(lb);
      } catch (err: any) {
        console.error('Failed to fetch leaderboard:', err);
        setError(err.response?.data?.detail || 'Failed to load leaderboard');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-48 mb-8" />
          <div className="space-y-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
          <p className="text-red-600 dark:text-red-400">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      {/* Back link */}
      <Link
        to="/skills"
        className="inline-flex items-center text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 mb-6"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Skills
      </Link>

      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-yellow-100 dark:bg-yellow-900/30 mb-4">
          <Trophy className="w-8 h-8 text-yellow-500" />
        </div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          IT Level Leaderboard
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Top players ranked by overall IT Level
        </p>
      </div>

      {/* User's rank (if logged in) */}
      {isAuthenticated && leaderboard?.userRank && (
        <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl p-6 mb-8 text-white">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center">
                <User className="w-6 h-6" />
              </div>
              <div>
                <div className="font-bold text-lg">Your Ranking</div>
                <div className="opacity-90">Keep learning to climb higher!</div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-4xl font-bold">#{leaderboard.userRank}</div>
              <div className="opacity-90">of {leaderboard.totalParticipants} players</div>
            </div>
          </div>
        </div>
      )}

      {/* Leaderboard table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        {/* Header */}
        <div className="bg-gray-50 dark:bg-gray-700 px-6 py-4 border-b border-gray-200 dark:border-gray-600">
          <div className="grid grid-cols-12 gap-4 text-sm font-medium text-gray-500 dark:text-gray-400">
            <div className="col-span-1">Rank</div>
            <div className="col-span-4">Player</div>
            <div className="col-span-2 text-center">IT Level</div>
            <div className="col-span-2 text-center">Total Level</div>
            <div className="col-span-3 text-right">Specialization</div>
          </div>
        </div>

        {/* Entries */}
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {leaderboard?.entries.map((entry, idx) => {
            const isCurrentUser = isAuthenticated && user?.id === entry.userId;
            return (
              <div
                key={entry.userId}
                className={`px-6 py-4 ${
                  idx < 3 ? 'bg-yellow-50/50 dark:bg-yellow-900/10' : ''
                } ${isCurrentUser ? 'bg-blue-50 dark:bg-blue-900/20' : ''}`}
              >
                <div className="grid grid-cols-12 gap-4 items-center">
                  <div className="col-span-1">
                    <RankBadge rank={entry.rank} />
                  </div>
                  <div className="col-span-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-400 to-purple-500 flex items-center justify-center text-white font-bold">
                        {entry.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">
                          {entry.username}
                          {isCurrentUser && (
                            <span className="ml-2 text-xs text-blue-600 dark:text-blue-400">(You)</span>
                          )}
                        </div>
                        {entry.skillsAt99 > 0 && (
                          <div className="flex items-center gap-1 text-xs text-yellow-600">
                            <Star className="w-3 h-3" />
                            {entry.skillsAt99} skill{entry.skillsAt99 > 1 ? 's' : ''} maxed
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="col-span-2 text-center">
                    <span className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 font-bold text-xl">
                      {entry.itLevel}
                    </span>
                  </div>
                  <div className="col-span-2 text-center">
                    <span className="text-gray-600 dark:text-gray-400">
                      {entry.totalLevel.toLocaleString()}
                    </span>
                    <span className="text-xs text-gray-400 dark:text-gray-500 block">
                      / 1,188
                    </span>
                  </div>
                  <div className="col-span-3 text-right">
                    <span className="inline-block px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 rounded-full text-sm">
                      {entry.specialization}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Empty state */}
        {(!leaderboard || leaderboard.entries.length === 0) && (
          <div className="px-6 py-12 text-center">
            <Trophy className="w-16 h-16 mx-auto text-gray-300 dark:text-gray-600 mb-4" />
            <p className="text-gray-500 dark:text-gray-400">
              No rankings yet. Be the first to climb the leaderboard!
            </p>
            <Link
              to="/tutorials"
              className="mt-4 inline-block px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
            >
              Start Learning
            </Link>
          </div>
        )}
      </div>

      {/* Total participants */}
      {leaderboard && leaderboard.totalParticipants > 0 && (
        <div className="mt-4 text-center text-gray-500 dark:text-gray-400">
          Showing top {leaderboard.entries.length} of {leaderboard.totalParticipants} players
        </div>
      )}
    </div>
  );
};

export default SkillsLeaderboard;
