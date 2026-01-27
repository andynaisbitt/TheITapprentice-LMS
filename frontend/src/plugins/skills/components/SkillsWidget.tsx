// frontend/src/plugins/skills/components/SkillsWidget.tsx
/**
 * SkillsWidget - Compact skills summary for dashboards and profiles
 * Shows IT Level, top skills, and link to full dashboard
 */

import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { skillsApi } from '../services/skillsApi';
import type { UserSkillsOverview, UserSkillProgress } from '../types';
import { SkillBadge } from './SkillBadge';
import { Trophy, TrendingUp, ChevronRight, Zap } from 'lucide-react';

interface SkillsWidgetProps {
  userId?: number; // If provided, shows another user's skills
  maxSkills?: number;
  showLeaderboardLink?: boolean;
  compact?: boolean;
}

export const SkillsWidget: React.FC<SkillsWidgetProps> = ({
  userId,
  maxSkills = 6,
  showLeaderboardLink = true,
  compact = false,
}) => {
  const [overview, setOverview] = useState<UserSkillsOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSkills = async () => {
      try {
        setLoading(true);
        const data = userId
          ? await skillsApi.getUserSkills(userId)
          : await skillsApi.getMySkills();
        setOverview(data);
      } catch (err: any) {
        console.error('Failed to fetch skills:', err);
        setError(err.response?.data?.detail || 'Failed to load skills');
      } finally {
        setLoading(false);
      }
    };

    fetchSkills();
  }, [userId]);

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="animate-pulse">
          <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded w-24 mb-4" />
          <div className="flex gap-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="w-10 h-10 bg-gray-200 dark:bg-gray-700 rounded-full" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="text-center text-gray-500 dark:text-gray-400 text-sm">
          <Zap className="w-6 h-6 mx-auto mb-2 opacity-50" />
          <p>Skills not available</p>
          <p className="text-xs mt-1">Admin needs to seed skills first</p>
        </div>
      </div>
    );
  }

  if (!overview || overview.skills.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-500" />
            Skills
          </h3>
          <Link
            to="/skills"
            className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400"
          >
            Get started
          </Link>
        </div>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Complete tutorials, courses, and quizzes to level up your IT skills!
        </p>
      </div>
    );
  }

  // Get top skills by level
  const topSkills = [...overview.skills]
    .sort((a, b) => b.currentLevel - a.currentLevel || b.currentXp - a.currentXp)
    .slice(0, maxSkills);

  if (compact) {
    return (
      <Link
        to="/skills"
        className="flex items-center gap-3 p-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-blue-300 dark:hover:border-blue-600 transition-colors group"
      >
        <div className="w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
          <span className="text-2xl font-bold text-blue-600 dark:text-blue-400">
            {overview.itLevel}
          </span>
        </div>
        <div className="flex-1">
          <div className="text-sm font-medium text-gray-900 dark:text-white">IT Level</div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {overview.specialization}
          </div>
        </div>
        <ChevronRight className="w-5 h-5 text-gray-400 group-hover:text-blue-500 group-hover:translate-x-1 transition-all" />
      </Link>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
          <Zap className="w-4 h-4 text-yellow-500" />
          Skills
        </h3>
        <Link
          to="/skills"
          className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 flex items-center gap-1"
        >
          View all
          <ChevronRight className="w-4 h-4" />
        </Link>
      </div>

      {/* IT Level and Total Level */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
            {overview.itLevel}
          </div>
          <div className="text-xs text-blue-600/70 dark:text-blue-400/70">IT Level</div>
        </div>
        <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
            {overview.totalLevel}
          </div>
          <div className="text-xs text-purple-600/70 dark:text-purple-400/70">Total Level</div>
        </div>
      </div>

      {/* Top Skills */}
      <div className="mb-4">
        <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">Top Skills</div>
        <div className="flex flex-wrap gap-2">
          {topSkills.map((skill) => (
            <SkillBadge
              key={skill.skillSlug}
              skillSlug={skill.skillSlug}
              skillName={skill.skillName}
              skillIcon={skill.skillIcon}
              level={skill.currentLevel}
              tier={skill.tier}
              tierColor={skill.tierColor}
              size="sm"
            />
          ))}
        </div>
      </div>

      {/* Specialization */}
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-500 dark:text-gray-400">Specialization</span>
        <span className="text-gray-900 dark:text-white font-medium">
          {overview.specialization}
        </span>
      </div>

      {/* Leaderboard Link */}
      {showLeaderboardLink && (
        <Link
          to="/skills/leaderboard"
          className="mt-4 flex items-center justify-center gap-2 w-full py-2 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400 rounded-lg text-sm font-medium hover:bg-yellow-100 dark:hover:bg-yellow-900/30 transition-colors"
        >
          <Trophy className="w-4 h-4" />
          View Leaderboard
        </Link>
      )}
    </div>
  );
};

export default SkillsWidget;
