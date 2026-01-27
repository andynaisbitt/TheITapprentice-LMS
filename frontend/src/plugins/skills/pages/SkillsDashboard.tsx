// frontend/src/plugins/skills/pages/SkillsDashboard.tsx
/**
 * Skills Dashboard - Main page showing user's skill progress
 * OSRS-style skill grid with level tracking and progression
 */

import React, { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../../state/contexts/AuthContext';
import { skillsApi } from '../services/skillsApi';
import type { UserSkillsOverview, Skill, UserSkillProgress } from '../types';
import {
  Trophy,
  TrendingUp,
  Star,
  Zap,
  ChevronRight,
  Shield,
  Code,
  Server,
  Cloud
} from 'lucide-react';

// Category config with icons and labels
const categoryConfig: Record<string, { icon: React.ReactNode; label: string }> = {
  foundation: { icon: <Shield className="w-4 h-4" />, label: 'Foundation' },
  development: { icon: <Code className="w-4 h-4" />, label: 'Development' },
  systems: { icon: <Server className="w-4 h-4" />, label: 'Systems' },
  cloud_security: { icon: <Cloud className="w-4 h-4" />, label: 'Cloud & Security' },
};

// Skill card component — compact-responsive
const SkillCard: React.FC<{ skill: UserSkillProgress }> = ({ skill }) => {
  const progressPercent = Math.min(100, skill.xpProgressPercentage);
  const isMaxed = skill.currentLevel >= 99;

  return (
    <Link
      to={`/skills/${skill.skillSlug}`}
      className="group relative bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3 sm:p-4 hover:shadow-lg hover:border-blue-300 dark:hover:border-blue-600 transition-all duration-200"
    >
      {/* Level badge */}
      <div
        className="absolute -top-2 -right-2 w-7 h-7 text-xs sm:w-8 sm:h-8 rounded-full flex items-center justify-center text-white sm:text-sm font-bold shadow-md"
        style={{ backgroundColor: skill.tierColor }}
      >
        {skill.currentLevel}
      </div>

      {/* Icon and name */}
      <div className="flex items-center gap-2 sm:gap-3 mb-2 sm:mb-3">
        <span className="text-xl sm:text-2xl">{skill.skillIcon}</span>
        <div className="min-w-0">
          <h3 className="text-sm sm:text-base font-semibold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors truncate">
            {skill.skillName}
          </h3>
          <span
            className="text-xs font-medium px-2 py-0.5 rounded-full"
            style={{ backgroundColor: `${skill.tierColor}20`, color: skill.tierColor }}
          >
            {skill.tier}
          </span>
        </div>
      </div>

      {/* XP Progress bar */}
      <div className="mb-2">
        <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
          <span>{(skill.currentXp ?? 0).toLocaleString()} XP</span>
          <span className="hidden sm:inline">{(skill.xpToNextLevel ?? 0).toLocaleString()} to next</span>
        </div>
        <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${progressPercent}%`,
              backgroundColor: skill.tierColor
            }}
          />
        </div>
      </div>

      {/* Milestone badges */}
      <div className="flex gap-1 mt-2">
        {[10, 30, 50, 75, 99].map((milestone) => {
          const achieved =
            (milestone === 10 && skill.level10Achieved) ||
            (milestone === 30 && skill.level30Achieved) ||
            (milestone === 50 && skill.level50Achieved) ||
            (milestone === 75 && skill.level75Achieved) ||
            (milestone === 99 && skill.level99Achieved);

          return (
            <div
              key={milestone}
              className={`w-5 h-5 text-[10px] sm:w-6 sm:h-6 rounded-full flex items-center justify-center sm:text-xs font-bold ${
                achieved
                  ? 'bg-yellow-400 text-yellow-900'
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-400'
              }`}
              title={achieved ? `Level ${milestone} achieved!` : `Reach level ${milestone}`}
            >
              {milestone}
            </div>
          );
        })}
      </div>

      {/* Hover tooltip */}
      <div className="absolute left-1/2 -translate-x-1/2 -bottom-8 z-10 text-xs bg-gray-900 text-white px-2 py-1 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
        {isMaxed ? 'MAX LEVEL' : `${(skill.xpToNextLevel ?? 0).toLocaleString()} XP to next level`}
      </div>

      {/* Hover arrow */}
      <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-300 dark:text-gray-600 group-hover:text-blue-500 group-hover:translate-x-1 transition-all opacity-0 group-hover:opacity-100" />
    </Link>
  );
};

// Stats card component (desktop only)
const StatCard: React.FC<{
  label: string;
  value: string | number;
  subValue?: string;
  icon: React.ReactNode;
  color: string;
}> = ({ label, value, subValue, icon, color }) => (
  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
    <div className="flex items-center gap-3">
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center"
        style={{ backgroundColor: `${color}20` }}
      >
        <span style={{ color }}>{icon}</span>
      </div>
      <div>
        <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
        <div className="text-sm text-gray-500 dark:text-gray-400">{label}</div>
        {subValue && (
          <div className="text-xs text-gray-400 dark:text-gray-500">{subValue}</div>
        )}
      </div>
    </div>
  </div>
);

export const SkillsDashboard: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const [overview, setOverview] = useState<UserSkillsOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState<string>('all');

  useEffect(() => {
    const fetchSkills = async () => {
      if (!isAuthenticated) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const data = await skillsApi.getMySkills();
        setOverview(data);
      } catch (err: any) {
        console.error('Failed to fetch skills:', err);
        setError(err.response?.data?.detail || 'Failed to load skills');
      } finally {
        setLoading(false);
      }
    };

    fetchSkills();
  }, [isAuthenticated]);

  // Group skills by category
  const skillsByCategory = useMemo(() =>
    overview?.skills.reduce((acc, skill) => {
      const cat = skill.skillCategory;
      if (!acc[cat]) acc[cat] = [];
      acc[cat].push(skill);
      return acc;
    }, {} as Record<string, UserSkillProgress[]>) || {}
  , [overview]);

  // Get all category keys from data
  const categories = useMemo(() => Object.keys(skillsByCategory), [skillsByCategory]);

  // Filtered skills based on active category
  const filteredSkills = useMemo(() => {
    if (activeCategory === 'all') {
      return overview?.skills || [];
    }
    return skillsByCategory[activeCategory] || [];
  }, [activeCategory, overview, skillsByCategory]);

  if (!isAuthenticated) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8">
          <Trophy className="w-16 h-16 mx-auto text-yellow-500 mb-4" />
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
            Skill Tracking
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Track your progress across 12 IT skills. Complete tutorials, courses, quizzes,
            and typing games to earn XP and level up!
          </p>
          <Link
            to="/login"
            className="inline-flex items-center px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
          >
            Sign in to track your skills
          </Link>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-48 mb-4" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 bg-gray-200 dark:bg-gray-700 rounded-lg" />
            ))}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map((i) => (
              <div key={i} className="h-40 bg-gray-200 dark:bg-gray-700 rounded-lg" />
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

  if (!overview) return null;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-1">
            Skills Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400 text-sm">
            Track your IT skill progression across 12 disciplines
            <span className="mx-2 text-gray-300 dark:text-gray-600">|</span>
            <span className="text-gray-500 dark:text-gray-400">
              Avg Lvl {overview.averageLevel.toFixed(1)} &middot;{' '}
              {overview.skillsAt50Plus} Expert+ &middot;{' '}
              {overview.specializationPath}
            </span>
          </p>
        </div>
        <div className="mt-3 md:mt-0 flex items-center gap-2">
          <Link
            to="/skills/history"
            className="inline-flex items-center px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg font-medium transition-colors"
          >
            <TrendingUp className="w-4 h-4 mr-1.5" />
            XP History
          </Link>
          <Link
            to="/skills/leaderboard"
            className="inline-flex items-center px-3 py-2 text-sm bg-yellow-500 hover:bg-yellow-600 text-white rounded-lg font-medium transition-colors"
          >
            <Trophy className="w-4 h-4 mr-1.5" />
            Leaderboard
          </Link>
        </div>
      </div>

      {/* Mobile: Compact single-row stats strip */}
      <div className="md:hidden flex items-center justify-between bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 px-3 py-2.5 mb-6 text-sm">
        <div className="flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-blue-500" />
          <span className="font-bold text-gray-900 dark:text-white">{overview.itLevel}</span>
          <span className="text-gray-400 text-xs">IT Lvl</span>
        </div>
        <div className="w-px h-4 bg-gray-200 dark:bg-gray-700" />
        <div className="flex items-center gap-1.5">
          <TrendingUp className="w-3.5 h-3.5 text-emerald-500" />
          <span className="font-bold text-gray-900 dark:text-white">{overview.totalLevel}</span>
          <span className="text-gray-400 text-xs">Total</span>
        </div>
        <div className="w-px h-4 bg-gray-200 dark:bg-gray-700" />
        <div className="flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-amber-500" />
          <span className="font-bold text-gray-900 dark:text-white">{(overview.totalXp ?? 0).toLocaleString()}</span>
          <span className="text-gray-400 text-xs">XP</span>
        </div>
        <div className="w-px h-4 bg-gray-200 dark:bg-gray-700" />
        <div className="flex items-center gap-1.5">
          <Star className="w-3.5 h-3.5 text-purple-500" />
          <span className="font-bold text-gray-900 dark:text-white truncate max-w-[60px]">{overview.specialization}</span>
        </div>
      </div>

      {/* Desktop: Full stats cards */}
      <div className="hidden md:grid md:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="IT Level"
          value={overview.itLevel}
          subValue={`/ ${overview.maxItLevel}`}
          icon={<Shield className="w-5 h-5" />}
          color="#3B82F6"
        />
        <StatCard
          label="Total Level"
          value={overview.totalLevel}
          subValue={`/ ${overview.maxTotalLevel}`}
          icon={<TrendingUp className="w-5 h-5" />}
          color="#10B981"
        />
        <StatCard
          label="Total XP"
          value={(overview.totalXp ?? 0).toLocaleString()}
          icon={<Zap className="w-5 h-5" />}
          color="#F59E0B"
        />
        <StatCard
          label="Specialization"
          value={overview.specialization}
          icon={<Star className="w-5 h-5" />}
          color="#8B5CF6"
        />
      </div>

      {/* Category filter chips */}
      <div className="flex gap-2 overflow-x-auto pb-2 mb-6 scrollbar-hide">
        <button
          onClick={() => setActiveCategory('all')}
          className={`whitespace-nowrap px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
            activeCategory === 'all'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
          }`}
        >
          All Skills
        </button>
        {categories.map((cat) => {
          const config = categoryConfig[cat];
          return (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`whitespace-nowrap inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
                activeCategory === cat
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              {config?.icon}
              {config?.label || cat.replace('_', ' & ').replace(/\b\w/g, l => l.toUpperCase())}
            </button>
          );
        })}
      </div>

      {/* Skills Grid — unified, filtered */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 sm:gap-4">
        {filteredSkills.map((skill) => (
          <SkillCard key={skill.skillSlug} skill={skill} />
        ))}
      </div>
    </div>
  );
};

export default SkillsDashboard;
