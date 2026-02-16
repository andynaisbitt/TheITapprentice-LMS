// frontend/src/plugins/skills/pages/SkillsDashboard.tsx
/**
 * Skills Dashboard - Main page showing user's skill progress
 * OSRS-style skill grid with level tracking and progression
 */

import React, { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../../state/contexts/AuthContext';
import { skillsApi } from '../services/skillsApi';
import type { UserSkillsOverview, UserSkillProgress } from '../types';
import {
  Trophy,
  TrendingUp,
  Star,
  Zap,
  ChevronRight,
  Shield,
  Code,
  Server,
  Cloud,
  Flame,
  Sparkles,
  Rocket,
} from 'lucide-react';

// Category config with icons and labels
const categoryConfig: Record<string, { icon: React.ReactNode; label: string }> = {
  foundation: { icon: <Shield className="w-4 h-4" />, label: 'Foundation' },
  development: { icon: <Code className="w-4 h-4" />, label: 'Development' },
  systems: { icon: <Server className="w-4 h-4" />, label: 'Systems' },
  cloud_security: { icon: <Cloud className="w-4 h-4" />, label: 'Cloud & Security' },
};

// Tier-based card accent colours (gradient from/to)
const tierGradients: Record<string, { border: string; glow: string; bg: string }> = {
  Novice:       { border: 'border-slate-500/30', glow: '', bg: 'from-slate-500/5 to-transparent' },
  Apprentice:   { border: 'border-green-500/30', glow: '', bg: 'from-green-500/5 to-transparent' },
  Journeyman:   { border: 'border-blue-500/30', glow: 'shadow-blue-500/10', bg: 'from-blue-500/8 to-transparent' },
  Expert:       { border: 'border-purple-500/40', glow: 'shadow-purple-500/15', bg: 'from-purple-500/10 to-transparent' },
  Master:       { border: 'border-amber-500/40', glow: 'shadow-amber-500/20', bg: 'from-amber-500/10 to-transparent' },
  Grandmaster:  { border: 'border-red-500/50', glow: 'shadow-red-500/25', bg: 'from-red-500/10 to-transparent' },
};

// Skill card component
const SkillCard: React.FC<{ skill: UserSkillProgress }> = ({ skill }) => {
  const progressPercent = Math.min(100, skill.xpProgressPercentage);
  const isMaxed = skill.currentLevel >= 99;
  const tier = tierGradients[skill.tier] || tierGradients.Novice;

  return (
    <Link
      to={`/skills/${skill.skillSlug}`}
      className={`group relative overflow-hidden rounded-xl border ${tier.border} bg-gradient-to-br ${tier.bg} bg-white dark:bg-gray-800/80 backdrop-blur-sm p-4 hover:scale-[1.02] hover:shadow-xl ${tier.glow} transition-all duration-300`}
    >
      {/* Decorative corner glow for higher tiers */}
      {skill.currentLevel >= 10 && (
        <div
          className="absolute -top-8 -right-8 w-20 h-20 rounded-full blur-2xl opacity-20 pointer-events-none"
          style={{ backgroundColor: skill.tierColor }}
        />
      )}

      {/* Level badge */}
      <div
        className={`absolute -top-1.5 -right-1.5 w-8 h-8 rounded-full flex items-center justify-center text-sm font-black shadow-lg ring-2 ring-white dark:ring-gray-900 ${isMaxed ? 'animate-pulse' : ''}`}
        style={{ backgroundColor: skill.tierColor, color: '#fff' }}
      >
        {skill.currentLevel}
      </div>

      {/* Icon and name */}
      <div className="flex items-center gap-3 mb-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center text-2xl shrink-0"
          style={{ backgroundColor: `${skill.tierColor}15` }}
        >
          {skill.skillIcon}
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-bold text-gray-900 dark:text-white group-hover:text-blue-500 dark:group-hover:text-blue-400 transition-colors truncate">
            {skill.skillName}
          </h3>
          <span
            className="inline-block text-[11px] font-semibold px-2 py-0.5 rounded-full mt-0.5"
            style={{ backgroundColor: `${skill.tierColor}20`, color: skill.tierColor }}
          >
            {skill.tier}
          </span>
        </div>
      </div>

      {/* XP Progress */}
      <div className="mb-3">
        <div className="flex justify-between text-xs mb-1.5">
          <span className="font-semibold text-gray-700 dark:text-gray-300">
            {(skill.currentXp ?? 0).toLocaleString()} XP
          </span>
          <span className="text-gray-400 dark:text-gray-500">
            {isMaxed ? 'MAX' : `${(skill.xpToNextLevel ?? 0).toLocaleString()} to go`}
          </span>
        </div>
        <div className="h-2.5 bg-gray-200 dark:bg-gray-700/80 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700 ease-out relative"
            style={{
              width: `${isMaxed ? 100 : progressPercent}%`,
              background: isMaxed
                ? `linear-gradient(90deg, ${skill.tierColor}, #fbbf24, ${skill.tierColor})`
                : `linear-gradient(90deg, ${skill.tierColor}cc, ${skill.tierColor})`,
            }}
          >
            {progressPercent > 15 && (
              <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/25 to-white/0 rounded-full" />
            )}
          </div>
        </div>
      </div>

      {/* Milestone badges */}
      <div className="flex gap-1.5">
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
              className={`w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-bold transition-all ${
                achieved
                  ? 'bg-gradient-to-br from-yellow-300 to-amber-500 text-amber-900 shadow-sm shadow-amber-500/30 scale-105'
                  : 'bg-gray-100 dark:bg-gray-700/60 text-gray-400 dark:text-gray-500'
              }`}
              title={achieved ? `Level ${milestone} achieved!` : `Reach level ${milestone}`}
            >
              {milestone}
            </div>
          );
        })}
      </div>

      {/* Hover arrow */}
      <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-300 dark:text-gray-600 group-hover:text-blue-500 group-hover:translate-x-1 transition-all opacity-0 group-hover:opacity-100" />
    </Link>
  );
};

// Stats card component
const StatCard: React.FC<{
  label: string;
  value: string | number;
  subValue?: string;
  icon: React.ReactNode;
  gradient: string;
  iconBg: string;
}> = ({ label, value, subValue, icon, gradient, iconBg }) => (
  <div className={`relative overflow-hidden rounded-xl bg-gradient-to-br ${gradient} p-4 border border-white/10`}>
    <div className="flex items-center gap-3 relative z-10">
      <div className={`w-11 h-11 rounded-xl flex items-center justify-center ${iconBg} shadow-lg`}>
        {icon}
      </div>
      <div>
        <div className="text-2xl font-black text-white">{value}</div>
        <div className="text-sm text-white/70 font-medium">{label}</div>
        {subValue && (
          <div className="text-xs text-white/50">{subValue}</div>
        )}
      </div>
    </div>
    {/* Background decoration */}
    <div className="absolute -right-4 -bottom-4 w-24 h-24 rounded-full bg-white/5 pointer-events-none" />
    <div className="absolute -right-2 -bottom-2 w-16 h-16 rounded-full bg-white/5 pointer-events-none" />
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

  const categories = useMemo(() => Object.keys(skillsByCategory), [skillsByCategory]);

  const filteredSkills = useMemo(() => {
    if (activeCategory === 'all') {
      return overview?.skills || [];
    }
    return skillsByCategory[activeCategory] || [];
  }, [activeCategory, overview, skillsByCategory]);

  if (!isAuthenticated) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="bg-gradient-to-br from-indigo-500/10 to-purple-500/10 dark:from-indigo-500/5 dark:to-purple-500/5 rounded-2xl shadow-xl border border-indigo-200 dark:border-indigo-800/30 p-10">
          <div className="w-20 h-20 mx-auto mb-6 rounded-2xl bg-gradient-to-br from-yellow-400 to-amber-500 flex items-center justify-center shadow-lg shadow-amber-500/30">
            <Trophy className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-black text-gray-900 dark:text-white mb-3">
            Skill Tracking
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mb-8 max-w-md mx-auto">
            Track your progress across 12 IT skills. Complete tutorials, courses, quizzes,
            and typing practice to earn XP and level up!
          </p>
          <Link
            to="/login"
            className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl font-semibold shadow-lg shadow-blue-500/30 transition-all hover:scale-105"
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
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded-lg w-48 mb-4" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 bg-gray-200 dark:bg-gray-700 rounded-xl" />
            ))}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map((i) => (
              <div key={i} className="h-44 bg-gray-200 dark:bg-gray-700 rounded-xl" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-6">
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

  // Calculate streak-like engagement stats
  const highestSkill = overview.skills.reduce((a, b) => (a.currentLevel > b.currentLevel ? a : b), overview.skills[0]);
  const lowestSkill = overview.skills.reduce((a, b) => (a.currentLevel < b.currentLevel ? a : b), overview.skills[0]);
  const skillsAbove1 = overview.skills.filter(s => s.currentLevel > 1).length;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-3xl font-black text-gray-900 dark:text-white">
              Skills Dashboard
            </h1>
            {overview.totalXp > 0 && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold bg-gradient-to-r from-amber-400 to-orange-500 text-white shadow-sm">
                <Flame className="w-3 h-3" />
                {skillsAbove1} Active
              </span>
            )}
          </div>
          <p className="text-gray-500 dark:text-gray-400 text-sm">
            Track your IT skill progression across {overview.skills.length} disciplines
            <span className="mx-2 text-gray-300 dark:text-gray-600">|</span>
            Avg Lvl {overview.averageLevel.toFixed(1)}
            {overview.skillsAt50Plus > 0 && (
              <>
                <span className="mx-1">&middot;</span>
                <span className="text-purple-500 font-semibold">{overview.skillsAt50Plus} Expert+</span>
              </>
            )}
          </p>
        </div>
        <div className="mt-3 md:mt-0 flex items-center gap-2">
          <Link
            to="/skills/history"
            className="inline-flex items-center px-4 py-2 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-xl font-medium transition-all border border-gray-200 dark:border-gray-700"
          >
            <TrendingUp className="w-4 h-4 mr-1.5" />
            XP History
          </Link>
          <Link
            to="/skills/leaderboard"
            className="inline-flex items-center px-4 py-2 text-sm bg-gradient-to-r from-yellow-500 to-amber-500 hover:from-yellow-400 hover:to-amber-400 text-white rounded-xl font-semibold shadow-md shadow-amber-500/20 transition-all hover:scale-105"
          >
            <Trophy className="w-4 h-4 mr-1.5" />
            Leaderboard
          </Link>
        </div>
      </div>

      {/* Mobile: Compact stats strip */}
      <div className="md:hidden flex items-center justify-between bg-gradient-to-r from-indigo-600 to-blue-600 rounded-xl px-4 py-3 mb-6 text-sm shadow-lg shadow-indigo-500/20">
        <div className="flex items-center gap-1.5">
          <Shield className="w-4 h-4 text-blue-200" />
          <span className="font-black text-white">{overview.itLevel}</span>
          <span className="text-blue-200 text-xs">IT Lvl</span>
        </div>
        <div className="w-px h-5 bg-white/20" />
        <div className="flex items-center gap-1.5">
          <TrendingUp className="w-4 h-4 text-emerald-300" />
          <span className="font-black text-white">{overview.totalLevel}</span>
          <span className="text-blue-200 text-xs">Total</span>
        </div>
        <div className="w-px h-5 bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Zap className="w-4 h-4 text-amber-300" />
          <span className="font-black text-white">{(overview.totalXp ?? 0).toLocaleString()}</span>
          <span className="text-blue-200 text-xs">XP</span>
        </div>
        <div className="w-px h-5 bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Star className="w-4 h-4 text-purple-300" />
          <span className="font-bold text-white truncate max-w-[60px] text-xs">{overview.specialization}</span>
        </div>
      </div>

      {/* Desktop: Full stats cards */}
      <div className="hidden md:grid md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="IT Level"
          value={overview.itLevel}
          subValue={`/ ${overview.maxItLevel}`}
          icon={<Shield className="w-5 h-5 text-white" />}
          gradient="from-blue-600 to-indigo-700"
          iconBg="bg-blue-500/80"
        />
        <StatCard
          label="Total Level"
          value={overview.totalLevel}
          subValue={`/ ${overview.maxTotalLevel}`}
          icon={<TrendingUp className="w-5 h-5 text-white" />}
          gradient="from-emerald-600 to-teal-700"
          iconBg="bg-emerald-500/80"
        />
        <StatCard
          label="Total XP"
          value={(overview.totalXp ?? 0).toLocaleString()}
          icon={<Zap className="w-5 h-5 text-white" />}
          gradient="from-amber-500 to-orange-600"
          iconBg="bg-amber-400/80"
        />
        <StatCard
          label="Specialization"
          value={overview.specialization}
          icon={<Star className="w-5 h-5 text-white" />}
          gradient="from-purple-600 to-fuchsia-700"
          iconBg="bg-purple-500/80"
        />
      </div>

      {/* Best skill spotlight (if user has progress) */}
      {highestSkill && highestSkill.currentLevel > 1 && (
        <div className="mb-6 p-4 rounded-xl bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-pink-500/10 dark:from-indigo-500/5 dark:via-purple-500/5 dark:to-pink-500/5 border border-indigo-200/50 dark:border-indigo-700/30">
          <div className="flex items-center gap-3">
            <Sparkles className="w-5 h-5 text-indigo-500" />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Top skill:
            </span>
            <span className="text-2xl">{highestSkill.skillIcon}</span>
            <span className="font-bold text-gray-900 dark:text-white">{highestSkill.skillName}</span>
            <span
              className="text-sm font-bold px-2 py-0.5 rounded-full"
              style={{ backgroundColor: `${highestSkill.tierColor}20`, color: highestSkill.tierColor }}
            >
              Lvl {highestSkill.currentLevel} {highestSkill.tier}
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400 ml-auto hidden sm:inline">
              {(highestSkill.currentXp ?? 0).toLocaleString()} XP earned
            </span>
          </div>
        </div>
      )}

      {/* Suggest weakest skill */}
      {lowestSkill && highestSkill && lowestSkill.skillSlug !== highestSkill.skillSlug && (
        <div className="mb-6 p-4 rounded-xl bg-gradient-to-r from-blue-500/10 via-cyan-500/10 to-teal-500/10 dark:from-blue-500/5 dark:via-cyan-500/5 dark:to-teal-500/5 border border-blue-200/50 dark:border-blue-700/30">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-3">
              <Rocket className="w-5 h-5 text-blue-500" />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Level up your weakest skill:
              </span>
              <span className="text-2xl">{lowestSkill.skillIcon}</span>
              <span className="font-bold text-gray-900 dark:text-white">{lowestSkill.skillName}</span>
              <span
                className="text-sm font-bold px-2 py-0.5 rounded-full"
                style={{ backgroundColor: `${lowestSkill.tierColor}20`, color: lowestSkill.tierColor }}
              >
                Lvl {lowestSkill.currentLevel}
              </span>
            </div>
            <Link
              to={`/skills/${lowestSkill.skillSlug}`}
              className="inline-flex items-center gap-1.5 text-sm font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
            >
              Find Activities
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      )}

      {/* Category filter chips */}
      <div className="flex gap-2 overflow-x-auto pb-2 mb-6 scrollbar-hide">
        <button
          onClick={() => setActiveCategory('all')}
          className={`whitespace-nowrap px-4 py-2 rounded-xl text-sm font-semibold transition-all ${
            activeCategory === 'all'
              ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-md shadow-blue-500/20'
              : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700'
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
              className={`whitespace-nowrap inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold transition-all ${
                activeCategory === cat
                  ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-md shadow-blue-500/20'
                  : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700'
              }`}
            >
              {config?.icon}
              {config?.label || cat.replace('_', ' & ').replace(/\b\w/g, l => l.toUpperCase())}
            </button>
          );
        })}
      </div>

      {/* Skills Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filteredSkills.map((skill) => (
          <SkillCard key={skill.skillSlug} skill={skill} />
        ))}
      </div>
    </div>
  );
};

export default SkillsDashboard;
