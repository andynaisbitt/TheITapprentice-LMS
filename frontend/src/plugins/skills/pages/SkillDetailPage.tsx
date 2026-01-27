// frontend/src/plugins/skills/pages/SkillDetailPage.tsx
/**
 * Skill Detail Page - Shows detailed progress for a single skill
 * Includes XP history, milestones, and leaderboard
 */

import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../../../state/contexts/AuthContext';
import { skillsApi } from '../services/skillsApi';
import type {
  Skill,
  UserSkillProgress,
  SkillLeaderboard,
  SkillXPLogEntry,
} from '../types';
import {
  ArrowLeft,
  Trophy,
  Zap,
  Clock,
  TrendingUp,
  BookOpen,
  Gamepad2,
  ClipboardCheck,
  GraduationCap,
  Award
} from 'lucide-react';

// Source type icons
const sourceIcons: Record<string, React.ReactNode> = {
  tutorial: <BookOpen className="w-4 h-4" />,
  course: <GraduationCap className="w-4 h-4" />,
  quiz: <ClipboardCheck className="w-4 h-4" />,
  typing_game: <Gamepad2 className="w-4 h-4" />,
  achievement: <Award className="w-4 h-4" />,
};

// Format relative time
function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

// Determine the current milestone tier based on level
function getCurrentMilestoneLevel(level: number): number {
  if (level >= 99) return 99;
  if (level >= 75) return 75;
  if (level >= 50) return 50;
  if (level >= 30) return 30;
  if (level >= 10) return 10;
  return 0;
}

// Tier colors for milestone highlights
const milestoneTierColors: Record<number, string> = {
  10: '#6B7280',  // gray
  30: '#10B981',  // emerald
  50: '#3B82F6',  // blue
  75: '#8B5CF6',  // purple
  99: '#F59E0B',  // amber/gold
};

export const SkillDetailPage: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const { isAuthenticated } = useAuth();
  const [skill, setSkill] = useState<Skill | null>(null);
  const [userProgress, setUserProgress] = useState<UserSkillProgress | null>(null);
  const [leaderboard, setLeaderboard] = useState<SkillLeaderboard | null>(null);
  const [xpHistory, setXpHistory] = useState<SkillXPLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'history' | 'players'>('history');

  useEffect(() => {
    const fetchData = async () => {
      if (!slug) return;

      try {
        setLoading(true);
        setError(null);

        // Fetch skill info
        const skillData = await skillsApi.getSkill(slug);
        setSkill(skillData);

        // Fetch leaderboard
        const lb = await skillsApi.getSkillLeaderboard(slug, 10);
        setLeaderboard(lb);

        // If authenticated, fetch user progress and history
        if (isAuthenticated) {
          const overview = await skillsApi.getMySkills();
          const mySkill = overview.skills.find(s => s.skillSlug === slug);
          setUserProgress(mySkill || null);

          const history = await skillsApi.getMyXPHistory(slug, 20);
          setXpHistory(history.entries);
        }
      } catch (err: any) {
        console.error('Failed to fetch skill data:', err);
        setError(err.response?.data?.detail || 'Failed to load skill data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [slug, isAuthenticated]);

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto px-4 py-8">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-24 mb-4" />
          <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded w-64 mb-8" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="md:col-span-2 h-64 bg-gray-200 dark:bg-gray-700 rounded-lg" />
            <div className="h-64 bg-gray-200 dark:bg-gray-700 rounded-lg" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !skill) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 text-center">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
          <p className="text-red-600 dark:text-red-400">{error || 'Skill not found'}</p>
          <Link
            to="/skills"
            className="mt-4 inline-block px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg"
          >
            Back to Skills
          </Link>
        </div>
      </div>
    );
  }

  const progressPercent = userProgress ? Math.min(100, userProgress.xpProgressPercentage) : 0;
  const currentMilestoneLevel = userProgress ? getCurrentMilestoneLevel(userProgress.currentLevel) : 0;

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      {/* Back link */}
      <Link
        to="/skills"
        className="inline-flex items-center text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 mb-6"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Skills
      </Link>

      {/* Skill Header */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 sm:p-6 mb-6">
        <div className="flex flex-col md:flex-row md:items-center gap-6">
          {/* Skill icon and name */}
          <div className="flex items-center gap-4">
            <span className="text-5xl">{skill.icon}</span>
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                {skill.name}
              </h1>
              <p className="text-gray-600 dark:text-gray-400">{skill.description}</p>
            </div>
          </div>

          {/* Level display */}
          {userProgress && (
            <div className="md:ml-auto text-center md:text-right">
              <div
                className="inline-flex items-center justify-center w-20 h-20 rounded-full text-white text-3xl font-bold shadow-lg"
                style={{ backgroundColor: userProgress.tierColor }}
              >
                {userProgress.currentLevel}
              </div>
              <div className="mt-2">
                <span
                  className="px-3 py-1 rounded-full text-sm font-medium"
                  style={{ backgroundColor: `${userProgress.tierColor}20`, color: userProgress.tierColor }}
                >
                  {userProgress.tier}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Progress bar (if authenticated) */}
        {userProgress && (
          <div className="mt-6">
            <div className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-2">
              <span>{(userProgress.currentXp ?? 0).toLocaleString()} XP</span>
              <span>
                {(userProgress.xpToNextLevel ?? 0).toLocaleString()} XP to level {(userProgress.currentLevel ?? 0) + 1}
              </span>
            </div>
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${progressPercent}%`,
                  backgroundColor: userProgress.tierColor
                }}
              />
            </div>
          </div>
        )}

        {/* Milestones — with current tier highlight */}
        {userProgress && (
          <div className="mt-6 flex flex-wrap gap-3">
            {[
              { level: 10, achieved: userProgress.level10Achieved, label: 'Apprentice' },
              { level: 30, achieved: userProgress.level30Achieved, label: 'Journeyman' },
              { level: 50, achieved: userProgress.level50Achieved, label: 'Expert' },
              { level: 75, achieved: userProgress.level75Achieved, label: 'Master' },
              { level: 99, achieved: userProgress.level99Achieved, label: 'Grandmaster' },
            ].map((milestone) => {
              const isCurrent = milestone.level === currentMilestoneLevel;
              const tierColor = milestoneTierColors[milestone.level] || '#6B7280';

              return (
                <div
                  key={milestone.level}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-transform ${
                    milestone.achieved
                      ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-300 dark:border-yellow-700'
                      : 'bg-gray-50 dark:bg-gray-700 border-gray-200 dark:border-gray-600'
                  } ${isCurrent ? 'ring-2 ring-offset-2 ring-offset-white dark:ring-offset-gray-800 scale-105' : ''}`}
                  style={isCurrent ? { borderColor: tierColor, ['--tw-ring-color' as string]: tierColor } as React.CSSProperties : undefined}
                >
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                      milestone.achieved
                        ? 'bg-yellow-400 text-yellow-900'
                        : 'bg-gray-300 dark:bg-gray-600 text-gray-500'
                    }`}
                  >
                    {milestone.level}
                  </div>
                  <span className={milestone.achieved ? 'text-yellow-700 dark:text-yellow-400' : 'text-gray-500'}>
                    {milestone.label}
                  </span>
                  {milestone.achieved && <Award className="w-4 h-4 text-yellow-500" />}
                  {isCurrent && !milestone.achieved && (
                    <span className="text-xs font-medium text-blue-500 dark:text-blue-400">Current</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Mobile tab switcher */}
      <div className="lg:hidden flex border-b border-gray-200 dark:border-gray-700 mb-4">
        <button
          onClick={() => setActiveTab('history')}
          className={`flex-1 py-2.5 text-sm font-medium text-center transition-colors ${
            activeTab === 'history'
              ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
          }`}
        >
          <Clock className="w-4 h-4 inline mr-1.5" />
          XP History
        </button>
        <button
          onClick={() => setActiveTab('players')}
          className={`flex-1 py-2.5 text-sm font-medium text-center transition-colors ${
            activeTab === 'players'
              ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
          }`}
        >
          <Trophy className="w-4 h-4 inline mr-1.5" />
          Top Players
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* XP History */}
        <div className={`lg:col-span-2 ${activeTab !== 'history' ? 'hidden lg:block' : ''}`}>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 sm:p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5" />
              Recent XP Gains
            </h2>

            {!isAuthenticated ? (
              <div className="text-center py-8">
                <p className="text-gray-500 dark:text-gray-400 mb-4">
                  Sign in to track your XP history
                </p>
                <Link
                  to="/login"
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
                >
                  Sign In
                </Link>
              </div>
            ) : xpHistory.length === 0 ? (
              <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                <Zap className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No XP earned yet for this skill</p>
                <p className="text-sm mt-1">Complete tutorials, courses, or quizzes to earn XP!</p>
              </div>
            ) : (
              <div className="space-y-2 sm:space-y-3">
                {xpHistory.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex items-center gap-3 p-2 sm:p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
                  >
                    <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center text-green-600 dark:text-green-400 flex-shrink-0">
                      {sourceIcons[entry.sourceType] || <Zap className="w-4 h-4" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-gray-900 dark:text-white">
                        +{entry.xpGained} XP
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400 truncate">
                        {entry.sourceType.replace('_', ' ')}
                        {entry.sourceMetadata?.tutorial_title ? `: ${String(entry.sourceMetadata.tutorial_title)}` : null}
                        {entry.sourceMetadata?.quiz_title ? `: ${String(entry.sourceMetadata.quiz_title)}` : null}
                        {entry.sourceMetadata?.course_title ? `: ${String(entry.sourceMetadata.course_title)}` : null}
                      </div>
                    </div>
                    <div className="text-sm text-gray-400 flex-shrink-0">
                      <span className="hidden sm:inline">{formatRelativeTime(entry.createdAt)}</span>
                      <span className="sm:hidden">{formatRelativeTime(entry.createdAt).replace(' ago', '')}</span>
                    </div>
                    {entry.levelBefore < entry.levelAfter && (
                      <div className="px-2 py-1 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 rounded text-sm font-medium flex-shrink-0">
                        Level up!
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Leaderboard */}
        <div className={`${activeTab !== 'players' ? 'hidden lg:block' : ''}`}>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 sm:p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              <Trophy className="w-5 h-5 text-yellow-500" />
              Top Players
            </h2>

            {leaderboard && leaderboard.entries.length > 0 ? (
              <div className="space-y-2">
                {leaderboard.entries.map((entry, idx) => (
                  <div
                    key={entry.userId}
                    className={`flex items-center gap-3 p-2 rounded-lg ${
                      idx < 3 ? 'bg-yellow-50 dark:bg-yellow-900/10' : ''
                    }`}
                  >
                    <div
                      className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        idx === 0
                          ? 'bg-yellow-400 text-yellow-900'
                          : idx === 1
                          ? 'bg-gray-300 text-gray-700'
                          : idx === 2
                          ? 'bg-amber-600 text-white'
                          : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                      }`}
                    >
                      {entry.rank}
                    </div>
                    <div className="flex-1">
                      <div className="font-medium text-gray-900 dark:text-white text-sm">
                        {entry.username}
                      </div>
                    </div>
                    <div
                      className="px-2 py-1 rounded text-xs font-bold text-white"
                      style={{ backgroundColor: entry.tierColor }}
                    >
                      {entry.level}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                <Trophy className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No rankings yet</p>
              </div>
            )}

            {leaderboard && leaderboard.userRank && (
              <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Your rank:</span>
                  <span className="font-bold text-gray-900 dark:text-white">
                    #{leaderboard.userRank} of {leaderboard.totalParticipants}
                  </span>
                </div>
              </div>
            )}

            <Link
              to="/skills/leaderboard"
              className="mt-4 block text-center text-blue-600 hover:text-blue-700 dark:text-blue-400 text-sm"
            >
              View Full Leaderboard
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SkillDetailPage;
