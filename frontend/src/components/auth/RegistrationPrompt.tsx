// src/components/auth/RegistrationPrompt.tsx
/**
 * Registration Prompt Modal
 * Shows when unregistered users try to access features that benefit from registration
 * Provides options to Sign Up, Login, or Skip (continue without registration)
 */

import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import {
  X,
  UserPlus,
  LogIn,
  Trophy,
  Zap,
  Target,
  TrendingUp,
  Gamepad2,
  BookOpen,
  GraduationCap,
  ClipboardCheck,
} from 'lucide-react';

export type PromptContext = 'course' | 'tutorial' | 'quiz' | 'game' | 'pvp' | 'general';

interface RegistrationPromptProps {
  isOpen: boolean;
  onClose: () => void;
  onSkip?: () => void;
  context?: PromptContext;
  /** If true, user cannot skip (required for features like PVP) */
  required?: boolean;
  /** Custom title override */
  title?: string;
  /** Custom description override */
  description?: string;
}

const contextConfig: Record<PromptContext, {
  icon: React.ElementType;
  title: string;
  description: string;
  benefits: string[];
  skipText: string;
  showSkip: boolean;
}> = {
  course: {
    icon: GraduationCap,
    title: 'Start Learning on The IT Apprentice',
    description: 'Create a free account to track your progress through courses and earn XP rewards.',
    benefits: [
      'Save your progress and resume anytime',
      'Earn XP and level up your skills',
      'Get completion certificates',
      'Track achievements across all courses',
    ],
    skipText: 'Continue without saving progress',
    showSkip: true,
  },
  tutorial: {
    icon: BookOpen,
    title: 'Track Your Tutorial Progress',
    description: 'Sign up to save your progress and earn XP as you complete tutorials.',
    benefits: [
      'Save progress on each step',
      'Earn XP for completed tutorials',
      'Build your learning streak',
      'Unlock achievements',
    ],
    skipText: 'Continue without tracking',
    showSkip: true,
  },
  quiz: {
    icon: ClipboardCheck,
    title: 'Save Your Quiz Results',
    description: 'Create an account to track your quiz scores and compete on leaderboards.',
    benefits: [
      'Save quiz scores and history',
      'Appear on leaderboards',
      'Earn XP for high scores',
      'Track your improvement over time',
    ],
    skipText: 'Take quiz without saving',
    showSkip: true,
  },
  game: {
    icon: Gamepad2,
    title: 'Track Your Gaming Progress',
    description: 'Sign up to save your scores, earn XP, and compete on leaderboards.',
    benefits: [
      'Save high scores to leaderboards',
      'Earn XP for your performance',
      'Track your typing speed improvement',
      'Unlock gaming achievements',
    ],
    skipText: 'Play without saving progress',
    showSkip: true,
  },
  pvp: {
    icon: Trophy,
    title: 'Registration Required for PvP',
    description: 'You need an account to compete against other players in real-time PvP matches.',
    benefits: [
      'Challenge players in real-time',
      'Climb the competitive leaderboard',
      'Earn bonus XP for victories',
      'Track your win/loss record',
    ],
    skipText: '',
    showSkip: false,
  },
  general: {
    icon: Zap,
    title: 'Join The IT Apprentice',
    description: 'Create a free account to unlock all features and track your learning journey.',
    benefits: [
      'Track progress across all content',
      'Earn XP and unlock achievements',
      'Compete on leaderboards',
      'Build your learning streak',
    ],
    skipText: 'Continue as guest',
    showSkip: true,
  },
};

export const RegistrationPrompt: React.FC<RegistrationPromptProps> = ({
  isOpen,
  onClose,
  onSkip,
  context = 'general',
  required = false,
  title,
  description,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const config = contextConfig[context];
  const Icon = config.icon;

  const handleSignUp = () => {
    // Store return URL to redirect back after registration
    const returnUrl = location.pathname + location.search;
    navigate(`/register?returnUrl=${encodeURIComponent(returnUrl)}`);
    onClose();
  };

  const handleLogin = () => {
    const returnUrl = location.pathname + location.search;
    navigate(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
    onClose();
  };

  const handleSkip = () => {
    if (onSkip) {
      onSkip();
    }
    onClose();
  };

  if (!isOpen) return null;

  const canSkip = config.showSkip && !required && onSkip;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={canSkip ? handleSkip : undefined}
      />

      {/* Modal */}
      <div className="relative bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Close button (only if skippable) */}
        {canSkip && (
          <button
            onClick={handleSkip}
            className="absolute top-4 right-4 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors z-10"
          >
            <X className="w-5 h-5" />
          </button>
        )}

        {/* Header with gradient */}
        <div className="bg-gradient-to-br from-primary via-primary-dark to-purple-700 px-6 py-8 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-white/20 backdrop-blur-sm mb-4">
            <Icon className="w-8 h-8 text-white" />
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">
            {title || config.title}
          </h2>
          <p className="text-white/90 text-sm">
            {description || config.description}
          </p>
        </div>

        {/* Benefits */}
        <div className="px-6 py-6">
          <ul className="space-y-3">
            {config.benefits.map((benefit, index) => (
              <li key={index} className="flex items-start gap-3">
                <div className="flex-shrink-0 w-5 h-5 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mt-0.5">
                  <svg className="w-3 h-3 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <span className="text-gray-700 dark:text-gray-300 text-sm">{benefit}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Actions */}
        <div className="px-6 pb-6 space-y-3">
          {/* Sign Up Button */}
          <button
            onClick={handleSignUp}
            className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-primary to-primary-dark text-white font-semibold rounded-xl hover:opacity-90 transition-opacity shadow-lg shadow-primary/25"
          >
            <UserPlus className="w-5 h-5" />
            Create Free Account
          </button>

          {/* Login Link */}
          <button
            onClick={handleLogin}
            className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 font-medium rounded-xl hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
          >
            <LogIn className="w-5 h-5" />
            Already have an account? Login
          </button>

          {/* Skip Button */}
          {canSkip && (
            <button
              onClick={handleSkip}
              className="w-full text-center text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 py-2 transition-colors"
            >
              {config.skipText}
            </button>
          )}

          {/* Required notice for PvP etc */}
          {required && (
            <p className="text-center text-xs text-gray-500 dark:text-gray-400">
              An account is required for this feature
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

export default RegistrationPrompt;
