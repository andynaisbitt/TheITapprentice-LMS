// src/components/home/FeatureShowcaseHero/slideData.ts
import {
  GraduationCap,
  Keyboard,
  Brain,
  BookOpen,
  Trophy,
  Target,
  type LucideIcon
} from 'lucide-react';

export interface FeatureSlide {
  id: string;
  icon: LucideIcon;
  headline: string;
  subtext: string;
  cta: string;
  ctaLink: string;
  gradient: string;
  iconGradient: string;
  accentColor: string;
}

export const featureSlides: FeatureSlide[] = [
  {
    id: 'courses',
    icon: GraduationCap,
    headline: 'Master New Skills',
    subtext: 'Structured courses from beginner to advanced, designed by industry experts',
    cta: 'Browse Courses',
    ctaLink: '/courses',
    gradient: 'from-blue-600 via-indigo-600 to-violet-700',
    iconGradient: 'from-blue-400 to-indigo-500',
    accentColor: 'blue',
  },
  {
    id: 'typing',
    icon: Keyboard,
    headline: 'Speed Up Your Typing',
    subtext: 'Fun games, real-time PvP battles, and detailed stats to track your WPM',
    cta: 'Start Typing',
    ctaLink: '/games/typing',
    gradient: 'from-orange-500 via-amber-500 to-yellow-500',
    iconGradient: 'from-orange-400 to-amber-500',
    accentColor: 'amber',
  },
  {
    id: 'quizzes',
    icon: Brain,
    headline: 'Test Your Knowledge',
    subtext: 'Interactive quizzes across IT topics with instant feedback and explanations',
    cta: 'Take a Quiz',
    ctaLink: '/quizzes',
    gradient: 'from-purple-600 via-fuchsia-600 to-pink-600',
    iconGradient: 'from-purple-400 to-pink-500',
    accentColor: 'purple',
  },
  {
    id: 'tutorials',
    icon: BookOpen,
    headline: 'Learn Step by Step',
    subtext: 'Bite-sized tutorials for every skill level, with hands-on examples',
    cta: 'Explore Tutorials',
    ctaLink: '/tutorials',
    gradient: 'from-emerald-500 via-teal-500 to-cyan-600',
    iconGradient: 'from-emerald-400 to-teal-500',
    accentColor: 'emerald',
  },
  {
    id: 'leaderboard',
    icon: Trophy,
    headline: 'Compete & Climb',
    subtext: 'Earn XP, unlock achievements, and race to the top of the leaderboard',
    cta: 'View Leaderboard',
    ctaLink: '/leaderboard',
    gradient: 'from-yellow-500 via-amber-500 to-orange-600',
    iconGradient: 'from-yellow-400 to-orange-500',
    accentColor: 'yellow',
  },
  {
    id: 'progress',
    icon: Target,
    headline: 'Track Your Journey',
    subtext: 'See your progress, maintain streaks, and celebrate milestones',
    cta: 'My Dashboard',
    ctaLink: '/dashboard',
    gradient: 'from-cyan-500 via-blue-500 to-indigo-600',
    iconGradient: 'from-cyan-400 to-blue-500',
    accentColor: 'cyan',
  },
];
