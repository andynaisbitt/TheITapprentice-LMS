// src/components/home/FeatureShowcaseHero/slideData.ts
import {
  GraduationCap,
  Keyboard,
  Brain,
  BookOpen,
  Trophy,
  Target,
  Sparkles,
  Award,
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
    headline: 'Learn IT Basics',
    subtext: 'Step-by-step courses for complete beginners. No experience needed.',
    cta: 'Start Learning',
    ctaLink: '/courses',
    gradient: 'from-blue-600 via-indigo-600 to-violet-700',
    iconGradient: 'from-blue-400 to-indigo-500',
    accentColor: 'blue',
  },
  {
    id: 'skills',
    icon: Sparkles,
    headline: 'Level Up Your Skills',
    subtext: 'Track your progress across PC basics, typing, email, and more',
    cta: 'View Skills',
    ctaLink: '/skills',
    gradient: 'from-violet-600 via-purple-600 to-fuchsia-600',
    iconGradient: 'from-violet-400 to-purple-500',
    accentColor: 'violet',
  },
  {
    id: 'typing',
    icon: Keyboard,
    headline: 'Learn to Type Fast',
    subtext: 'Fun typing games to boost your speed. Track your WPM and accuracy.',
    cta: 'Start Typing',
    ctaLink: '/typing-practice',
    gradient: 'from-orange-500 via-amber-500 to-yellow-500',
    iconGradient: 'from-orange-400 to-amber-500',
    accentColor: 'amber',
  },
  {
    id: 'quizzes',
    icon: Brain,
    headline: 'Test What You Know',
    subtext: 'Quick quizzes on keyboards, files, shortcuts, and IT basics',
    cta: 'Take a Quiz',
    ctaLink: '/quizzes',
    gradient: 'from-purple-600 via-fuchsia-600 to-pink-600',
    iconGradient: 'from-purple-400 to-pink-500',
    accentColor: 'purple',
  },
  {
    id: 'tutorials',
    icon: BookOpen,
    headline: 'Follow Along Guides',
    subtext: 'Easy tutorials: set up email, connect to WiFi, install apps',
    cta: 'Browse Tutorials',
    ctaLink: '/tutorials',
    gradient: 'from-emerald-500 via-teal-500 to-cyan-600',
    iconGradient: 'from-emerald-400 to-teal-500',
    accentColor: 'emerald',
  },
  {
    id: 'leaderboard',
    icon: Trophy,
    headline: 'See How You Rank',
    subtext: 'Compete with other learners and climb the weekly leaderboard',
    cta: 'View Leaderboard',
    ctaLink: '/leaderboard',
    gradient: 'from-yellow-500 via-amber-500 to-orange-600',
    iconGradient: 'from-yellow-400 to-orange-500',
    accentColor: 'yellow',
  },
  {
    id: 'certifications',
    icon: Award,
    headline: 'Earn Achievements',
    subtext: 'Complete challenges to unlock badges and show off your progress',
    cta: 'My Achievements',
    ctaLink: '/certifications',
    gradient: 'from-amber-500 via-yellow-500 to-lime-500',
    iconGradient: 'from-amber-400 to-yellow-500',
    accentColor: 'amber',
  },
  {
    id: 'progress',
    icon: Target,
    headline: 'Your Dashboard',
    subtext: 'See your streak, XP, level, and everything you have accomplished',
    cta: 'My Dashboard',
    ctaLink: '/dashboard',
    gradient: 'from-cyan-500 via-blue-500 to-indigo-600',
    iconGradient: 'from-cyan-400 to-blue-500',
    accentColor: 'cyan',
  },
];
