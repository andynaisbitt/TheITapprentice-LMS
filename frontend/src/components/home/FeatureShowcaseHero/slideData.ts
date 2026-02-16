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
  Rocket,
  Flame,
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
    id: 'welcome',
    icon: Rocket,
    headline: 'Your IT Journey Starts Here',
    subtext: 'Free courses, typing games, quizzes, and challenges — everything you need to build real IT skills.',
    cta: 'Get Started',
    ctaLink: '/courses',
    gradient: 'from-slate-800 to-indigo-800',
    iconGradient: 'from-indigo-300 to-violet-400',
    accentColor: 'indigo',
  },
  {
    id: 'courses',
    icon: GraduationCap,
    headline: 'Learn IT Basics',
    subtext: 'Step-by-step courses for complete beginners. No experience needed.',
    cta: 'Start Learning',
    ctaLink: '/courses',
    gradient: 'from-blue-800 to-indigo-700',
    iconGradient: 'from-blue-300 to-indigo-400',
    accentColor: 'blue',
  },
  {
    id: 'skills',
    icon: Sparkles,
    headline: 'Level Up Your Skills',
    subtext: 'Track your progress across PC basics, typing, email, and more',
    cta: 'View Skills',
    ctaLink: '/skills',
    gradient: 'from-violet-800 to-purple-700',
    iconGradient: 'from-violet-300 to-purple-400',
    accentColor: 'violet',
  },
  {
    id: 'typing',
    icon: Keyboard,
    headline: 'Learn to Type Fast',
    subtext: 'Fun typing games to boost your speed. Track your WPM and accuracy.',
    cta: 'Start Typing',
    ctaLink: '/typing-practice',
    gradient: 'from-amber-800 to-orange-700',
    iconGradient: 'from-amber-300 to-orange-400',
    accentColor: 'amber',
  },
  {
    id: 'quizzes',
    icon: Brain,
    headline: 'Test What You Know',
    subtext: 'Quick quizzes on keyboards, files, shortcuts, and IT basics',
    cta: 'Take a Quiz',
    ctaLink: '/quizzes',
    gradient: 'from-purple-800 to-fuchsia-700',
    iconGradient: 'from-purple-300 to-pink-400',
    accentColor: 'purple',
  },
  {
    id: 'tutorials',
    icon: BookOpen,
    headline: 'Follow Along Guides',
    subtext: 'Easy tutorials: set up email, connect to WiFi, install apps',
    cta: 'Browse Tutorials',
    ctaLink: '/tutorials',
    gradient: 'from-emerald-800 to-teal-700',
    iconGradient: 'from-emerald-300 to-teal-400',
    accentColor: 'emerald',
  },
  {
    id: 'leaderboard',
    icon: Trophy,
    headline: 'See How You Rank',
    subtext: 'Compete with other learners and climb the weekly leaderboard',
    cta: 'View Leaderboard',
    ctaLink: '/leaderboard',
    gradient: 'from-amber-700 to-orange-800',
    iconGradient: 'from-amber-300 to-orange-400',
    accentColor: 'yellow',
  },
  {
    id: 'certifications',
    icon: Award,
    headline: 'Earn Achievements',
    subtext: 'Complete challenges to unlock badges and show off your progress',
    cta: 'My Achievements',
    ctaLink: '/certifications',
    gradient: 'from-amber-800 to-yellow-700',
    iconGradient: 'from-amber-300 to-yellow-400',
    accentColor: 'amber',
  },
  {
    id: 'challenges',
    icon: Flame,
    headline: 'Daily Challenges',
    subtext: 'Complete daily tasks to earn XP, build streaks, and climb the leaderboard.',
    cta: "Today's Challenges",
    ctaLink: '/challenges',
    gradient: 'from-rose-800 to-red-700',
    iconGradient: 'from-rose-300 to-red-400',
    accentColor: 'rose',
  },
  {
    id: 'progress',
    icon: Target,
    headline: 'Your Dashboard',
    subtext: 'See your streak, XP, level, and everything you have accomplished',
    cta: 'My Dashboard',
    ctaLink: '/dashboard',
    gradient: 'from-cyan-800 to-blue-700',
    iconGradient: 'from-cyan-300 to-blue-400',
    accentColor: 'cyan',
  },
];

// Spring animation presets
export const SPRING_SNAPPY = { type: 'spring' as const, stiffness: 400, damping: 28 };
export const SPRING_BOUNCY = { type: 'spring' as const, stiffness: 500, damping: 22 };
export const SPRING_GENTLE = { type: 'spring' as const, stiffness: 260, damping: 26 };
