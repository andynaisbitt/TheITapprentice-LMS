// src/utils/navUtils.ts
import {
  BookOpen,
  GraduationCap,
  ClipboardCheck,
  Gamepad2,
  Target,
  FileText,
  Home,
  HelpCircle,
  Trophy,
  Users,
  Settings,
  User,
  Keyboard,
  Brain,
  Award,
  BarChart3,
  Zap,
  type LucideIcon,
} from 'lucide-react';

// Icon mapping based on URL patterns
const iconMap: Record<string, LucideIcon> = {
  '/': Home,
  '/home': Home,
  '/courses': GraduationCap,
  '/tutorials': BookOpen,
  '/quizzes': ClipboardCheck,
  '/typing': Keyboard,
  '/practice': Target,
  '/games': Gamepad2,
  '/blog': FileText,
  '/help': HelpCircle,
  '/achievements': Trophy,
  '/leaderboard': BarChart3,
  '/challenges': Brain,
  '/skills': Award,
  '/about': Users,
  '/profile': User,
  '/settings': Settings,
  '/dashboard': Zap,
};

export const getIconForUrl = (url: string): LucideIcon => {
  // Check exact match first
  if (iconMap[url]) return iconMap[url];

  // Check prefix match
  for (const [pattern, icon] of Object.entries(iconMap)) {
    if (url.startsWith(pattern) && pattern !== '/') {
      return icon;
    }
  }

  return BookOpen; // Default icon
};

// Gradient mapping based on URL patterns
const gradientMap: Record<string, string> = {
  '/courses': 'bg-gradient-to-br from-emerald-500 via-green-600 to-teal-700',
  '/tutorials': 'bg-gradient-to-br from-blue-500 via-cyan-600 to-teal-600',
  '/quizzes': 'bg-gradient-to-br from-indigo-500 via-purple-600 to-pink-600',
  '/typing': 'bg-gradient-to-br from-orange-500 via-amber-600 to-yellow-600',
  '/practice': 'bg-gradient-to-br from-orange-500 via-amber-600 to-yellow-600',
  '/games': 'bg-gradient-to-br from-rose-500 via-red-600 to-orange-600',
  '/blog': 'bg-gradient-to-br from-green-500 via-emerald-600 to-teal-600',
  '/achievements': 'bg-gradient-to-br from-yellow-500 via-amber-600 to-orange-600',
  '/leaderboard': 'bg-gradient-to-br from-purple-500 via-violet-600 to-indigo-600',
  '/challenges': 'bg-gradient-to-br from-pink-500 via-rose-600 to-red-600',
  '/skills': 'bg-gradient-to-br from-violet-500 via-purple-600 to-fuchsia-600',
  '/help': 'bg-gradient-to-br from-slate-500 via-gray-600 to-zinc-700',
  '/dashboard': 'bg-gradient-to-br from-blue-600 via-indigo-600 to-violet-600',
};

export const getGradientForUrl = (url: string): string => {
  // Check exact match first
  if (gradientMap[url]) return gradientMap[url];

  // Check prefix match
  for (const [pattern, gradient] of Object.entries(gradientMap)) {
    if (url.startsWith(pattern)) {
      return gradient;
    }
  }

  return 'bg-gradient-to-br from-slate-600 via-gray-700 to-zinc-800';
};

// URL categorization for tabs
export const tabUrlMappings = {
  learn: ['/courses', '/tutorials', '/quizzes', '/skills'],
  practice: ['/typing-practice', '/challenges', '/practice'],
};

export const categorizeNavItem = (url: string): 'learn' | 'practice' | 'overview' => {
  for (const [tab, urls] of Object.entries(tabUrlMappings)) {
    if (urls.some(pattern => url.startsWith(pattern))) {
      return tab as 'learn' | 'practice';
    }
  }
  return 'overview';
};

// Subtitle suggestions based on URL
const subtitleMap: Record<string, string> = {
  '/courses': 'Structured Learning Paths',
  '/tutorials': 'Quick Learning Guides',
  '/quizzes': 'Test Your Knowledge',
  '/typing': 'Build Typing Speed',
  '/practice': 'Skill-Building Exercises',
  '/games': 'Learn Through Play',
  '/blog': 'Tech Articles & News',
  '/achievements': 'Your Accomplishments',
  '/leaderboard': 'Top Performers',
  '/challenges': 'Daily Challenges',
  '/skills': 'Track Your Progress',
  '/help': 'Support & Resources',
};

export const getSubtitleForUrl = (url: string): string => {
  if (subtitleMap[url]) return subtitleMap[url];

  for (const [pattern, subtitle] of Object.entries(subtitleMap)) {
    if (url.startsWith(pattern)) {
      return subtitle;
    }
  }

  return 'Explore more';
};
