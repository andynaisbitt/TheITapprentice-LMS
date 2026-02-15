// src/config/publicNavigation.ts
/**
 * Public Navigation Configuration
 * Defines the structure for public-facing sidebar navigation
 * Supports dynamic filtering based on enabled plugins
 */

import {
  GraduationCap,
  BookOpen,
  ClipboardCheck,
  Award,
  Keyboard,
  Brain,
  Home,
  BarChart3,
  FileText,
  Trophy,
  User,
  Settings,
  Shield,
  type LucideIcon,
} from 'lucide-react';

export interface PublicNavItem {
  id: string;
  label: string;
  path: string;
  icon: LucideIcon;
  subtitle?: string;
  description?: string;
  category: 'learn' | 'practice' | 'overview' | 'account';
  requiresPlugin?: string;
  requiresAuth?: boolean;
  isPopular?: boolean;
  isNew?: boolean;
}

export interface PublicNavSection {
  id: string;
  label: string;
  icon: LucideIcon;
  category: 'learn' | 'practice' | 'overview' | 'account';
  items: PublicNavItem[];
  hideIfEmpty?: boolean;
  requiresAuth?: boolean;
}

/**
 * Full public navigation structure
 * Items with requiresPlugin will only show when that plugin is enabled
 */
export const publicNavigationConfig: PublicNavSection[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: Home,
    category: 'overview',
    items: [
      {
        id: 'dashboard',
        label: 'Dashboard',
        path: '/dashboard',
        icon: Home,
        subtitle: 'Your Learning Hub',
        description: 'Track your progress, see recent activity, and continue where you left off.',
        category: 'overview',
        requiresAuth: true,
      },
      {
        id: 'blog',
        label: 'Blog',
        path: '/blog',
        icon: FileText,
        subtitle: 'Latest Articles',
        description: 'Read the latest articles and tutorials.',
        category: 'overview',
      },
      {
        id: 'leaderboard',
        label: 'Leaderboard',
        path: '/leaderboard',
        icon: Trophy,
        subtitle: 'Top Performers',
        description: 'See how you rank against other learners.',
        category: 'overview',
      },
    ],
  },
  {
    id: 'learn',
    label: 'Learn',
    icon: GraduationCap,
    category: 'learn',
    hideIfEmpty: true,
    items: [
      {
        id: 'courses',
        label: 'Courses',
        path: '/courses',
        icon: GraduationCap,
        subtitle: 'Structured Learning Paths',
        description: 'Comprehensive courses with interactive content and real-world projects.',
        category: 'learn',
        requiresPlugin: 'courses',
        isPopular: true,
      },
      {
        id: 'tutorials',
        label: 'Tutorials',
        path: '/tutorials',
        icon: BookOpen,
        subtitle: 'Quick Learning Guides',
        description: 'Step-by-step tutorials covering specific topics and technologies.',
        category: 'learn',
        requiresPlugin: 'tutorials',
      },
      {
        id: 'quizzes',
        label: 'Quizzes',
        path: '/quizzes',
        icon: ClipboardCheck,
        subtitle: 'Test Your Knowledge',
        description: 'Practice quizzes to reinforce learning and track your understanding.',
        category: 'learn',
        requiresPlugin: 'quizzes',
      },
      {
        id: 'skills',
        label: 'Skills',
        path: '/skills',
        icon: Award,
        subtitle: 'Track Your Progress',
        description: 'Monitor your skill development across different areas.',
        category: 'learn',
        requiresPlugin: 'skills',
        isNew: true,
      },
    ],
  },
  {
    id: 'practice',
    label: 'Practice',
    icon: Keyboard,
    category: 'practice',
    hideIfEmpty: true,
    items: [
      {
        id: 'typing-practice',
        label: 'Typing Practice',
        path: '/typing-practice',
        icon: Keyboard,
        subtitle: 'Build Speed & Accuracy',
        description: 'Master typing with IT terminology. Build muscle memory with real-world commands!',
        category: 'practice',
        requiresPlugin: 'typing_game',
        isPopular: true,
      },
      {
        id: 'challenges',
        label: 'Daily Challenges',
        path: '/challenges',
        icon: Brain,
        subtitle: 'Earn Streak Bonuses',
        description: 'Complete daily tasks to earn XP with up to 100% bonus from consecutive day streaks!',
        category: 'practice',
        isNew: true,
      },
    ],
  },
  {
    id: 'account',
    label: 'Account',
    icon: User,
    category: 'account',
    requiresAuth: true,
    items: [
      {
        id: 'profile',
        label: 'Profile',
        path: '/profile',
        icon: User,
        subtitle: 'Your Profile',
        description: 'View and edit your profile information.',
        category: 'account',
        requiresAuth: true,
      },
      {
        id: 'settings',
        label: 'Settings',
        path: '/settings',
        icon: Settings,
        subtitle: 'Preferences',
        description: 'Manage your account settings and preferences.',
        category: 'account',
        requiresAuth: true,
      },
      {
        id: 'admin',
        label: 'Admin Dashboard',
        path: '/admin',
        icon: Shield,
        subtitle: 'Site Management',
        description: 'Access the admin dashboard to manage your site.',
        category: 'account',
        requiresAuth: true,
      },
    ],
  },
];

/**
 * Filter a single navigation item based on enabled plugins and auth status
 */
export const filterPublicNavItem = (
  item: PublicNavItem,
  isPluginEnabled: (pluginId: string) => boolean,
  isAuthenticated?: boolean
): PublicNavItem | null => {
  // Check if item requires a plugin that's not enabled
  if (item.requiresPlugin && !isPluginEnabled(item.requiresPlugin)) {
    return null;
  }

  // Check if item requires authentication
  if (item.requiresAuth && !isAuthenticated) {
    return null;
  }

  return item;
};

/**
 * Get filtered navigation based on enabled plugins and auth status
 */
export const getFilteredPublicNavigation = (
  isPluginEnabled: (pluginId: string) => boolean,
  isAuthenticated?: boolean,
  isAdmin?: boolean
): PublicNavSection[] => {
  return publicNavigationConfig
    .map((section) => {
      // Check if section requires authentication
      if (section.requiresAuth && !isAuthenticated) {
        return null;
      }

      // Filter items
      const filteredItems = section.items
        .map((item) => filterPublicNavItem(item, isPluginEnabled, isAuthenticated))
        .filter((item): item is PublicNavItem => item !== null)
        // Filter out admin item if not admin
        .filter((item) => item.id !== 'admin' || isAdmin);

      // If hideIfEmpty and no items, hide section
      if (section.hideIfEmpty && filteredItems.length === 0) {
        return null;
      }

      // Hide account section if all items are filtered out
      if (section.id === 'account' && filteredItems.length === 0) {
        return null;
      }

      return { ...section, items: filteredItems };
    })
    .filter((section): section is PublicNavSection => section !== null);
};

/**
 * Get items by category
 */
export const getItemsByCategory = (
  sections: PublicNavSection[],
  category: PublicNavItem['category']
): PublicNavItem[] => {
  return sections
    .filter((section) => section.category === category)
    .flatMap((section) => section.items);
};

/**
 * Helper to check if a path is active (exact or starts with)
 */
export const isPublicPathActive = (itemPath: string, currentPath: string): boolean => {
  if (itemPath === '/') {
    return currentPath === '/';
  }
  if (itemPath === '/dashboard') {
    return currentPath === '/dashboard';
  }
  return currentPath === itemPath || currentPath.startsWith(itemPath + '/');
};

/**
 * Find the active section based on current path
 */
export const findActivePublicSection = (pathname: string): string | null => {
  for (const section of publicNavigationConfig) {
    for (const item of section.items) {
      if (isPublicPathActive(item.path, pathname)) {
        return section.id;
      }
    }
  }
  return null;
};

/**
 * Legacy export for backward compatibility
 */
export const publicNavigation = publicNavigationConfig;
