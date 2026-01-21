// src/config/adminNavigation.ts
/**
 * Admin Sidebar Navigation Configuration
 * Defines the structure of the admin panel sidebar menu
 * Supports dynamic filtering based on enabled plugins
 */

import {
  LayoutDashboard,
  Home,
  BarChart3,
  FileText,
  Files,
  FilePlus,
  FolderTree,
  Tags,
  GraduationCap,
  BookOpen,
  Library,
  Keyboard,
  ClipboardList,
  TrendingUp,
  Users,
  Shield,
  Trophy,
  Zap,
  Activity,
  Settings,
  Palette,
  Menu,
  Mail,
  Puzzle,
  HeartPulse,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  label: string;
  path?: string;
  icon?: LucideIcon;
  children?: NavItem[];
  badge?: string | number;
  /** Plugin ID required for this item to be visible */
  requiresPlugin?: string;
}

export interface NavSection {
  id: string;
  label: string;
  icon: LucideIcon;
  items: NavItem[];
  badge?: string | number;
  /** Plugin ID required for this section to be visible */
  requiresPlugin?: string;
  /** If true, section is shown only if ANY of its items are visible */
  hideIfEmpty?: boolean;
}

/**
 * Full admin navigation structure
 * Items with requiresPlugin will only show when that plugin is enabled
 */
export const adminNavigationConfig: NavSection[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: LayoutDashboard,
    items: [
      { label: 'Overview', path: '/admin', icon: Home },
      { label: 'Analytics', path: '/admin/analytics', icon: BarChart3 },
    ],
  },
  {
    id: 'content',
    label: 'Content',
    icon: FileText,
    items: [
      { label: 'All Posts', path: '/admin/posts', icon: Files },
      { label: 'New Post', path: '/admin/blog', icon: FilePlus },
      { label: 'Categories', path: '/admin/categories', icon: FolderTree },
      { label: 'Tags', path: '/admin/tags', icon: Tags },
      { label: 'Pages', path: '/admin/pages', icon: FileText },
    ],
  },
  {
    id: 'lms',
    label: 'LMS',
    icon: GraduationCap,
    hideIfEmpty: true,
    items: [
      {
        label: 'Tutorials',
        icon: BookOpen,
        requiresPlugin: 'tutorials',
        children: [
          { label: 'All Tutorials', path: '/admin/tutorials' },
          { label: 'New Tutorial', path: '/admin/tutorials/new' },
          { label: 'Categories', path: '/admin/tutorial-categories' },
          { label: 'Analytics', path: '/admin/tutorials/analytics' },
          { label: 'User Progress', path: '/admin/tutorials/user-progress' },
        ],
      },
      {
        label: 'Courses',
        icon: Library,
        requiresPlugin: 'courses',
        children: [
          { label: 'All Courses', path: '/admin/courses' },
          { label: 'New Course', path: '/admin/courses/new' },
          { label: 'Enrollments', path: '/admin/courses/enrollments' },
        ],
      },
      {
        label: 'Quizzes',
        icon: ClipboardList,
        requiresPlugin: 'quizzes',
        children: [
          { label: 'All Quizzes', path: '/admin/quizzes' },
          { label: 'New Quiz', path: '/admin/quizzes/new' },
        ],
      },
      {
        label: 'Typing Games',
        icon: Keyboard,
        requiresPlugin: 'typing_game',
        children: [
          { label: 'Word Lists', path: '/admin/games/word-lists' },
          { label: 'Challenges', path: '/admin/games/challenges' },
          { label: 'Leaderboard', path: '/admin/games/leaderboard' },
        ],
      },
      { label: 'Student Progress', path: '/admin/lms/progress', icon: TrendingUp },
    ],
  },
  {
    id: 'users',
    label: 'Users',
    icon: Users,
    items: [
      { label: 'All Users', path: '/admin/users', icon: Users },
      { label: 'Roles & Permissions', path: '/admin/users/roles', icon: Shield },
      { label: 'Achievements', path: '/admin/achievements', icon: Trophy },
      { label: 'XP & Levels', path: '/admin/xp-config', icon: Zap },
      { label: 'Activity Log', path: '/admin/activity', icon: Activity },
    ],
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: Settings,
    items: [
      { label: 'General', path: '/admin/settings', icon: Settings },
      { label: 'Theme', path: '/admin/theme', icon: Palette },
      { label: 'Navigation', path: '/admin/navigation', icon: Menu },
      { label: 'Newsletter', path: '/admin/newsletter', icon: Mail },
      { label: 'Plugins', path: '/admin/plugins', icon: Puzzle },
      { label: 'System Health', path: '/admin/system', icon: HeartPulse },
    ],
  },
];

/**
 * Filter navigation items based on enabled plugins
 */
export const filterNavItem = (
  item: NavItem,
  isPluginEnabled: (pluginId: string) => boolean
): NavItem | null => {
  // Check if item requires a plugin that's not enabled
  if (item.requiresPlugin && !isPluginEnabled(item.requiresPlugin)) {
    return null;
  }

  // If item has children, filter them too
  if (item.children) {
    const filteredChildren = item.children
      .map((child) => filterNavItem(child, isPluginEnabled))
      .filter((child): child is NavItem => child !== null);

    // If all children were filtered out, hide the parent too
    if (filteredChildren.length === 0) {
      return null;
    }

    return { ...item, children: filteredChildren };
  }

  return item;
};

/**
 * Get filtered navigation based on enabled plugins
 */
export const getFilteredNavigation = (
  isPluginEnabled: (pluginId: string) => boolean
): NavSection[] => {
  return adminNavigationConfig
    .map((section) => {
      // Check if section requires a plugin
      if (section.requiresPlugin && !isPluginEnabled(section.requiresPlugin)) {
        return null;
      }

      // Filter items
      const filteredItems = section.items
        .map((item) => filterNavItem(item, isPluginEnabled))
        .filter((item): item is NavItem => item !== null);

      // If hideIfEmpty and no items, hide section
      if (section.hideIfEmpty && filteredItems.length === 0) {
        return null;
      }

      return { ...section, items: filteredItems };
    })
    .filter((section): section is NavSection => section !== null);
};

/**
 * Legacy export for backward compatibility
 * Returns full navigation (use getFilteredNavigation for plugin-aware nav)
 */
export const adminNavigation = adminNavigationConfig;

// Helper to find active section based on current path
export const findActiveSection = (pathname: string): string | null => {
  for (const section of adminNavigationConfig) {
    for (const item of section.items) {
      if (item.path === pathname) {
        return section.id;
      }
      if (item.children) {
        for (const child of item.children) {
          if (child.path === pathname) {
            return section.id;
          }
        }
      }
    }
  }
  return 'dashboard'; // Default to dashboard
};

// Helper to check if a path is active (exact or starts with)
export const isPathActive = (itemPath: string, currentPath: string): boolean => {
  if (itemPath === '/admin') {
    return currentPath === '/admin';
  }
  return currentPath === itemPath || currentPath.startsWith(itemPath + '/');
};
