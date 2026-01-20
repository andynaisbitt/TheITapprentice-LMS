// src/config/adminNavigation.ts
/**
 * Admin Sidebar Navigation Configuration
 * Defines the structure of the admin panel sidebar menu
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
}

export interface NavSection {
  id: string;
  label: string;
  icon: LucideIcon;
  items: NavItem[];
  badge?: string | number;
}

export const adminNavigation: NavSection[] = [
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
    items: [
      {
        label: 'Tutorials',
        icon: BookOpen,
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
        children: [
          { label: 'All Courses', path: '/admin/courses' },
          { label: 'New Course', path: '/admin/courses/new' },
          { label: 'Enrollments', path: '/admin/courses/enrollments' },
        ],
      },
      {
        label: 'Typing Games',
        icon: Keyboard,
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

// Helper to find active section based on current path
export const findActiveSection = (pathname: string): string | null => {
  for (const section of adminNavigation) {
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
