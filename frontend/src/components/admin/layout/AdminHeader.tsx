// src/components/admin/layout/AdminHeader.tsx
/**
 * Admin Panel Header Bar
 * Slim header with breadcrumbs, search, and quick actions
 */

import { useLocation, Link } from 'react-router-dom';
import {
  Menu,
  Bell,
  Search,
  Sun,
  Moon,
  Plus,
} from 'lucide-react';
import { useState, useEffect } from 'react';

interface AdminHeaderProps {
  onMenuClick: () => void;
  sidebarCollapsed: boolean;
}

// Generate breadcrumbs from pathname
const generateBreadcrumbs = (pathname: string) => {
  const paths = pathname.split('/').filter(Boolean);
  const breadcrumbs: { label: string; path: string }[] = [];

  let currentPath = '';
  for (const segment of paths) {
    currentPath += `/${segment}`;

    // Convert segment to readable label
    let label = segment
      .replace(/-/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());

    // Handle special cases
    if (segment === 'admin') label = 'Dashboard';
    if (segment === 'blog' && paths.includes('admin')) label = 'New Post';
    if (segment === 'lms') label = 'LMS';
    if (segment === 'xp-config') label = 'XP & Levels';

    breadcrumbs.push({ label, path: currentPath });
  }

  return breadcrumbs;
};

export const AdminHeader: React.FC<AdminHeaderProps> = ({
  onMenuClick,
  sidebarCollapsed,
}) => {
  const location = useLocation();
  const breadcrumbs = generateBreadcrumbs(location.pathname);
  const [isDark, setIsDark] = useState(false);
  const [showSearch, setShowSearch] = useState(false);

  useEffect(() => {
    setIsDark(document.documentElement.classList.contains('dark'));
  }, []);

  const toggleTheme = () => {
    const newIsDark = !isDark;
    setIsDark(newIsDark);

    if (newIsDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  };

  return (
    <header
      className={`
        fixed top-0 right-0 h-16
        bg-white dark:bg-gray-900
        border-b border-gray-200 dark:border-gray-800
        flex items-center justify-between px-4
        z-30
        transition-all duration-300
        left-0
        ${sidebarCollapsed ? 'lg:left-16' : 'lg:left-60'}
      `}
    >
      {/* Left: Menu button (mobile) + Breadcrumbs */}
      <div className="flex items-center gap-4">
        {/* Mobile menu button */}
        <button
          onClick={onMenuClick}
          className="lg:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
        >
          <Menu className="w-5 h-5 text-gray-500" />
        </button>

        {/* Breadcrumbs */}
        <nav className="hidden sm:flex items-center gap-2 text-sm">
          {breadcrumbs.map((crumb, index) => (
            <div key={crumb.path} className="flex items-center gap-2">
              {index > 0 && (
                <span className="text-gray-400 dark:text-gray-600">/</span>
              )}
              {index === breadcrumbs.length - 1 ? (
                <span className="font-medium text-gray-900 dark:text-white">
                  {crumb.label}
                </span>
              ) : (
                <Link
                  to={crumb.path}
                  className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors"
                >
                  {crumb.label}
                </Link>
              )}
            </div>
          ))}
        </nav>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2">
        {/* Search */}
        {showSearch ? (
          <div className="relative">
            <input
              type="text"
              placeholder="Search..."
              autoFocus
              onBlur={() => setShowSearch(false)}
              className="
                w-64 px-4 py-2 pl-10
                bg-gray-100 dark:bg-gray-800
                border border-transparent focus:border-primary
                rounded-lg text-sm
                focus:outline-none focus:ring-2 focus:ring-primary/20
              "
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          </div>
        ) : (
          <button
            onClick={() => setShowSearch(true)}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            title="Search"
          >
            <Search className="w-5 h-5 text-gray-500" />
          </button>
        )}

        {/* Quick Add */}
        <div className="relative group">
          <button
            className="
              flex items-center gap-1 px-3 py-2
              bg-primary text-white rounded-lg
              hover:bg-primary-dark transition-colors
              text-sm font-medium
            "
          >
            <Plus className="w-4 h-4" />
            <span className="hidden sm:inline">New</span>
          </button>

          {/* Dropdown */}
          <div
            className="
              absolute right-0 top-full mt-2
              w-48 bg-white dark:bg-gray-800
              border border-gray-200 dark:border-gray-700
              rounded-lg shadow-lg
              opacity-0 invisible group-hover:opacity-100 group-hover:visible
              transition-all duration-200
              z-50
            "
          >
            <Link
              to="/admin/blog"
              className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-t-lg"
            >
              New Post
            </Link>
            <Link
              to="/admin/tutorials/new"
              className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              New Tutorial
            </Link>
            <Link
              to="/admin/courses/new"
              className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              New Course
            </Link>
            <Link
              to="/admin/pages/new"
              className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-b-lg"
            >
              New Page
            </Link>
          </div>
        </div>

        {/* Notifications */}
        <button
          className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors relative"
          title="Notifications"
        >
          <Bell className="w-5 h-5 text-gray-500" />
          {/* Notification badge */}
          <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
        </button>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {isDark ? (
            <Sun className="w-5 h-5 text-gray-500" />
          ) : (
            <Moon className="w-5 h-5 text-gray-500" />
          )}
        </button>
      </div>
    </header>
  );
};

export default AdminHeader;
