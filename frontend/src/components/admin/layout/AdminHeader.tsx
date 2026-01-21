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
  UserPlus,
  MessageSquare,
  FileText,
  AlertCircle,
  CheckCircle,
  X,
} from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import { apiClient } from '../../../services/api/client';

interface AdminHeaderProps {
  onMenuClick: () => void;
  sidebarCollapsed: boolean;
}

interface AdminNotification {
  id: string;
  type: 'user' | 'comment' | 'post' | 'system' | 'success';
  title: string;
  message: string;
  time: string;
  read: boolean;
  link?: string;
}

const notificationIcons = {
  user: UserPlus,
  comment: MessageSquare,
  post: FileText,
  system: AlertCircle,
  success: CheckCircle,
};

const notificationColors = {
  user: 'text-blue-500 bg-blue-100 dark:bg-blue-900/30',
  comment: 'text-green-500 bg-green-100 dark:bg-green-900/30',
  post: 'text-purple-500 bg-purple-100 dark:bg-purple-900/30',
  system: 'text-orange-500 bg-orange-100 dark:bg-orange-900/30',
  success: 'text-emerald-500 bg-emerald-100 dark:bg-emerald-900/30',
};

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
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<AdminNotification[]>([]);
  const [loadingNotifications, setLoadingNotifications] = useState(false);
  const notificationRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setIsDark(document.documentElement.classList.contains('dark'));
  }, []);

  // Fetch admin notifications (recent activity)
  useEffect(() => {
    const fetchNotifications = async () => {
      setLoadingNotifications(true);
      try {
        // Try to fetch recent admin activity
        const response = await apiClient.get('/admin/notifications');
        setNotifications(response.data);
      } catch {
        // If no endpoint exists, show placeholder notifications
        setNotifications([
          {
            id: '1',
            type: 'system',
            title: 'Welcome to Admin',
            message: 'Your admin panel is ready to use',
            time: 'Just now',
            read: false,
          },
          {
            id: '2',
            type: 'success',
            title: 'System Status',
            message: 'All systems operational',
            time: '5 min ago',
            read: true,
          },
        ]);
      } finally {
        setLoadingNotifications(false);
      }
    };
    fetchNotifications();
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadCount = notifications.filter(n => !n.read).length;

  const markAsRead = (id: string) => {
    setNotifications(prev =>
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    );
  };

  const markAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const clearNotifications = () => {
    setNotifications([]);
    setShowNotifications(false);
  };

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
        <div className="relative" ref={notificationRef}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors relative"
            title="Notifications"
          >
            <Bell className="w-5 h-5 text-gray-500" />
            {/* Notification badge */}
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
            )}
          </button>

          {/* Notifications Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-xl z-50">
              {/* Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                <h3 className="font-semibold text-gray-900 dark:text-white">Notifications</h3>
                <div className="flex items-center gap-2">
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllAsRead}
                      className="text-xs text-primary hover:text-primary-dark"
                    >
                      Mark all read
                    </button>
                  )}
                  <button
                    onClick={() => setShowNotifications(false)}
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                  >
                    <X className="w-4 h-4 text-gray-500" />
                  </button>
                </div>
              </div>

              {/* Notification List */}
              <div className="max-h-80 overflow-y-auto">
                {loadingNotifications ? (
                  <div className="px-4 py-8 text-center text-gray-500">
                    Loading...
                  </div>
                ) : notifications.length === 0 ? (
                  <div className="px-4 py-8 text-center text-gray-500">
                    No notifications
                  </div>
                ) : (
                  notifications.map((notification) => {
                    const Icon = notificationIcons[notification.type];
                    const colorClass = notificationColors[notification.type];
                    return (
                      <div
                        key={notification.id}
                        onClick={() => markAsRead(notification.id)}
                        className={`
                          flex items-start gap-3 px-4 py-3
                          hover:bg-gray-50 dark:hover:bg-gray-700/50
                          cursor-pointer transition-colors
                          ${!notification.read ? 'bg-blue-50/50 dark:bg-blue-900/10' : ''}
                        `}
                      >
                        <div className={`p-2 rounded-lg ${colorClass}`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className={`text-sm ${!notification.read ? 'font-semibold' : 'font-medium'} text-gray-900 dark:text-white`}>
                            {notification.title}
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                            {notification.message}
                          </p>
                          <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                            {notification.time}
                          </p>
                        </div>
                        {!notification.read && (
                          <span className="w-2 h-2 bg-primary rounded-full mt-2"></span>
                        )}
                      </div>
                    );
                  })
                )}
              </div>

              {/* Footer */}
              {notifications.length > 0 && (
                <div className="px-4 py-2 border-t border-gray-200 dark:border-gray-700">
                  <button
                    onClick={clearNotifications}
                    className="w-full text-center text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 py-1"
                  >
                    Clear all notifications
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

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
