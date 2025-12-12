// src/components/layout/Header.tsx
/**
 * Main Navigation Header
 * Includes logo, menu with dropdown support, search, and user actions
 */

import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../state/contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import { navigationApi, MenuItem } from '../../services/api/navigation.api';
import { useSiteSettings } from '../../hooks/useSiteSettings';

export const Header: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated, user, logout } = useAuth();
  const { refreshTheme } = useTheme();
  const { settings } = useSiteSettings();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [headerItems, setHeaderItems] = useState<MenuItem[]>([]);
  const [openDropdown, setOpenDropdown] = useState<number | null>(null);
  const dropdownTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    const fetchNavigation = async () => {
      try {
        const data = await navigationApi.getNavigation();
        setHeaderItems(data.header_items);
      } catch (error) {
        console.error('Failed to fetch navigation:', error);
        // Fallback to default navigation if API fails
        setHeaderItems([
          { id: 1, label: 'Home', url: '/', order: 1, parent_id: null, visible: true, show_in_header: true, show_in_footer: false, target_blank: false, created_at: '', updated_at: null },
          { id: 2, label: 'Blog', url: '/blog', order: 2, parent_id: null, visible: true, show_in_header: true, show_in_footer: false, target_blank: false, created_at: '', updated_at: null },
          { id: 3, label: 'About', url: '/about', order: 3, parent_id: null, visible: true, show_in_header: true, show_in_footer: false, target_blank: false, created_at: '', updated_at: null },
          { id: 4, label: 'Contact', url: '/contact', order: 4, parent_id: null, visible: true, show_in_header: true, show_in_footer: false, target_blank: false, created_at: '', updated_at: null },
        ]);
      }
    };

    fetchNavigation();
  }, []);

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const handleDropdownEnter = (itemId: number) => {
    if (dropdownTimeoutRef.current) {
      clearTimeout(dropdownTimeoutRef.current);
    }
    setOpenDropdown(itemId);
  };

  const handleDropdownLeave = () => {
    dropdownTimeoutRef.current = setTimeout(() => {
      setOpenDropdown(null);
    }, 200);
  };

  const renderNavItem = (item: MenuItem) => {
    const hasChildren = item.children && item.children.length > 0;

    if (hasChildren) {
      // Render dropdown menu
      return (
        <div
          key={item.id}
          className="relative group"
          onMouseEnter={() => handleDropdownEnter(item.id)}
          onMouseLeave={handleDropdownLeave}
        >
          <button
            className="flex items-center space-x-1 text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition font-medium"
          >
            <span>{item.label}</span>
            <svg
              className={`w-4 h-4 transition-transform ${openDropdown === item.id ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {/* Dropdown Menu */}
          {openDropdown === item.id && (
            <div className="absolute left-0 mt-2 w-56 bg-white dark:bg-slate-800 rounded-lg shadow-lg border border-gray-200 dark:border-slate-700 py-2 z-50">
              {item.children!.map((child) => (
                child.target_blank ? (
                  <a
                    key={child.id}
                    href={child.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 transition"
                  >
                    {child.label}
                  </a>
                ) : (
                  <Link
                    key={child.id}
                    to={child.url}
                    className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 transition"
                    onClick={() => setOpenDropdown(null)}
                  >
                    {child.label}
                  </Link>
                )
              ))}
            </div>
          )}
        </div>
      );
    }

    // Render regular menu item
    return item.target_blank ? (
      <a
        key={item.id}
        href={item.url}
        target="_blank"
        rel="noopener noreferrer"
        className="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition font-medium"
      >
        {item.label}
      </a>
    ) : (
      <Link
        key={item.id}
        to={item.url}
        className="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition font-medium"
      >
        {item.label}
      </Link>
    );
  };

  // Mobile nav item component - moved outside to fix React hooks error
  const MobileNavItem: React.FC<{ item: MenuItem; level?: number }> = ({ item, level = 0 }) => {
    const hasChildren = item.children && item.children.length > 0;
    const [isExpanded, setIsExpanded] = useState(false);

    if (hasChildren) {
      return (
        <div key={item.id}>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className={`w-full flex items-center justify-between text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition font-medium ${level > 0 ? 'pl-4' : ''}`}
          >
            <span>{item.label}</span>
            <svg
              className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {isExpanded && (
            <div className="ml-4 mt-2 space-y-2">
              {item.children!.map((child) => (
                child.target_blank ? (
                  <a
                    key={child.id}
                    href={child.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-sm text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition"
                    onClick={() => setIsMobileMenuOpen(false)}
                  >
                    {child.label}
                  </a>
                ) : (
                  <Link
                    key={child.id}
                    to={child.url}
                    className="block text-sm text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition"
                    onClick={() => setIsMobileMenuOpen(false)}
                  >
                    {child.label}
                  </Link>
                )
              ))}
            </div>
          )}
        </div>
      );
    }

    return item.target_blank ? (
      <a
        key={item.id}
        href={item.url}
        target="_blank"
        rel="noopener noreferrer"
        className={`block text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition font-medium ${level > 0 ? 'pl-4' : ''}`}
        onClick={() => setIsMobileMenuOpen(false)}
      >
        {item.label}
      </a>
    ) : (
      <Link
        key={item.id}
        to={item.url}
        className={`block text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition font-medium ${level > 0 ? 'pl-4' : ''}`}
        onClick={() => setIsMobileMenuOpen(false)}
      >
        {item.label}
      </Link>
    );
  };

  return (
    <header className="bg-white dark:bg-slate-900 shadow-sm sticky top-0 z-50 border-b border-gray-200 dark:border-slate-800">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2 sm:space-x-3 flex-shrink-0">
            {settings.logoUrl ? (
              /* Image Logo */
              <img
                src={settings.logoUrl}
                alt={settings.siteTitle}
                className="h-8 sm:h-10 w-auto"
              />
            ) : (
              /* Text Logo */
              <>
                <div className="w-8 h-8 sm:w-10 sm:h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-white font-bold text-lg sm:text-xl">
                    {settings.siteTitle.charAt(0).toUpperCase()}
                  </span>
                </div>
                <span className="text-base sm:text-xl font-bold text-gray-900 dark:text-white whitespace-nowrap">
                  {settings.siteTitle}
                </span>
              </>
            )}
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {headerItems.map((item) => renderNavItem(item))}
          </div>

          {/* Right Side - Auth & Theme Toggle */}
          <div className="flex items-center space-x-4">
            {/* Theme Toggle */}
            <button
              onClick={() => {
                document.documentElement.classList.toggle('dark');
                const isDark = document.documentElement.classList.contains('dark');
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
                // Refresh theme to apply correct background color
                refreshTheme();
                // Dispatch custom event for favicon manager
                window.dispatchEvent(new CustomEvent('themeChanged', { detail: { isDark } }));
              }}
              className="p-2 rounded-lg text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-slate-800 transition"
              aria-label="Toggle theme"
            >
              <svg
                className="w-5 h-5 dark:hidden"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
                />
              </svg>
              <svg
                className="w-5 h-5 hidden dark:block"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
                />
              </svg>
            </button>

            {/* User Menu */}
            {isAuthenticated ? (
              <div className="relative">
                <button
                  onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                  className="flex items-center space-x-2 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-800 transition"
                >
                  <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-full flex items-center justify-center">
                    <span className="text-white text-sm font-semibold">
                      {user?.first_name?.[0]}{user?.last_name?.[0]}
                    </span>
                  </div>
                  <svg
                    className={`w-4 h-4 text-gray-600 dark:text-gray-400 transition-transform ${
                      isUserMenuOpen ? 'rotate-180' : ''
                    }`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </button>

                {/* Dropdown */}
                {isUserMenuOpen && (
                  <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-slate-800 rounded-lg shadow-lg border border-gray-200 dark:border-slate-700 py-2 z-50">
                    <div className="px-4 py-2 border-b border-gray-200 dark:border-slate-700">
                      <p className="text-sm font-semibold text-gray-900 dark:text-white">
                        {user?.first_name} {user?.last_name}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {user?.email}
                      </p>
                    </div>
                    <Link
                      to="/admin"
                      className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 transition"
                      onClick={() => setIsUserMenuOpen(false)}
                    >
                      Admin Dashboard
                    </Link>
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        handleLogout();
                      }}
                      className="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-gray-100 dark:hover:bg-slate-700 transition"
                    >
                      Logout
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <Link
                to="/login"
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 text-white rounded-lg transition font-medium"
              >
                Login
              </Link>
            )}

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden p-2 rounded-lg text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-slate-800 transition"
              aria-label="Toggle menu"
            >
              <svg
                className={`w-6 h-6 ${isMobileMenuOpen ? 'hidden' : 'block'}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
              <svg
                className={`w-6 h-6 ${isMobileMenuOpen ? 'block' : 'hidden'}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="md:hidden border-t border-gray-200 dark:border-slate-800 py-4">
            <div className="flex flex-col space-y-4">
              {headerItems.map((item) => <MobileNavItem key={item.id} item={item} />)}
            </div>
          </div>
        )}
      </nav>
    </header>
  );
};

export default Header;
