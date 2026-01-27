// src/components/layout/MobileNav/sections/AccountSection.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  User,
  Settings,
  LogOut,
  Shield,
  FileText,
  ChevronRight,
  Crown,
} from 'lucide-react';

interface AccountSectionProps {
  user?: {
    first_name?: string;
    last_name?: string;
    email?: string;
    role?: string;
    is_admin?: boolean;
    can_write_blog?: boolean;
  } | null;
  isAuthenticated: boolean;
  onNavigate: (path: string) => void;
  onLogout: () => void;
}

interface MenuItemProps {
  icon: React.ElementType;
  label: string;
  description?: string;
  onClick?: () => void;
  to?: string;
  danger?: boolean;
  badge?: string;
}

const MenuItem: React.FC<MenuItemProps> = ({
  icon: Icon,
  label,
  description,
  onClick,
  to,
  danger,
  badge,
}) => {
  const content = (
    <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors">
      <div className="flex items-center space-x-3">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
          danger
            ? 'bg-red-100 dark:bg-red-900/30'
            : 'bg-white dark:bg-slate-900'
        }`}>
          <Icon className={`w-5 h-5 ${
            danger
              ? 'text-red-600 dark:text-red-400'
              : 'text-slate-600 dark:text-slate-400'
          }`} />
        </div>
        <div>
          <p className={`font-medium ${
            danger
              ? 'text-red-600 dark:text-red-400'
              : 'text-slate-900 dark:text-slate-100'
          }`}>
            {label}
          </p>
          {description && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {description}
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center space-x-2">
        {badge && (
          <span className="text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 px-2 py-0.5 rounded-full font-medium">
            {badge}
          </span>
        )}
        <ChevronRight className="w-4 h-4 text-slate-400" />
      </div>
    </div>
  );

  if (to) {
    return (
      <Link to={to} onClick={onClick}>
        {content}
      </Link>
    );
  }

  return (
    <button onClick={onClick} className="w-full text-left">
      {content}
    </button>
  );
};

export const AccountSection: React.FC<AccountSectionProps> = ({
  user,
  isAuthenticated,
  onNavigate,
  onLogout,
}) => {
  if (!isAuthenticated || !user) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="space-y-6"
      >
        <div className="text-center py-8">
          <div className="w-16 h-16 bg-slate-100 dark:bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <User className="w-8 h-8 text-slate-400" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">
            Sign In Required
          </h3>
          <p className="text-sm text-slate-600 dark:text-slate-400 mb-6">
            Sign in to access your account settings and progress.
          </p>
          <div className="flex flex-col gap-2">
            <button
              onClick={() => onNavigate('/login')}
              className="w-full px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-xl font-semibold hover:from-blue-700 hover:to-indigo-700 transition-all"
            >
              Sign In
            </button>
            <button
              onClick={() => onNavigate('/register')}
              className="w-full px-6 py-3 bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 rounded-xl font-semibold hover:bg-slate-200 dark:hover:bg-slate-700 transition-all"
            >
              Create Account
            </button>
          </div>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-4"
    >
      {/* User Info Card */}
      <div className="p-4 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl text-white">
        <div className="flex items-center space-x-3">
          <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center relative">
            <span className="text-lg font-bold">
              {user.first_name?.[0]}{user.last_name?.[0]}
            </span>
            {user.is_admin && (
              <div className="absolute -top-1 -right-1 w-5 h-5 bg-yellow-500 rounded-full flex items-center justify-center">
                <Crown className="w-3 h-3 text-white" />
              </div>
            )}
          </div>
          <div>
            <h3 className="font-semibold">
              {user.first_name} {user.last_name}
            </h3>
            <p className="text-white/70 text-sm">{user.email}</p>
            <p className="text-white/90 text-xs capitalize mt-0.5">{user.role}</p>
          </div>
        </div>
      </div>

      {/* Menu Items */}
      <div className="space-y-2">
        <MenuItem
          icon={User}
          label="My Profile"
          description="View and edit your profile"
          to="/profile"
          onClick={() => onNavigate('/profile')}
        />

        {user.is_admin && (
          <MenuItem
            icon={Shield}
            label="Admin Dashboard"
            description="Manage your site"
            to="/admin"
            onClick={() => onNavigate('/admin')}
            badge="Admin"
          />
        )}

        {(user.role === 'author' || user.can_write_blog || user.is_admin) && (
          <MenuItem
            icon={FileText}
            label="Write Blog Post"
            description="Create new content"
            to="/admin/blog"
            onClick={() => onNavigate('/admin/blog')}
          />
        )}

        <MenuItem
          icon={Settings}
          label="Settings"
          description="Preferences and account settings"
          to="/settings"
          onClick={() => onNavigate('/settings')}
        />

        <div className="pt-2 border-t border-slate-200 dark:border-slate-700">
          <MenuItem
            icon={LogOut}
            label="Sign Out"
            onClick={onLogout}
            danger
          />
        </div>
      </div>
    </motion.div>
  );
};
