// src/components/layout/Footer.tsx
/**
 * TheITApprentice Footer - Compact Mobile-First Design
 * Condensed layout on mobile, expands on desktop
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  GraduationCap,
  BookOpen,
  Keyboard,
  Brain,
  Trophy,
  FileText,
  Users,
  Mail,
  Shield,
  ScrollText,
  Github,
  Twitter,
  Linkedin,
  Youtube,
} from 'lucide-react';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

// Site links (LMS features)
const siteLinks = [
  { label: 'Courses', url: '/courses', icon: GraduationCap },
  { label: 'Tutorials', url: '/tutorials', icon: BookOpen },
  { label: 'Typing', url: '/typing-practice', icon: Keyboard },
  { label: 'Quizzes', url: '/quizzes', icon: Brain },
  { label: 'Leaderboard', url: '/leaderboard', icon: Trophy },
  { label: 'Blog', url: '/blog', icon: FileText },
];

// Company links
const companyLinks = [
  { label: 'About', url: '/about', icon: Users },
  { label: 'Contact', url: '/contact', icon: Mail },
  { label: 'Privacy', url: '/privacy', icon: Shield },
  { label: 'Terms', url: '/terms', icon: ScrollText },
];

export const Footer: React.FC = () => {
  const { settings } = useSiteSettings();
  const currentYear = new Date().getFullYear();

  // Social links from settings
  const socialLinks = [
    settings.githubUrl && { label: 'GitHub', url: settings.githubUrl, icon: Github },
    settings.twitterHandle && { label: 'Twitter', url: `https://twitter.com/${settings.twitterHandle.replace('@', '')}`, icon: Twitter },
    settings.linkedinUrl && { label: 'LinkedIn', url: settings.linkedinUrl, icon: Linkedin },
    settings.youtubeUrl && { label: 'YouTube', url: settings.youtubeUrl, icon: Youtube },
  ].filter(Boolean) as { label: string; url: string; icon: typeof Github }[];

  return (
    <footer className="bg-gray-100 dark:bg-slate-900 text-slate-600 dark:text-slate-300 pt-6 sm:pt-10 pb-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

        {/* ==================== */}
        {/* TIER 1: Brand Block */}
        {/* ==================== */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4 }}
          className="text-center mb-6 sm:mb-8"
        >
          {/* Logo - smaller on mobile */}
          <Link to="/" className="inline-flex items-center justify-center gap-2 sm:gap-3 mb-2 sm:mb-3">
            {settings.logoUrl ? (
              <img
                src={settings.logoUrl}
                alt={settings.siteTitle}
                className="h-8 sm:h-12 w-auto"
              />
            ) : (
              <>
                <div className="w-8 h-8 sm:w-12 sm:h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-lg sm:rounded-xl flex items-center justify-center">
                  <GraduationCap className="w-5 h-5 sm:w-7 sm:h-7 text-white" />
                </div>
                <span className="text-lg sm:text-2xl font-bold text-slate-900 dark:text-white">
                  {settings.siteTitle || 'TheITApprentice'}
                </span>
              </>
            )}
          </Link>

          {/* Tagline - hidden on very small screens */}
          <p className="text-slate-500 dark:text-slate-400 text-xs sm:text-base max-w-md mx-auto leading-relaxed hidden xs:block">
            {settings.siteTagline || 'A modern, SEO-optimized blog platform'}
          </p>
        </motion.div>

        {/* Divider */}
        <div className="h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-slate-700 to-transparent mb-5 sm:mb-8" />

        {/* ========================================= */}
        {/* TIER 2: Links Grid - Compact on Mobile  */}
        {/* ========================================= */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="mb-5 sm:mb-8"
        >
          {/* Mobile: 2-column grid with proper touch targets */}
          <div className="sm:hidden">
            <div className="grid grid-cols-2 gap-x-2">
              {/* Left column: Explore */}
              <div>
                <h4 className="text-slate-900 dark:text-white font-semibold text-xs uppercase tracking-wider mb-1 px-2">
                  Explore
                </h4>
                <div className="flex flex-col">
                  {siteLinks.map((link) => (
                    <Link
                      key={link.url}
                      to={link.url}
                      className="flex items-center gap-2 text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-white active:bg-slate-200 dark:active:bg-slate-800 text-sm py-2.5 px-2 rounded-lg transition-colors"
                    >
                      <link.icon className="w-4 h-4 text-slate-400 dark:text-slate-500" />
                      <span>{link.label}</span>
                    </Link>
                  ))}
                </div>
              </div>

              {/* Right column: Company + Social */}
              <div>
                <h4 className="text-slate-900 dark:text-white font-semibold text-xs uppercase tracking-wider mb-1 px-2">
                  Company
                </h4>
                <div className="flex flex-col">
                  {companyLinks.map((link) => (
                    <Link
                      key={link.url}
                      to={link.url}
                      className="flex items-center gap-2 text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-white active:bg-slate-200 dark:active:bg-slate-800 text-sm py-2.5 px-2 rounded-lg transition-colors"
                    >
                      <link.icon className="w-4 h-4 text-slate-400 dark:text-slate-500" />
                      <span>{link.label}</span>
                    </Link>
                  ))}
                </div>

                {/* Social icons - larger touch targets */}
                <div className="flex items-center gap-1 mt-2 px-1">
                  {socialLinks.length > 0 ? (
                    socialLinks.map((link) => (
                      <a
                        key={link.url}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="w-11 h-11 rounded-lg bg-slate-200 dark:bg-slate-800 active:bg-slate-300 dark:active:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-white transition-all"
                        aria-label={link.label}
                      >
                        <link.icon className="w-5 h-5" />
                      </a>
                    ))
                  ) : (
                    <>
                      <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="w-11 h-11 rounded-lg bg-slate-200 dark:bg-slate-800 active:bg-slate-300 dark:active:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-white transition-all" aria-label="GitHub">
                        <Github className="w-5 h-5" />
                      </a>
                      <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="w-11 h-11 rounded-lg bg-slate-200 dark:bg-slate-800 active:bg-slate-300 dark:active:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-white transition-all" aria-label="Twitter">
                        <Twitter className="w-5 h-5" />
                      </a>
                      <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="w-11 h-11 rounded-lg bg-slate-200 dark:bg-slate-800 active:bg-slate-300 dark:active:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-white transition-all" aria-label="LinkedIn">
                        <Linkedin className="w-5 h-5" />
                      </a>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Desktop: 3-column grid */}
          <div className="hidden sm:grid sm:grid-cols-3 gap-8">
            {/* Column 1: Site Links */}
            <div>
              <h4 className="text-slate-900 dark:text-white font-semibold text-sm uppercase tracking-wider mb-4">
                Explore
              </h4>
              <ul className="space-y-2.5">
                {siteLinks.map((link) => (
                  <li key={link.url}>
                    <Link
                      to={link.url}
                      className="group inline-flex items-center gap-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors duration-200"
                    >
                      <link.icon className="w-4 h-4 text-slate-400 dark:text-slate-500 group-hover:text-blue-500 dark:group-hover:text-blue-400 transition-colors" />
                      <span className="text-sm">{link.label}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 2: Company Links */}
            <div>
              <h4 className="text-slate-900 dark:text-white font-semibold text-sm uppercase tracking-wider mb-4">
                Company
              </h4>
              <ul className="space-y-2.5">
                {companyLinks.map((link) => (
                  <li key={link.url}>
                    <Link
                      to={link.url}
                      className="group inline-flex items-center gap-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors duration-200"
                    >
                      <link.icon className="w-4 h-4 text-slate-400 dark:text-slate-500 group-hover:text-blue-500 dark:group-hover:text-blue-400 transition-colors" />
                      <span className="text-sm">{link.label}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 3: Socials */}
            <div>
              <h4 className="text-slate-900 dark:text-white font-semibold text-sm uppercase tracking-wider mb-4">
                Connect
              </h4>
              <div className="flex flex-wrap gap-2">
                {socialLinks.length > 0 ? (
                  socialLinks.map((link) => (
                    <a
                      key={link.url}
                      href={link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="w-10 h-10 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all duration-200"
                      aria-label={link.label}
                    >
                      <link.icon className="w-5 h-5" />
                    </a>
                  ))
                ) : (
                  <>
                    <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="w-10 h-10 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all duration-200" aria-label="GitHub">
                      <Github className="w-5 h-5" />
                    </a>
                    <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="w-10 h-10 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all duration-200" aria-label="Twitter">
                      <Twitter className="w-5 h-5" />
                    </a>
                    <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="w-10 h-10 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all duration-200" aria-label="LinkedIn">
                      <Linkedin className="w-5 h-5" />
                    </a>
                  </>
                )}
              </div>
            </div>
          </div>
        </motion.div>

        {/* Divider */}
        <div className="h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-slate-700 to-transparent mb-4 sm:mb-6" />

        {/* ============================= */}
        {/* TIER 3: Copyright / Version  */}
        {/* ============================= */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.2 }}
          className="flex flex-col sm:flex-row items-center justify-between gap-2 sm:gap-4 text-xs sm:text-sm"
        >
          {/* Copyright */}
          <div className="text-slate-400 dark:text-slate-500 text-center sm:text-left">
            <span>© {currentYear} {settings.siteTitle || 'TheITApprentice'}</span>
            <span className="hidden sm:inline">. All rights reserved.</span>
          </div>

          {/* Version / Links */}
          <div className="flex items-center gap-3 sm:gap-6 text-slate-400 dark:text-slate-500">
            <Link to="/privacy" className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors">
              Privacy
            </Link>
            <Link to="/terms" className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors">
              Terms
            </Link>
            <a href="/sitemap.xml" target="_blank" rel="noopener noreferrer" className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors">
              Sitemap
            </a>
            <span className="text-slate-300 dark:text-slate-600">v2.0</span>
          </div>
        </motion.div>

        {/* Powered By (optional) */}
        {settings.showPoweredBy && (
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.4, delay: 0.3 }}
            className="text-center mt-3 sm:mt-4"
          >
            <p className="text-[10px] sm:text-xs text-slate-400 dark:text-slate-600">
              Powered by{' '}
              <a
                href="https://github.com/andynaisbitt/TheITapprentice-LMS"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-blue-400 transition-colors"
              >
                The IT Apprentice LMS
              </a>
            </p>
          </motion.div>
        )}
      </div>
    </footer>
  );
};

export default Footer;
