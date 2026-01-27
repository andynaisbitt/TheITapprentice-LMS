// src/components/layout/Footer.tsx
/**
 * TheITApprentice Footer - Modern 3-Tier Design
 * Mobile-first, Framer Motion animations, consistent branding
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
  ExternalLink,
} from 'lucide-react';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

// Animation variants
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.1,
    },
  },
};

const columnVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.5,
      ease: [0.25, 0.46, 0.45, 0.94],
    },
  },
};

const linkHoverVariants = {
  rest: { x: 0 },
  hover: { x: 4 },
};

// Site links (LMS features)
const siteLinks = [
  { label: 'Courses', url: '/courses', icon: GraduationCap },
  { label: 'Tutorials', url: '/tutorials', icon: BookOpen },
  { label: 'Typing Games', url: '/games/typing', icon: Keyboard },
  { label: 'Quizzes', url: '/quizzes', icon: Brain },
  { label: 'Leaderboard', url: '/leaderboard', icon: Trophy },
  { label: 'Blog', url: '/blog', icon: FileText },
];

// Company links
const companyLinks = [
  { label: 'About', url: '/about', icon: Users },
  { label: 'Contact', url: '/contact', icon: Mail },
  { label: 'Privacy Policy', url: '/privacy', icon: Shield },
  { label: 'Terms of Service', url: '/terms', icon: ScrollText },
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
    <footer className="bg-slate-900 dark:bg-slate-950 text-slate-300 pt-10 pb-20">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 space-y-10">

        {/* ==================== */}
        {/* TIER 1: Brand Block */}
        {/* ==================== */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center"
        >
          {/* Logo */}
          <Link to="/" className="inline-flex items-center justify-center gap-3 mb-4">
            {settings.logoUrl ? (
              <img
                src={settings.logoUrl}
                alt={settings.siteTitle}
                className="h-12 w-auto"
              />
            ) : (
              <>
                <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center">
                  <GraduationCap className="w-7 h-7 text-white" />
                </div>
                <span className="text-2xl font-bold text-white">
                  {settings.siteTitle || 'TheITApprentice'}
                </span>
              </>
            )}
          </Link>

          {/* Tagline */}
          <p className="text-slate-400 text-base max-w-md mx-auto leading-relaxed">
            {settings.siteTagline || 'Rebuilding, Reskilling, and Shipping for 2026'}
          </p>
        </motion.div>

        {/* Divider */}
        <div className="h-px bg-gradient-to-r from-transparent via-slate-700 to-transparent" />

        {/* ========================= */}
        {/* TIER 2: 3-Column Grid    */}
        {/* ========================= */}
        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="grid grid-cols-1 sm:grid-cols-3 gap-10 sm:gap-8"
        >
          {/* Column 1: Site Links */}
          <motion.div variants={columnVariants} className="text-center sm:text-left">
            <h4 className="text-white font-semibold text-sm uppercase tracking-wider mb-5">
              Explore
            </h4>
            <ul className="space-y-3">
              {siteLinks.map((link) => (
                <li key={link.url}>
                  <motion.div
                    initial="rest"
                    whileHover="hover"
                    animate="rest"
                  >
                    <Link
                      to={link.url}
                      className="group inline-flex items-center gap-2.5 text-slate-400 hover:text-white transition-colors duration-200"
                    >
                      <link.icon className="w-4 h-4 text-slate-500 group-hover:text-blue-400 transition-colors duration-200" />
                      <motion.span
                        variants={linkHoverVariants}
                        transition={{ duration: 0.2 }}
                        className="text-sm"
                      >
                        {link.label}
                      </motion.span>
                    </Link>
                  </motion.div>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Column 2: Company Links */}
          <motion.div variants={columnVariants} className="text-center sm:text-left">
            <h4 className="text-white font-semibold text-sm uppercase tracking-wider mb-5">
              Company
            </h4>
            <ul className="space-y-3">
              {companyLinks.map((link) => (
                <li key={link.url}>
                  <motion.div
                    initial="rest"
                    whileHover="hover"
                    animate="rest"
                  >
                    <Link
                      to={link.url}
                      className="group inline-flex items-center gap-2.5 text-slate-400 hover:text-white transition-colors duration-200"
                    >
                      <link.icon className="w-4 h-4 text-slate-500 group-hover:text-blue-400 transition-colors duration-200" />
                      <motion.span
                        variants={linkHoverVariants}
                        transition={{ duration: 0.2 }}
                        className="text-sm"
                      >
                        {link.label}
                      </motion.span>
                    </Link>
                  </motion.div>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Column 3: Socials */}
          <motion.div variants={columnVariants} className="text-center sm:text-left">
            <h4 className="text-white font-semibold text-sm uppercase tracking-wider mb-5">
              Connect
            </h4>
            {socialLinks.length > 0 ? (
              <ul className="space-y-3">
                {socialLinks.map((link) => (
                  <li key={link.url}>
                    <motion.div
                      initial="rest"
                      whileHover="hover"
                      animate="rest"
                    >
                      <a
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group inline-flex items-center gap-2.5 text-slate-400 hover:text-white transition-colors duration-200"
                      >
                        <link.icon className="w-4 h-4 text-slate-500 group-hover:text-blue-400 transition-colors duration-200" />
                        <motion.span
                          variants={linkHoverVariants}
                          transition={{ duration: 0.2 }}
                          className="text-sm"
                        >
                          {link.label}
                        </motion.span>
                        <ExternalLink className="w-3 h-3 text-slate-600 group-hover:text-slate-400 transition-colors duration-200" />
                      </a>
                    </motion.div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="flex justify-center sm:justify-start gap-3">
                {/* Placeholder social buttons */}
                <a
                  href="https://github.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center text-slate-400 hover:text-white transition-all duration-200"
                  aria-label="GitHub"
                >
                  <Github className="w-5 h-5" />
                </a>
                <a
                  href="https://twitter.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center text-slate-400 hover:text-white transition-all duration-200"
                  aria-label="Twitter"
                >
                  <Twitter className="w-5 h-5" />
                </a>
                <a
                  href="https://linkedin.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center text-slate-400 hover:text-white transition-all duration-200"
                  aria-label="LinkedIn"
                >
                  <Linkedin className="w-5 h-5" />
                </a>
              </div>
            )}
          </motion.div>
        </motion.div>

        {/* Divider */}
        <div className="h-px bg-gradient-to-r from-transparent via-slate-700 to-transparent" />

        {/* ============================= */}
        {/* TIER 3: Copyright / Version  */}
        {/* ============================= */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="flex flex-col sm:flex-row items-center justify-between gap-4 text-sm"
        >
          {/* Copyright */}
          <div className="text-slate-500 text-center sm:text-left">
            <span>© {currentYear} {settings.siteTitle || 'TheITApprentice'}.</span>
            <span className="hidden sm:inline"> All rights reserved.</span>
          </div>

          {/* Version / Links */}
          <div className="flex items-center gap-4 sm:gap-6 text-slate-500">
            <Link
              to="/privacy"
              className="hover:text-slate-300 transition-colors duration-200"
            >
              Privacy
            </Link>
            <Link
              to="/terms"
              className="hover:text-slate-300 transition-colors duration-200"
            >
              Terms
            </Link>
            <a
              href="/sitemap.xml"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-300 transition-colors duration-200"
            >
              Sitemap
            </a>
            <span className="text-slate-600">v2.0</span>
          </div>
        </motion.div>

        {/* Powered By (optional) */}
        {settings.showPoweredBy && (
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="text-center"
          >
            <p className="text-xs text-slate-600">
              Powered by{' '}
              <a
                href="https://github.com/andynaisbitt/TheITapprentice-LMS"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-blue-400 transition-colors duration-200"
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
