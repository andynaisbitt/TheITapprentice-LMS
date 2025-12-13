// src/components/home/HeroSection.tsx
/**
 * Hero Section - Homepage header with gradient and CTA
 */

import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { ArrowRight, BookOpen, Sparkles } from 'lucide-react';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

export const HeroSection: React.FC = () => {
  const { settings } = useSiteSettings();
  return (
    <section className="relative overflow-hidden bg-gradient-to-br from-blue-600 via-indigo-600 to-purple-700 dark:from-blue-900 dark:via-indigo-900 dark:to-purple-900">
      {/* Animated background pattern */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-0 left-0 w-full h-full bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmZmZmYiIGZpbGwtb3BhY2l0eT0iMC4xIj48cGF0aCBkPSJNMzYgMzRjMC0yLjIxIDEuNzktNCAzLjk5LTRTNDQgMzEuNzkgNDQgMzRzLTEuNzkgNC00IDQtNC0xLjc5LTQtNHptLTggMGMwLTIuMjEgMS43OS00IDQtNHM0IDEuNzkgNCA0LTEuNzkgNC00IDQtNC0xLjc5LTQtNHptLTE2IDBjMC0yLjIxIDEuNzktNCA0LTRzNCAxLjc5IDQgNC0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTAgMTZjMC0yLjIxIDEuNzktNCA0LTRzNCAxLjc5IDQgNC0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTAgMTZjMC0yLjIxIDEuNzktNCA0LTRzNCAxLjc5IDQgNC0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTE2IDBjMC0yLjIxIDEuNzktNCA0LTRzNCAxLjc5IDQgNC0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTggMGMwLTIuMjEgMS43OS00IDQuMDEtNFM0NCA1Ni43OSA0NCA1OXMtMS43OSA0LTQgNC00LTEuNzktNC00em0wLTE2YzAtMi4yMSAxLjc5LTQgNC4wMS00UzQ0IDQwLjc5IDQ0IDQzcy0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTAtMTZjMC0yLjIxIDEuNzktNCA0LTRzNCAxLjc5IDQgNC0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTAgMTZjMC0yLjIxIDEuNzktNCA0LTRzNCAxLjc5IDQgNC0xLjc5IDQtNCA0LTQtMS43OS00LTR6bTE2IDBjMC0yLjIxIDEuNzktNCA0LjAxLTRTNDQgNDAuNzkgNDQgNDNzLTEuNzkgNC00IDQtNC0xLjc5LTQtNHoiLz48L2c+PC9nPjwvc3ZnPg==')]"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
        <div className="text-center">
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-white/10 backdrop-blur-sm rounded-full text-white text-sm font-medium mb-6"
          >
            <Sparkles size={16} />
            <span>{settings.heroBadgeText}</span>
          </motion.div>

          {/* Heading */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white mb-6 leading-tight"
          >
            {settings.heroTitle}
          </motion.h1>

          {/* Subtitle */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg sm:text-xl text-blue-100 dark:text-blue-200 mb-10 max-w-2xl mx-auto"
          >
            {settings.heroSubtitle}
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link
              to="/blog"
              className="group inline-flex items-center gap-2 px-8 py-4 bg-white text-blue-600 rounded-lg font-semibold text-lg hover:bg-blue-50 transition-all shadow-lg hover:shadow-xl hover:scale-105 transform"
            >
              <BookOpen size={24} />
              <span>{settings.heroCTAPrimary}</span>
              <ArrowRight
                size={20}
                className="group-hover:translate-x-1 transition-transform"
              />
            </Link>

            <Link
              to="/about"
              className="inline-flex items-center gap-2 px-8 py-4 bg-white/10 backdrop-blur-sm text-white border-2 border-white/30 rounded-lg font-semibold text-lg hover:bg-white/20 transition-all"
            >
              {settings.heroCTASecondary}
            </Link>
          </motion.div>

          {/* Stats - Only show if at least one stat is set */}
          {(() => {
            const statsCount = [settings.statsArticles, settings.statsReaders, settings.statsFree].filter(Boolean).length;
            if (statsCount === 0) return null;

            return (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5, delay: 0.5 }}
                className={`mt-16 grid gap-8 max-w-2xl mx-auto ${
                  statsCount === 1 ? 'grid-cols-1' : statsCount === 2 ? 'grid-cols-2' : 'grid-cols-3'
                }`}
              >
                {settings.statsArticles && (
                  <div className="text-center">
                    <div className="text-3xl sm:text-4xl font-bold text-white mb-1">
                      {settings.statsArticles}
                    </div>
                    <div className="text-sm text-blue-200">Articles</div>
                  </div>
                )}
                {settings.statsReaders && (
                  <div className="text-center">
                    <div className="text-3xl sm:text-4xl font-bold text-white mb-1">
                      {settings.statsReaders}
                    </div>
                    <div className="text-sm text-blue-200">Readers</div>
                  </div>
                )}
                {settings.statsFree && (
                  <div className="text-center">
                    <div className="text-3xl sm:text-4xl font-bold text-white mb-1">
                      {settings.statsFree}
                    </div>
                    <div className="text-sm text-blue-200">Free</div>
                  </div>
                )}
              </motion.div>
            );
          })()}
        </div>
      </div>

      {/* Wave divider */}
      <div className="absolute bottom-0 left-0 right-0">
        <svg
          viewBox="0 0 1440 120"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-12 sm:h-16"
        >
          <path
            d="M0 120L60 105C120 90 240 60 360 45C480 30 600 30 720 37.5C840 45 960 60 1080 67.5C1200 75 1320 75 1380 75L1440 75V120H1380C1320 120 1200 120 1080 120C960 120 840 120 720 120C600 120 480 120 360 120C240 120 120 120 60 120H0Z"
            fill="currentColor"
            className="text-gray-50 dark:text-slate-900"
          />
        </svg>
      </div>
    </section>
  );
};

export default HeroSection;
