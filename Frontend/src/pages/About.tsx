// src/pages/About.tsx
import React from 'react';
import { motion } from 'framer-motion';

export const About: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-blue-50 to-purple-50 dark:from-gray-900 dark:via-gray-900 dark:to-gray-900 py-12">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Hero Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="inline-block mb-4"
          >
            <span className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white text-sm font-semibold rounded-full shadow-lg">
              Open Source • Developer First • Lightning Fast
            </span>
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="text-6xl md:text-7xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 mb-6"
          >
            FastReactCMS
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5, duration: 0.6 }}
            className="text-2xl md:text-3xl text-gray-700 dark:text-gray-300 font-light max-w-3xl mx-auto"
          >
            The blog platform that doesn't suck
          </motion.p>
        </motion.div>

        {/* Main Content */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden">
          <div className="p-8 md:p-12">
            {/* Intro */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="mb-12"
            >
              <p className="text-xl text-gray-700 dark:text-gray-300 leading-relaxed mb-6">
                Tired of WordPress bloat? Sick of fighting with page builders?
                <span className="font-bold text-blue-600 dark:text-blue-400"> We feel you.</span>
              </p>
              <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed">
                FastReactCMS is a modern, no-BS blog platform built for developers who want to ship fast without sacrificing control.
                React + FastAPI + PostgreSQL. That's it. No plugins, no marketplace chaos, no "premium" paywalls.
              </p>
            </motion.div>

            {/* Feature Grid */}
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="mb-16"
            >
              <h2 className="text-3xl font-black text-gray-900 dark:text-white mb-8 flex items-center gap-3">
                <span className="text-4xl">⚡</span>
                Built Different
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[
                  { icon: '🎨', title: 'Dynamic Pages', desc: 'Modular block system for building custom pages without code' },
                  { icon: '🚀', title: 'Lightning Fast', desc: 'Vite builds, optimized queries, sub-second page loads' },
                  { icon: '🔒', title: 'Actually Secure', desc: 'JWT auth, CSRF protection, HTTP-only cookies by default' },
                  { icon: '📱', title: 'Mobile First', desc: 'Responsive design that works on every device' },
                  { icon: '🌙', title: 'Dark Mode', desc: 'Beautiful dark theme throughout the entire platform' },
                  { icon: '📊', title: 'SEO Ready', desc: 'Meta tags, RSS feeds, sitemaps - all built in' },
                  { icon: '🖼️', title: 'Media Magic', desc: 'Image upload, optimization, and management made easy' },
                  { icon: '⚙️', title: 'Developer DX', desc: 'TypeScript, type safety, clean architecture, easy to extend' },
                  { icon: '🎯', title: 'No Bloat', desc: "Only what you need. Nothing you don't. Period." }
                ].map((feature, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: idx * 0.1, duration: 0.5 }}
                    whileHover={{ scale: 1.05, transition: { duration: 0.2 } }}
                    className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-700 dark:to-gray-800 p-6 rounded-xl border-2 border-transparent hover:border-blue-500 dark:hover:border-blue-400 transition-all cursor-default"
                  >
                    <div className="text-4xl mb-3">{feature.icon}</div>
                    <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-2">{feature.title}</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">{feature.desc}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* Tech Stack */}
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="mb-16"
            >
              <h2 className="text-3xl font-black text-gray-900 dark:text-white mb-8 flex items-center gap-3">
                <span className="text-4xl">🛠️</span>
                The Stack
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 p-8 rounded-xl border-2 border-blue-200 dark:border-blue-700"
                >
                  <h3 className="text-2xl font-bold text-blue-900 dark:text-blue-300 mb-6 flex items-center gap-3">
                    <span className="text-3xl">⚛️</span>
                    Frontend
                  </h3>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                      <span className="font-semibold">React 18</span> + TypeScript
                    </div>
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
                      <span className="font-semibold">Vite</span> for dev & builds
                    </div>
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-cyan-500 rounded-full"></span>
                      <span className="font-semibold">Tailwind CSS</span> for styling
                    </div>
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-pink-500 rounded-full"></span>
                      <span className="font-semibold">Framer Motion</span> for animations
                    </div>
                  </div>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 p-8 rounded-xl border-2 border-green-200 dark:border-green-700"
                >
                  <h3 className="text-2xl font-bold text-green-900 dark:text-green-300 mb-6 flex items-center gap-3">
                    <span className="text-3xl">🐍</span>
                    Backend
                  </h3>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                      <span className="font-semibold">FastAPI</span> Python framework
                    </div>
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                      <span className="font-semibold">PostgreSQL</span> database
                    </div>
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-orange-500 rounded-full"></span>
                      <span className="font-semibold">SQLAlchemy</span> ORM
                    </div>
                    <div className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
                      <span className="font-semibold">Alembic</span> migrations
                    </div>
                  </div>
                </motion.div>
              </div>
            </motion.div>

            {/* Philosophy */}
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="mb-16"
            >
              <h2 className="text-3xl font-black text-gray-900 dark:text-white mb-8 flex items-center gap-3">
                <span className="text-4xl">💭</span>
                Our Philosophy
              </h2>
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="text-3xl">🎯</div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Simplicity Wins</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Clean code beats clever code. Simple beats complex. Every time. We ship features, not complexity.
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="text-3xl">👨‍💻</div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Developers First</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      We build tools we'd actually want to use. Type safety, clear patterns, no magic - just good code that makes sense.
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="text-3xl">⚡</div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Performance Matters</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Every millisecond counts. Optimized queries, efficient rendering, lazy loading - performance isn't optional.
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="text-3xl">🔓</div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Open Always</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Open source, open standards, open data. Your content is yours. No lock-in, no premium upsells, no BS.
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>

            {/* CTA */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl p-8 md:p-12 text-center text-white"
            >
              <h2 className="text-3xl md:text-4xl font-black mb-4">Ready to ship?</h2>
              <p className="text-xl mb-8 text-blue-100">
                Fork it. Clone it. Make it yours. It's open source.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <a
                  href="/contact"
                  className="inline-block bg-white text-blue-600 font-bold px-8 py-4 rounded-xl hover:bg-gray-100 transition-colors shadow-lg"
                >
                  Get In Touch
                </a>
                <a
                  href="/admin"
                  className="inline-block bg-transparent border-2 border-white text-white font-bold px-8 py-4 rounded-xl hover:bg-white hover:text-blue-600 transition-colors"
                >
                  Try the Admin Panel
                </a>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;
