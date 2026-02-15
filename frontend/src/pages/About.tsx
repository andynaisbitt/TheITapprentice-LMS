// src/pages/About.tsx
import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  BookOpen,
  Keyboard,
  Trophy,
  Target,
  Flame,
  Shield,
  Zap,
  Monitor,
  Code,
  Gamepad2,
  Moon,
  GraduationCap,
  ArrowRight,
  ChevronRight,
} from 'lucide-react';

const features = [
  {
    icon: BookOpen,
    title: 'Blog & Content Management',
    desc: 'Dynamic pages with a rich block editor, media management, and SEO-optimised publishing.',
    color: 'from-blue-500 to-blue-600',
  },
  {
    icon: GraduationCap,
    title: 'Courses & Tutorials',
    desc: 'Structured learning paths with step-by-step tutorials, progress tracking, and completion certificates.',
    color: 'from-green-500 to-emerald-600',
  },
  {
    icon: Keyboard,
    title: 'Typing Practice',
    desc: '4 game modes: Quick Challenge, Infinite Rush, Ghost Mode, and Word Lists. Real-time WPM and accuracy tracking.',
    color: 'from-purple-500 to-indigo-600',
  },
  {
    icon: Zap,
    title: 'Skills System',
    desc: '13 IT skills with OSRS-style progression from level 1 to 99. Earn XP through courses, typing, and challenges.',
    color: 'from-yellow-500 to-amber-600',
  },
  {
    icon: Flame,
    title: 'Daily Challenges',
    desc: 'Streaks, XP rewards, milestone badges, and streak freezes to keep your momentum going.',
    color: 'from-orange-500 to-red-600',
  },
  {
    icon: Target,
    title: 'Quizzes & Assessments',
    desc: 'Test your knowledge with scored quizzes across multiple IT topics and skill areas.',
    color: 'from-cyan-500 to-teal-600',
  },
  {
    icon: Trophy,
    title: 'Achievements & Gamification',
    desc: 'Unlock badges, climb leaderboards, and earn XP across everything you do on the platform.',
    color: 'from-amber-500 to-orange-600',
  },
  {
    icon: Moon,
    title: 'Dark Mode & Responsive',
    desc: 'Beautiful light and dark themes with a fully responsive design that works on every device.',
    color: 'from-slate-500 to-gray-600',
  },
  {
    icon: Shield,
    title: 'Anti-Cheat System',
    desc: 'Fair play enforcement with keystroke validation, timing analysis, and anomaly detection in typing games.',
    color: 'from-red-500 to-rose-600',
  },
];

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
            className="inline-flex items-center gap-2 mb-6"
          >
            <span className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white text-sm font-semibold rounded-full shadow-lg">
              Open Source
            </span>
            <span className="px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 text-white text-sm font-semibold rounded-full shadow-lg">
              Gamified Learning
            </span>
            <span className="px-4 py-2 bg-gradient-to-r from-pink-600 to-orange-500 text-white text-sm font-semibold rounded-full shadow-lg">
              Skills Progression
            </span>
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="text-5xl md:text-7xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 mb-6"
          >
            TheITApprentice
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5, duration: 0.6 }}
            className="text-xl md:text-2xl text-gray-700 dark:text-gray-300 font-light max-w-3xl mx-auto"
          >
            Your IT Learning Management System
          </motion.p>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.6 }}
            className="text-lg text-gray-500 dark:text-gray-400 mt-3 max-w-2xl mx-auto"
          >
            Learn IT skills through courses, tutorials, typing games, and daily challenges
          </motion.p>
        </motion.div>

        {/* Main Content */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden">
          <div className="p-8 md:p-12">
            {/* Platform Overview */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="mb-12"
            >
              <h2 className="text-3xl font-black text-gray-900 dark:text-white mb-6 flex items-center gap-3">
                <span className="text-4xl">
                  <Monitor className="w-9 h-9 text-blue-500 inline" />
                </span>
                What is TheITApprentice?
              </h2>
              <p className="text-xl text-gray-700 dark:text-gray-300 leading-relaxed mb-4">
                TheITApprentice is a{' '}
                <span className="font-bold text-blue-600 dark:text-blue-400">gamified IT learning platform</span>{' '}
                that combines structured courses, hands-on typing practice, daily challenges, and an OSRS-inspired skills system to make learning IT genuinely engaging.
              </p>
              <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed">
                What started as a simple blog CMS evolved into a full learning management system with 13 trackable skills, 4 typing game modes, achievement badges, leaderboards, and a streak system that keeps learners coming back every day.
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
                <Gamepad2 className="w-9 h-9 text-purple-500" />
                Platform Features
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {features.map((feature, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: idx * 0.08, duration: 0.5 }}
                    whileHover={{ scale: 1.03, transition: { duration: 0.2 } }}
                    className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-700 dark:to-gray-800 p-6 rounded-xl border-2 border-transparent hover:border-blue-500 dark:hover:border-blue-400 transition-all cursor-default"
                  >
                    <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.color} flex items-center justify-center mb-4`}>
                      <feature.icon className="w-6 h-6 text-white" />
                    </div>
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
                <Code className="w-9 h-9 text-green-500" />
                The Stack
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 p-8 rounded-xl border-2 border-blue-200 dark:border-blue-700"
                >
                  <h3 className="text-2xl font-bold text-blue-900 dark:text-blue-300 mb-6 flex items-center gap-3">
                    <span className="text-3xl">&#9883;</span>
                    Frontend
                  </h3>
                  <div className="space-y-3">
                    {[
                      { label: 'React 18', detail: '+ TypeScript', color: 'bg-blue-500' },
                      { label: 'Vite', detail: 'for dev & builds', color: 'bg-purple-500' },
                      { label: 'Tailwind CSS', detail: 'utility-first styling', color: 'bg-cyan-500' },
                      { label: 'Framer Motion', detail: 'animations & transitions', color: 'bg-pink-500' },
                      { label: 'React Router', detail: 'SPA navigation', color: 'bg-orange-500' },
                    ].map((item, i) => (
                      <div key={i} className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                        <span className={`w-2 h-2 ${item.color} rounded-full`}></span>
                        <span className="font-semibold">{item.label}</span> {item.detail}
                      </div>
                    ))}
                  </div>
                </motion.div>

                <motion.div
                  whileHover={{ scale: 1.02 }}
                  className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 p-8 rounded-xl border-2 border-green-200 dark:border-green-700"
                >
                  <h3 className="text-2xl font-bold text-green-900 dark:text-green-300 mb-6 flex items-center gap-3">
                    <span className="text-3xl">&#128013;</span>
                    Backend
                  </h3>
                  <div className="space-y-3">
                    {[
                      { label: 'FastAPI', detail: 'Python web framework', color: 'bg-green-500' },
                      { label: 'PostgreSQL', detail: 'relational database', color: 'bg-blue-500' },
                      { label: 'SQLAlchemy', detail: 'ORM & migrations', color: 'bg-orange-500' },
                      { label: 'JWT Auth', detail: 'secure authentication', color: 'bg-red-500' },
                      { label: 'Plugin Architecture', detail: 'modular feature system', color: 'bg-purple-500' },
                    ].map((item, i) => (
                      <div key={i} className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                        <span className={`w-2 h-2 ${item.color} rounded-full`}></span>
                        <span className="font-semibold">{item.label}</span> {item.detail}
                      </div>
                    ))}
                  </div>
                </motion.div>
              </div>
            </motion.div>

            {/* The Journey */}
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="mb-16"
            >
              <h2 className="text-3xl font-black text-gray-900 dark:text-white mb-8 flex items-center gap-3">
                <ArrowRight className="w-9 h-9 text-orange-500" />
                The Journey
              </h2>
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/40 rounded-full flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold">1</div>
                    <div className="w-0.5 flex-1 bg-gray-200 dark:bg-gray-700 mt-2" />
                  </div>
                  <div className="pb-8">
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">FastReactCMS</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Started as a modern blog platform built with React and FastAPI. Clean, fast, developer-friendly content management with dynamic pages and media handling.
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/40 rounded-full flex items-center justify-center text-purple-600 dark:text-purple-400 font-bold">2</div>
                    <div className="w-0.5 flex-1 bg-gray-200 dark:bg-gray-700 mt-2" />
                  </div>
                  <div className="pb-8">
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Adding Learning Features</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Tutorials, courses, and a typing practice game turned the CMS into an interactive learning tool. The skills system brought OSRS-style progression to track growth across 13 IT disciplines.
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-pink-500 rounded-full flex items-center justify-center text-white font-bold">3</div>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">TheITApprentice</h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Daily challenges, achievements, leaderboards, anti-cheat, and 4 typing game modes completed the transformation into a full gamified IT learning management system.
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
              <h2 className="text-3xl md:text-4xl font-black mb-4">Start Learning Today</h2>
              <p className="text-xl mb-8 text-blue-100">
                Courses, typing games, daily challenges, and 13 skills to master.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link
                  to="/courses"
                  className="inline-flex items-center justify-center gap-2 bg-white text-blue-600 font-bold px-8 py-4 rounded-xl hover:bg-gray-100 transition-colors shadow-lg"
                >
                  Explore Courses
                  <ChevronRight className="w-5 h-5" />
                </Link>
                <Link
                  to="/typing-practice"
                  className="inline-flex items-center justify-center gap-2 bg-transparent border-2 border-white text-white font-bold px-8 py-4 rounded-xl hover:bg-white hover:text-blue-600 transition-colors"
                >
                  <Keyboard className="w-5 h-5" />
                  Try Typing Practice
                </Link>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;
