// src/pages/HelpPage.tsx
/**
 * Help & Support Page
 * Quick links to key areas, FAQ snippets, and contact info
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  GraduationCap,
  BookOpen,
  ClipboardCheck,
  Keyboard,
  Brain,
  Trophy,
  HelpCircle,
  Mail,
  MessageCircle,
  ChevronRight,
  Rocket,
  Shield,
  Zap,
} from 'lucide-react';

const quickLinks = [
  { icon: GraduationCap, label: 'Courses', desc: 'Browse structured learning paths', path: '/courses', color: 'text-blue-600 dark:text-blue-400' },
  { icon: BookOpen, label: 'Tutorials', desc: 'Step-by-step guides', path: '/tutorials', color: 'text-green-600 dark:text-green-400' },
  { icon: ClipboardCheck, label: 'Quizzes', desc: 'Test your knowledge', path: '/quizzes', color: 'text-purple-600 dark:text-purple-400' },
  { icon: Keyboard, label: 'Typing Practice', desc: 'Improve your typing speed', path: '/typing-practice', color: 'text-orange-600 dark:text-orange-400' },
  { icon: Brain, label: 'Daily Challenges', desc: 'Earn XP and build streaks', path: '/challenges', color: 'text-pink-600 dark:text-pink-400' },
  { icon: Trophy, label: 'Leaderboard', desc: 'See top performers', path: '/leaderboard', color: 'text-amber-600 dark:text-amber-400' },
];

const faqs = [
  {
    q: 'Do I need an account to use the site?',
    a: 'You can browse courses, tutorials, quizzes, and practice typing without an account. Create a free account to save your progress, earn XP, and appear on the leaderboard.',
  },
  {
    q: 'How does the XP system work?',
    a: 'You earn XP by completing tutorials, passing quizzes, finishing courses, and completing daily challenges. Your streak multiplier gives bonus XP for consecutive days of activity.',
  },
  {
    q: 'What are Daily Challenges?',
    a: 'Each day, new challenges are generated for you. Complete them to earn XP with streak bonuses up to 100%. Visit the Challenges page to see today\'s tasks.',
  },
  {
    q: 'Can I track my typing improvement?',
    a: 'Yes! The Typing Practice section tracks your WPM, accuracy, and progress over time. Log in to save your stats and compete on the leaderboard.',
  },
  {
    q: 'How do I earn certificates?',
    a: 'Complete all modules in a course to earn a certificate. You must be logged in, as certificates are tied to your account.',
  },
];

const HelpPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 rounded-full text-sm font-medium mb-4">
            <HelpCircle className="w-4 h-4" />
            Help & Support
          </div>
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">
            How can we help?
          </h1>
          <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
            Find your way around the platform, get answers to common questions, or reach out for support.
          </p>
        </motion.div>

        {/* Getting Started */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gradient-to-br from-blue-600 to-indigo-700 rounded-2xl p-8 mb-8 text-white"
        >
          <div className="flex items-center gap-3 mb-4">
            <Rocket className="w-6 h-6" />
            <h2 className="text-2xl font-bold">Getting Started</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { icon: Zap, title: 'Explore Content', desc: 'Browse courses, tutorials, and quizzes - no account needed.' },
              { icon: Shield, title: 'Create an Account', desc: 'Sign up free to save progress, earn XP, and get certificates.' },
              { icon: Brain, title: 'Build a Streak', desc: 'Complete daily challenges to earn bonus XP multipliers.' },
            ].map((item) => (
              <div key={item.title} className="bg-white/10 backdrop-blur-sm rounded-xl p-4">
                <item.icon className="w-5 h-5 mb-2 text-blue-200" />
                <h3 className="font-semibold mb-1">{item.title}</h3>
                <p className="text-sm text-blue-100">{item.desc}</p>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Quick Links */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mb-8"
        >
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Quick Links</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {quickLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                className="flex items-center gap-3 p-4 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 hover:border-blue-300 dark:hover:border-blue-700 hover:shadow-sm transition-all"
              >
                <link.icon className={`w-5 h-5 flex-shrink-0 ${link.color}`} />
                <div className="min-w-0">
                  <div className="font-medium text-gray-900 dark:text-white text-sm">{link.label}</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{link.desc}</div>
                </div>
              </Link>
            ))}
          </div>
        </motion.div>

        {/* FAQ */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="mb-8"
        >
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Frequently Asked Questions</h2>
          <div className="space-y-3">
            {faqs.map((faq, i) => (
              <details
                key={i}
                className="group bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden"
              >
                <summary className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                  <span className="font-medium text-gray-900 dark:text-white pr-4">{faq.q}</span>
                  <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0 transition-transform group-open:rotate-90" />
                </summary>
                <div className="px-4 pb-4 text-gray-600 dark:text-gray-400 text-sm leading-relaxed">
                  {faq.a}
                </div>
              </details>
            ))}
          </div>
        </motion.div>

        {/* Contact */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-white dark:bg-gray-800 rounded-2xl p-8 border border-gray-200 dark:border-gray-700 text-center"
        >
          <MessageCircle className="w-8 h-8 text-blue-600 dark:text-blue-400 mx-auto mb-3" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">Still need help?</h2>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Can't find what you're looking for? Get in touch.
          </p>
          <Link
            to="/contact"
            className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-xl font-medium hover:bg-blue-700 transition-colors"
          >
            <Mail className="w-4 h-4" />
            Contact Us
          </Link>
        </motion.div>
      </div>
    </div>
  );
};

export default HelpPage;
