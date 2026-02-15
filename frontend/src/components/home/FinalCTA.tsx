// src/components/home/FinalCTA.tsx
/**
 * Final CTA - Clear next action section at bottom of homepage
 * Replaces the weak "More to Explore" filler
 */

import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Rocket,
  BookOpen,
  Brain,
  Keyboard,
  ArrowRight,
  Sparkles,
} from 'lucide-react';

const primaryActions = [
  {
    icon: Rocket,
    label: 'Browse Courses',
    description: 'Start learning IT basics',
    link: '/courses',
    gradient: 'from-blue-500 to-indigo-600',
  },
  {
    icon: BookOpen,
    label: 'View Tutorials',
    description: 'Step-by-step guides',
    link: '/tutorials',
    gradient: 'from-emerald-500 to-teal-600',
  },
  {
    icon: Brain,
    label: 'Take a Quiz',
    description: 'Test your knowledge',
    link: '/quizzes',
    gradient: 'from-purple-500 to-pink-600',
  },
  {
    icon: Keyboard,
    label: 'Practice Typing',
    description: 'Improve your speed',
    link: '/typing-practice',
    gradient: 'from-amber-500 to-orange-600',
  },
];

const FinalCTA: React.FC = () => {
  return (
    <section className="relative pt-20 sm:pt-24 pb-16 sm:pb-20 overflow-hidden bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-slate-900 dark:via-blue-900 dark:to-indigo-900">
      {/* Wave top - matches page bg transitioning to this section */}
      <div className="absolute top-0 left-0 right-0 overflow-hidden z-10">
        <svg
          viewBox="0 0 1440 80"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-12 sm:h-16"
          preserveAspectRatio="none"
        >
          <path
            d="M0 0L48 8C96 16 192 32 288 40C384 48 480 48 576 44C672 40 768 32 864 28C960 24 1056 24 1152 28C1248 32 1344 40 1392 44L1440 48V0H0Z"
            className="fill-gray-50 dark:fill-slate-900"
          />
        </svg>
      </div>

      {/* Decorative elements */}
      <div className="absolute inset-0 opacity-20 dark:opacity-30">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-400 dark:bg-blue-500 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-400 dark:bg-purple-500 rounded-full blur-3xl" />
      </div>

      {/* Grid pattern overlay */}
      <div
        className="absolute inset-0 opacity-[0.03] dark:opacity-5"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23000000' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
        }}
      />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-10 sm:mb-12"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-blue-100 dark:bg-white/10 backdrop-blur-sm rounded-full text-blue-700 dark:text-white/80 text-sm font-medium mb-4">
            <Sparkles className="w-4 h-4 text-yellow-500 dark:text-yellow-400" />
            Ready to get started?
          </div>
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-slate-900 dark:text-white mb-4">
            Start Your IT Journey Today
          </h2>
          <p className="text-lg text-slate-600 dark:text-white/70 max-w-2xl mx-auto">
            Pick a skill to learn, take a quiz, or just explore. Every small step counts.
          </p>
        </motion.div>

        {/* Action Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-10">
          {primaryActions.map((action, index) => (
            <motion.div
              key={action.label}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
            >
              <Link
                to={action.link}
                className="group block h-full p-5 sm:p-6 rounded-2xl bg-white/80 dark:bg-white/10 backdrop-blur-sm border border-slate-200 dark:border-white/10 hover:bg-white dark:hover:bg-white/20 hover:border-blue-300 dark:hover:border-white/20 hover:shadow-lg dark:hover:shadow-none transition-all duration-300"
              >
                <div className={`inline-flex p-3 rounded-xl bg-gradient-to-br ${action.gradient} mb-4`}>
                  <action.icon className="w-6 h-6 text-white" />
                </div>
                <h3 className="font-semibold text-slate-900 dark:text-white mb-1 group-hover:text-blue-600 dark:group-hover:text-blue-300 transition-colors">
                  {action.label}
                </h3>
                <p className="text-sm text-slate-500 dark:text-white/60">
                  {action.description}
                </p>
              </Link>
            </motion.div>
          ))}
        </div>

        {/* Secondary CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.4 }}
          className="text-center"
        >
          <p className="text-slate-500 dark:text-white/60 mb-4">
            Already learning?
          </p>
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 px-6 py-3 bg-slate-900 dark:bg-white text-white dark:text-slate-900 rounded-xl font-semibold hover:bg-slate-800 dark:hover:bg-blue-50 transition-colors"
          >
            Continue Where You Left Off
            <ArrowRight className="w-5 h-5" />
          </Link>
        </motion.div>
      </div>
    </section>
  );
};

export default FinalCTA;
