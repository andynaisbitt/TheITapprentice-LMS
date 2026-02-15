// src/components/home/LearningPathsShowcase.tsx
/**
 * Learning Paths Showcase - Simplified view showing 3 curated learning paths
 * Each path is a structured journey through related content
 */

import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Monitor,
  Keyboard,
  Mail,
  Shield,
  ArrowRight,
  Zap,
} from 'lucide-react';
import Section from './Section';

interface LearningPath {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  color: string;
  gradient: string;
  modules: number;
  xpReward: number;
  link: string;
  skills: string[];
}

const learningPaths: LearningPath[] = [
  {
    id: 'pc-basics',
    title: 'PC Basics',
    description: 'Learn to use a computer from scratch - mouse, keyboard, files, and folders',
    icon: Monitor,
    color: 'blue',
    gradient: 'from-blue-500 to-indigo-600',
    modules: 8,
    xpReward: 500,
    link: '/courses?category=pc-basics',
    skills: ['Mouse & Keyboard', 'Files & Folders', 'Desktop Navigation'],
  },
  {
    id: 'typing',
    title: 'Learn to Type',
    description: 'Build typing speed and accuracy with fun practice games',
    icon: Keyboard,
    color: 'amber',
    gradient: 'from-amber-500 to-orange-600',
    modules: 5,
    xpReward: 300,
    link: '/typing-practice',
    skills: ['Touch Typing', 'Speed Building', 'Accuracy'],
  },
  {
    id: 'email-internet',
    title: 'Email & Internet',
    description: 'Set up email, browse safely, and connect to WiFi',
    icon: Mail,
    color: 'emerald',
    gradient: 'from-emerald-500 to-teal-600',
    modules: 6,
    xpReward: 400,
    link: '/tutorials?category=email',
    skills: ['Email Setup', 'Web Browsing', 'WiFi Connection'],
  },
];

const LearningPathsShowcase: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Section
      eyebrow="Learning Paths"
      title="Pick a Path"
      subtitle="Structured journeys to build your IT skills step by step"
      background="muted"
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {learningPaths.map((path, index) => (
          <motion.div
            key={path.id}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: index * 0.1 }}
            whileHover={{ y: -8 }}
            onClick={() => navigate(path.link)}
            className="cursor-pointer group"
          >
            <div className="relative bg-white dark:bg-slate-800 rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-700 hover:border-transparent hover:shadow-xl transition-all h-full">
              {/* Colored top bar */}
              <div className={`h-2 bg-gradient-to-r ${path.gradient}`} />

              <div className="p-6">
                {/* Icon and Title */}
                <div className="flex items-start gap-4 mb-4">
                  <div className={`p-3 rounded-xl bg-gradient-to-br ${path.gradient} shadow-lg`}>
                    <path.icon className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="font-bold text-lg text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                      {path.title}
                    </h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                      {path.modules} modules
                    </p>
                  </div>
                </div>

                {/* Description */}
                <p className="text-slate-600 dark:text-slate-400 text-sm mb-4">
                  {path.description}
                </p>

                {/* Skills tags */}
                <div className="flex flex-wrap gap-2 mb-4">
                  {path.skills.map((skill) => (
                    <span
                      key={skill}
                      className="px-2 py-1 text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 rounded-md"
                    >
                      {skill}
                    </span>
                  ))}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-700">
                  <div className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400 font-semibold text-sm">
                    <Zap className="w-4 h-4" />
                    +{path.xpReward} XP
                  </div>
                  <span className="flex items-center gap-1 text-blue-600 dark:text-blue-400 text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity">
                    Start path
                    <ArrowRight className="w-4 h-4" />
                  </span>
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </Section>
  );
};

export default LearningPathsShowcase;
