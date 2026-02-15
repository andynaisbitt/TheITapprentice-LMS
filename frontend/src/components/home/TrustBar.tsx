// src/components/home/TrustBar.tsx
/**
 * Trust Bar - Credibility strip showing platform stats
 * Displays key metrics to build instant trust
 */

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { GraduationCap, BookOpen, Brain, Users, Keyboard, Trophy } from 'lucide-react';
import { progressApi } from '../../plugins/shared/services/progressApi';

interface Stat {
  icon: React.ReactNode;
  value: number;
  label: string;
  suffix?: string;
}

const TrustBar: React.FC = () => {
  const [stats, setStats] = useState<Stat[]>([
    { icon: <GraduationCap className="w-5 h-5" />, value: 0, label: 'Courses', suffix: '+' },
    { icon: <BookOpen className="w-5 h-5" />, value: 0, label: 'Tutorials', suffix: '+' },
    { icon: <Brain className="w-5 h-5" />, value: 0, label: 'Quizzes', suffix: '+' },
    { icon: <Users className="w-5 h-5" />, value: 0, label: 'Learners', suffix: '+' },
  ]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await progressApi.getHomepageStats();
        if (data) {
          // Use actual API data where available, fallbacks for content counts
          setStats([
            { icon: <GraduationCap className="w-5 h-5" />, value: data.courses_completed || 25, label: 'Courses', suffix: '+' },
            { icon: <BookOpen className="w-5 h-5" />, value: data.tutorials_completed || 100, label: 'Tutorials', suffix: '+' },
            { icon: <Brain className="w-5 h-5" />, value: data.quizzes_completed || 50, label: 'Quizzes', suffix: '+' },
            { icon: <Users className="w-5 h-5" />, value: data.total_learners || 500, label: 'Learners', suffix: '+' },
          ]);
        }
      } catch {
        // Use fallback values
        setStats([
          { icon: <GraduationCap className="w-5 h-5" />, value: 25, label: 'Courses', suffix: '+' },
          { icon: <BookOpen className="w-5 h-5" />, value: 100, label: 'Tutorials', suffix: '+' },
          { icon: <Brain className="w-5 h-5" />, value: 50, label: 'Quizzes', suffix: '+' },
          { icon: <Users className="w-5 h-5" />, value: 500, label: 'Learners', suffix: '+' },
        ]);
      } finally {
        setLoaded(true);
      }
    };
    fetchStats();
  }, []);

  // Animated counter component
  const AnimatedNumber = ({ value, suffix }: { value: number; suffix?: string }) => {
    const [displayValue, setDisplayValue] = useState(0);

    useEffect(() => {
      if (!loaded) return;
      let start = 0;
      const duration = 1500;
      const increment = value / (duration / 16);
      const timer = setInterval(() => {
        start += increment;
        if (start >= value) {
          setDisplayValue(value);
          clearInterval(timer);
        } else {
          setDisplayValue(Math.floor(start));
        }
      }, 16);
      return () => clearInterval(timer);
    }, [value, loaded]);

    return (
      <span>
        {displayValue.toLocaleString()}{suffix}
      </span>
    );
  };

  return (
    <section className="relative bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950 border-y border-slate-700/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-5">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 sm:gap-8">
          {stats.map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: loaded ? 1 : 0, y: loaded ? 0 : 20 }}
              transition={{ duration: 0.4, delay: index * 0.1 }}
              className="flex items-center justify-center gap-3 text-white"
            >
              <div className="p-2 rounded-lg bg-white/10 text-blue-400">
                {stat.icon}
              </div>
              <div>
                <div className="text-xl sm:text-2xl font-bold">
                  <AnimatedNumber value={stat.value} suffix={stat.suffix} />
                </div>
                <div className="text-xs sm:text-sm text-slate-400">{stat.label}</div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default TrustBar;
