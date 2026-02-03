// src/components/home/TypingChallengeCTA.tsx
/**
 * Typing Challenge CTA - Homepage component promoting the typing game
 * Features animated keyboard visual and quick access to typing modes
 * Mobile-first design with staggered animations
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  Keyboard,
  Zap,
  Users,
  Trophy,
  Timer,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { useAuth } from '../../state/contexts/AuthContext';

// Animation variants for staggered feature list
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, x: -20 },
  visible: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.4,
      ease: 'easeOut' as const,
    },
  },
};

const buttonVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.5,
      ease: 'easeOut' as const,
    },
  },
};

// Animated typing text
const TYPING_TEXTS = [
  'Practice makes perfect',
  'Improve your typing speed',
  'Challenge your friends',
  'Track your progress',
  'Earn XP as you type',
];

export const TypingChallengeCTA: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [currentTextIndex, setCurrentTextIndex] = useState(0);
  const [displayedText, setDisplayedText] = useState('');
  const [isTyping, setIsTyping] = useState(true);

  // Typing animation effect
  useEffect(() => {
    const text = TYPING_TEXTS[currentTextIndex];

    if (isTyping) {
      if (displayedText.length < text.length) {
        const timeout = setTimeout(() => {
          setDisplayedText(text.slice(0, displayedText.length + 1));
        }, 50);
        return () => clearTimeout(timeout);
      } else {
        // Pause at the end
        const timeout = setTimeout(() => {
          setIsTyping(false);
        }, 2000);
        return () => clearTimeout(timeout);
      }
    } else {
      // Delete text
      if (displayedText.length > 0) {
        const timeout = setTimeout(() => {
          setDisplayedText(displayedText.slice(0, -1));
        }, 30);
        return () => clearTimeout(timeout);
      } else {
        // Move to next text
        setCurrentTextIndex((prev) => (prev + 1) % TYPING_TEXTS.length);
        setIsTyping(true);
      }
    }
  }, [displayedText, isTyping, currentTextIndex]);

  // Feature list data
  const features = [
    { icon: Zap, label: 'Speed Tests', desc: '60-second challenges', color: 'text-yellow-300' },
    { icon: Users, label: 'PvP Battles', desc: 'Compete in real-time', color: 'text-green-300' },
    { icon: Trophy, label: 'Leaderboards', desc: 'Global rankings', color: 'text-orange-300' },
    { icon: Sparkles, label: 'Earn XP', desc: 'Level up as you play', color: 'text-purple-300' },
  ];

  return (
    <section className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10 sm:py-14">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.2 }}
        transition={{ duration: 0.5 }}
        className="relative overflow-hidden rounded-2xl sm:rounded-3xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 dark:from-cyan-700 dark:via-blue-800 dark:to-indigo-900"
      >
        {/* Animated keyboard pattern background */}
        <div className="absolute inset-0 opacity-5">
          <div className="absolute inset-0" style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60' viewBox='0 0 60 60'%3E%3Crect x='5' y='5' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='25' y='5' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='45' y='5' width='10' height='15' rx='2' fill='white'/%3E%3Crect x='5' y='25' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='25' y='25' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='45' y='25' width='10' height='15' rx='2' fill='white'/%3E%3Crect x='5' y='45' width='50' height='10' rx='2' fill='white'/%3E%3C/svg%3E")`,
            backgroundSize: '60px 60px',
          }} />
        </div>

        <div className="relative px-5 sm:px-8 lg:px-12 py-8 sm:py-12">
          <div className="grid lg:grid-cols-2 gap-6 lg:gap-10 items-center">
            {/* Left side - Content */}
            <div>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4 }}
                className="inline-flex items-center gap-2 px-3 py-1.5 bg-white/10 backdrop-blur-sm rounded-full text-cyan-100 text-sm font-medium mb-3 sm:mb-4"
              >
                <Keyboard className="w-4 h-4" />
                <span>Typing Practice</span>
              </motion.div>

              <motion.h2
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: 0.1 }}
                className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white mb-3"
              >
                Master Your Typing Skills
              </motion.h2>

              {/* Animated typing text */}
              <motion.div
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: 0.2 }}
                className="h-7 sm:h-8 mb-5 sm:mb-6"
              >
                <p className="text-base sm:text-lg text-cyan-100 font-mono">
                  <span>{displayedText}</span>
                  <span className="animate-pulse">|</span>
                </p>
              </motion.div>

              {/* Feature highlights - staggered animation */}
              <motion.div
                variants={containerVariants}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
                className="grid grid-cols-2 gap-3 sm:gap-4 mb-6 sm:mb-8"
              >
                {features.map((feature, idx) => {
                  const Icon = feature.icon;
                  return (
                    <motion.div
                      key={idx}
                      variants={itemVariants}
                      className="flex items-center gap-2 sm:gap-3 text-white/90"
                    >
                      <div className="p-1.5 sm:p-2 bg-white/10 rounded-lg shrink-0">
                        <Icon className={`w-4 h-4 sm:w-5 sm:h-5 ${feature.color}`} />
                      </div>
                      <div className="min-w-0">
                        <div className="font-medium text-sm sm:text-base truncate">{feature.label}</div>
                        <div className="text-xs sm:text-sm text-cyan-200 truncate">{feature.desc}</div>
                      </div>
                    </motion.div>
                  );
                })}
              </motion.div>

              {/* CTA Buttons - animated */}
              <motion.div
                variants={buttonVariants}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
                className="flex flex-col sm:flex-row gap-3"
              >
                <Link
                  to="/typing-practice"
                  className="group inline-flex items-center justify-center gap-2 px-5 sm:px-6 py-2.5 sm:py-3 bg-white text-blue-600 rounded-lg font-semibold hover:bg-blue-50 transition-all shadow-lg text-sm sm:text-base"
                >
                  <Timer className="w-4 h-4 sm:w-5 sm:h-5" />
                  <span>Start Typing</span>
                  <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5 group-hover:translate-x-1 transition-transform" />
                </Link>

                {isAuthenticated && (
                  <Link
                    to="/typing-practice/pvp"
                    className="group inline-flex items-center justify-center gap-2 px-5 sm:px-6 py-2.5 sm:py-3 bg-white/10 backdrop-blur-sm text-white border-2 border-white/30 rounded-lg font-semibold hover:bg-white/20 transition-all text-sm sm:text-base"
                  >
                    <Users className="w-4 h-4 sm:w-5 sm:h-5" />
                    <span>Find PvP Match</span>
                  </Link>
                )}

                {!isAuthenticated && (
                  <Link
                    to="/register"
                    className="inline-flex items-center justify-center gap-2 px-5 sm:px-6 py-2.5 sm:py-3 bg-white/10 backdrop-blur-sm text-white border-2 border-white/30 rounded-lg font-semibold hover:bg-white/20 transition-all text-sm sm:text-base"
                  >
                    Sign up to compete
                  </Link>
                )}
              </motion.div>
            </div>

            {/* Right side - Visual */}
            <div className="hidden lg:flex items-center justify-center">
              <div className="relative">
                {/* Animated keyboard visualization */}
                <motion.div
                  initial={{ scale: 0.9, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ duration: 0.5, delay: 0.2 }}
                  className="relative"
                >
                  {/* Main keyboard visual */}
                  <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-6 border border-white/20">
                    {/* Top row */}
                    <div className="flex gap-2 mb-2">
                      {['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'].map(
                        (key, i) => (
                          <KeyCap key={key} char={key} delay={i * 0.05} />
                        )
                      )}
                    </div>
                    {/* Home row */}
                    <div className="flex gap-2 mb-2 ml-3">
                      {['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'].map(
                        (key, i) => (
                          <KeyCap key={key} char={key} delay={0.5 + i * 0.05} isHome={['F', 'J'].includes(key)} />
                        )
                      )}
                    </div>
                    {/* Bottom row */}
                    <div className="flex gap-2 ml-6">
                      {['Z', 'X', 'C', 'V', 'B', 'N', 'M'].map((key, i) => (
                        <KeyCap key={key} char={key} delay={1 + i * 0.05} />
                      ))}
                    </div>
                    {/* Space bar */}
                    <div className="flex justify-center mt-2">
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 1.5 }}
                        className="w-48 h-8 bg-white/20 rounded-lg border border-white/30"
                      />
                    </div>
                  </div>

                  {/* Stats floating badges */}
                  <motion.div
                    animate={{ y: [0, -5, 0] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="absolute -top-4 -right-4 px-3 py-2 bg-yellow-400 text-yellow-900 rounded-lg shadow-lg font-bold text-sm"
                  >
                    120+ WPM
                  </motion.div>

                  <motion.div
                    animate={{ y: [0, 5, 0] }}
                    transition={{ duration: 2, repeat: Infinity, delay: 0.5 }}
                    className="absolute -bottom-4 -left-4 px-3 py-2 bg-green-400 text-green-900 rounded-lg shadow-lg font-bold text-sm"
                  >
                    99% Accuracy
                  </motion.div>
                </motion.div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </section>
  );
};

// Animated key cap component
interface KeyCapProps {
  char: string;
  delay?: number;
  isHome?: boolean;
}

const KeyCap: React.FC<KeyCapProps> = ({ char, delay = 0, isHome = false }) => {
  const [isPressed, setIsPressed] = useState(false);

  // Random press animation
  useEffect(() => {
    const pressInterval = setInterval(() => {
      if (Math.random() > 0.85) {
        setIsPressed(true);
        setTimeout(() => setIsPressed(false), 100);
      }
    }, 500);

    return () => clearInterval(pressInterval);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{
        opacity: 1,
        y: isPressed ? 2 : 0,
        scale: isPressed ? 0.95 : 1,
      }}
      transition={{ delay, duration: 0.2 }}
      className={`w-8 h-8 flex items-center justify-center rounded-md text-sm font-semibold transition-all ${
        isPressed
          ? 'bg-cyan-300 text-cyan-900 shadow-inner'
          : 'bg-white/20 text-white border border-white/30 shadow-md'
      } ${isHome ? 'border-b-2 border-b-cyan-300' : ''}`}
    >
      {char}
    </motion.div>
  );
};

export default TypingChallengeCTA;
