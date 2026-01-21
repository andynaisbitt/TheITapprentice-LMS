// src/components/home/TypingChallengeCTA.tsx
/**
 * Typing Challenge CTA - Homepage component promoting the typing game
 * Features animated keyboard visual and quick access to typing modes
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

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 dark:from-cyan-700 dark:via-blue-800 dark:to-indigo-900"
      >
        {/* Animated keyboard pattern background */}
        <div className="absolute inset-0 opacity-5">
          <div className="absolute inset-0" style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60' viewBox='0 0 60 60'%3E%3Crect x='5' y='5' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='25' y='5' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='45' y='5' width='10' height='15' rx='2' fill='white'/%3E%3Crect x='5' y='25' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='25' y='25' width='15' height='15' rx='2' fill='white'/%3E%3Crect x='45' y='25' width='10' height='15' rx='2' fill='white'/%3E%3Crect x='5' y='45' width='50' height='10' rx='2' fill='white'/%3E%3C/svg%3E")`,
            backgroundSize: '60px 60px',
          }} />
        </div>

        <div className="relative px-6 sm:px-8 lg:px-12 py-10 sm:py-14">
          <div className="grid lg:grid-cols-2 gap-8 items-center">
            {/* Left side - Content */}
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-white/10 backdrop-blur-sm rounded-full text-cyan-100 text-sm font-medium mb-4">
                <Keyboard className="w-4 h-4" />
                <span>Typing Practice</span>
              </div>

              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                Master Your Typing Skills
              </h2>

              {/* Animated typing text */}
              <div className="h-8 mb-6">
                <p className="text-lg text-cyan-100 font-mono">
                  <span>{displayedText}</span>
                  <span className="animate-pulse">|</span>
                </p>
              </div>

              {/* Feature highlights */}
              <div className="grid sm:grid-cols-2 gap-4 mb-8">
                <div className="flex items-center gap-3 text-white/90">
                  <div className="p-2 bg-white/10 rounded-lg">
                    <Zap className="w-5 h-5 text-yellow-300" />
                  </div>
                  <div>
                    <div className="font-medium">Speed Tests</div>
                    <div className="text-sm text-cyan-200">60-second challenges</div>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-white/90">
                  <div className="p-2 bg-white/10 rounded-lg">
                    <Users className="w-5 h-5 text-green-300" />
                  </div>
                  <div>
                    <div className="font-medium">PvP Battles</div>
                    <div className="text-sm text-cyan-200">Compete in real-time</div>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-white/90">
                  <div className="p-2 bg-white/10 rounded-lg">
                    <Trophy className="w-5 h-5 text-orange-300" />
                  </div>
                  <div>
                    <div className="font-medium">Leaderboards</div>
                    <div className="text-sm text-cyan-200">Global rankings</div>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-white/90">
                  <div className="p-2 bg-white/10 rounded-lg">
                    <Sparkles className="w-5 h-5 text-purple-300" />
                  </div>
                  <div>
                    <div className="font-medium">Earn XP</div>
                    <div className="text-sm text-cyan-200">Level up as you play</div>
                  </div>
                </div>
              </div>

              {/* CTA Buttons */}
              <div className="flex flex-wrap gap-4">
                <Link
                  to="/typing"
                  className="group inline-flex items-center gap-2 px-6 py-3 bg-white text-blue-600 rounded-lg font-semibold hover:bg-blue-50 transition-all shadow-lg"
                >
                  <Timer className="w-5 h-5" />
                  <span>Start Typing</span>
                  <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </Link>

                {isAuthenticated && (
                  <Link
                    to="/typing/pvp"
                    className="group inline-flex items-center gap-2 px-6 py-3 bg-white/10 backdrop-blur-sm text-white border-2 border-white/30 rounded-lg font-semibold hover:bg-white/20 transition-all"
                  >
                    <Users className="w-5 h-5" />
                    <span>Find PvP Match</span>
                  </Link>
                )}

                {!isAuthenticated && (
                  <Link
                    to="/register"
                    className="inline-flex items-center gap-2 px-6 py-3 bg-white/10 backdrop-blur-sm text-white border-2 border-white/30 rounded-lg font-semibold hover:bg-white/20 transition-all"
                  >
                    Sign up to compete
                  </Link>
                )}
              </div>
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
