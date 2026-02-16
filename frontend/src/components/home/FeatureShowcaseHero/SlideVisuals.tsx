// src/components/home/FeatureShowcaseHero/SlideVisuals.tsx
/**
 * Responsive visuals for each feature slide
 * All visuals scale to fit their container
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  GraduationCap,
  CheckCircle,
  Trophy,
  Award,
  Zap,
  Flame,
  Medal,
  Star,
  Rocket,
} from 'lucide-react';
import { SPRING_SNAPPY, SPRING_BOUNCY, SPRING_GENTLE } from './slideData';

// Shared animation constants
const STAGGER = 0.05;

// ============================================
// WELCOME VISUAL
// ============================================
export const WelcomeVisual: React.FC = () => {
  const features = [
    { icon: '📚', label: 'Courses', desc: 'Step-by-step IT basics', color: 'from-blue-500 to-indigo-500' },
    { icon: '⌨️', label: 'Typing Games', desc: '5 game modes', color: 'from-orange-500 to-amber-500' },
    { icon: '🧠', label: 'Quizzes', desc: 'Test your knowledge', color: 'from-purple-500 to-pink-500' },
    { icon: '🏆', label: 'Compete', desc: 'Leaderboards & XP', color: 'from-yellow-500 to-orange-500' },
  ];

  return (
    <div className="w-full flex justify-center">
      <div className="relative w-full max-w-xs">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ y: SPRING_SNAPPY, opacity: { duration: 0.2, ease: 'easeOut' } }}
          className="backdrop-blur-xl bg-white/90 dark:bg-slate-800/90 rounded-2xl shadow-2xl border border-white/30 overflow-hidden"
        >
          {/* Header with rocket */}
          <div className="bg-gradient-to-r from-indigo-700 to-violet-700 p-3 sm:p-4">
            <div className="flex items-center gap-3">
              <motion.div
                animate={{ y: [0, -4, 0] }}
                transition={{ duration: 2.5, repeat: Infinity, ease: 'easeInOut' }}
                className="w-10 h-10 bg-white/20 backdrop-blur rounded-xl flex items-center justify-center"
              >
                <Rocket className="w-5 h-5 text-white" />
              </motion.div>
              <div>
                <h3 className="text-white font-bold text-sm sm:text-base">The IT Apprentice</h3>
                <p className="text-white/80 text-xs">Learn IT from scratch</p>
              </div>
            </div>
          </div>

          {/* Feature rows */}
          <div className="p-2 sm:p-3 space-y-1">
            {features.map((feature, i) => (
              <motion.div
                key={feature.label}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ x: { ...SPRING_SNAPPY, delay: i * STAGGER }, opacity: { duration: 0.2, delay: i * STAGGER } }}
                className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700/50"
              >
                <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${feature.color} flex items-center justify-center shadow-sm`}>
                  <span className="text-sm">{feature.icon}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">{feature.label}</p>
                  <p className="text-[10px] text-slate-500">{feature.desc}</p>
                </div>
                <Zap className="w-3 h-3 text-amber-400" />
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* 100% Free badge */}
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1, y: [0, -4, 0] }}
          transition={{ scale: { delay: 0.3, ...SPRING_BOUNCY }, y: { duration: 2, repeat: Infinity } }}
          className="absolute -top-2 -right-2 px-2.5 py-1.5 bg-gradient-to-r from-emerald-400 to-green-500 rounded-lg shadow-lg"
        >
          <span className="text-white font-bold text-xs">100% Free</span>
        </motion.div>
      </div>
    </div>
  );
};

// ============================================
// COURSES VISUAL
// ============================================
export const CoursesVisual: React.FC = () => {
  const [activeModule, setActiveModule] = useState(0);
  const [progress, setProgress] = useState(0);

  const course = {
    title: 'IT Fundamentals',
    modules: [
      { name: 'Using a Computer', lessons: 5, complete: true },
      { name: 'Files & Folders', lessons: 6, complete: true },
      { name: 'Email & Internet', lessons: 8, complete: false },
      { name: 'Basic Troubleshooting', lessons: 4, complete: false },
    ],
  };

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveModule((prev) => (prev + 1) % course.modules.length);
    }, 1500);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => setProgress(52), 500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="w-full flex justify-center">
      <div className="relative w-full max-w-xs">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ y: SPRING_SNAPPY, opacity: { duration: 0.2, ease: 'easeOut' } }}
          className="backdrop-blur-xl bg-white/90 dark:bg-slate-800/90 rounded-2xl shadow-2xl border border-white/30 overflow-hidden"
        >
          <div className="bg-gradient-to-r from-blue-700 to-indigo-700 p-3 sm:p-4">
            <div className="flex items-center gap-3">
              <motion.div
                animate={{ rotate: [0, -5, 5, 0] }}
                transition={{ duration: 3, repeat: Infinity }}
                className="w-10 h-10 bg-white/20 backdrop-blur rounded-xl flex items-center justify-center"
              >
                <GraduationCap className="w-5 h-5 text-white" />
              </motion.div>
              <div>
                <h3 className="text-white font-bold text-sm sm:text-base">{course.title}</h3>
                <p className="text-white/80 text-xs">4 modules • 23 lessons</p>
              </div>
            </div>
            <div className="mt-3">
              <div className="flex justify-between text-xs text-white/80 mb-1">
                <span>Progress</span>
                <span>{progress}%</span>
              </div>
              <div className="h-2.5 bg-white/20 rounded-full overflow-hidden relative">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 1.5, ease: [0.22, 1, 0.36, 1] }}
                  className="h-full bg-gradient-to-r from-white to-blue-100 rounded-full relative"
                >
                  <motion.div
                    animate={{ x: ['-100%', '200%'] }}
                    transition={{ duration: 1.5, repeat: Infinity, repeatDelay: 1 }}
                    className="absolute inset-0 bg-gradient-to-r from-transparent via-white/60 to-transparent"
                  />
                </motion.div>
              </div>
            </div>
          </div>

          <div className="p-2 sm:p-3 space-y-1">
            {course.modules.map((module, i) => (
              <motion.div
                key={module.name}
                initial={{ opacity: 0, x: -10 }}
                animate={{
                  opacity: 1,
                  x: 0,
                  backgroundColor: activeModule === i ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  scale: activeModule === i ? 1.02 : 1,
                }}
                transition={{ x: { ...SPRING_SNAPPY, delay: i * STAGGER }, opacity: { duration: 0.2, delay: i * STAGGER } }}
                className="flex items-center gap-2 p-2 rounded-lg"
              >
                <motion.div
                  animate={{
                    scale: activeModule === i ? [1, 1.15, 1] : 1,
                    boxShadow: activeModule === i ? '0 0 12px rgba(59, 130, 246, 0.5)' : 'none',
                  }}
                  transition={{ duration: 0.5, repeat: activeModule === i ? Infinity : 0, repeatDelay: 1 }}
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                    module.complete
                      ? 'bg-green-500 text-white'
                      : activeModule === i
                      ? 'bg-blue-500 text-white'
                      : 'bg-slate-200 dark:bg-slate-600 text-slate-500'
                  }`}
                >
                  {module.complete ? <CheckCircle className="w-3.5 h-3.5" /> : i + 1}
                </motion.div>
                <div className="flex-1 min-w-0">
                  <p className={`text-xs font-medium truncate ${
                    module.complete ? 'text-green-600 dark:text-green-400' : 'text-slate-700 dark:text-slate-200'
                  }`}>
                    {module.name}
                  </p>
                  <p className="text-[10px] text-slate-500">{module.lessons} lessons</p>
                </div>
                {activeModule === i && !module.complete && (
                  <motion.span
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ scale: SPRING_BOUNCY, opacity: { duration: 0.2 } }}
                    className="text-[10px] bg-blue-500 text-white px-1.5 py-0.5 rounded-full"
                  >
                    Next
                  </motion.span>
                )}
              </motion.div>
            ))}
          </div>
        </motion.div>

        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1, y: [0, -4, 0] }}
          transition={{ scale: { delay: 0.3, ...SPRING_BOUNCY }, y: { duration: 2, repeat: Infinity } }}
          className="absolute -top-2 -right-2 px-2.5 py-1.5 bg-gradient-to-r from-amber-400 to-orange-500 rounded-lg shadow-lg"
        >
          <span className="flex items-center gap-1 text-white font-bold text-xs">
            <Zap className="w-3 h-3" />
            +120 XP
          </span>
        </motion.div>
      </div>
    </div>
  );
};

// ============================================
// TYPING VISUAL
// ============================================
export const TypingVisual: React.FC = () => {
  const [pressedKeys, setPressedKeys] = useState<Set<string>>(new Set());
  const [activeMode, setActiveMode] = useState(0);

  const modes = [
    { name: 'Speed Test', icon: '\u26A1', desc: 'Test your WPM', color: 'from-yellow-600 to-orange-600' },
    { name: 'Practice', icon: '\uD83D\uDCDD', desc: 'Custom words', color: 'from-green-600 to-emerald-600' },
    { name: 'Infinite Rush', icon: '\uD83D\uDD25', desc: 'Endless mode', color: 'from-red-600 to-rose-600' },
    { name: 'Ghost Mode', icon: '\uD83D\uDC7B', desc: 'Race yourself', color: 'from-purple-600 to-violet-600' },
    { name: 'PvP Battle', icon: '\u2694\uFE0F', desc: 'Real-time 1v1', color: 'from-blue-600 to-cyan-600' },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveMode((prev) => (prev + 1) % modes.length);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const keys = ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z', 'X', 'C', 'V', 'B', 'N', 'M'];
    const interval = setInterval(() => {
      const randomKey = keys[Math.floor(Math.random() * keys.length)];
      setPressedKeys(new Set([randomKey]));
      setTimeout(() => setPressedKeys(new Set()), 100);
    }, 150);
    return () => clearInterval(interval);
  }, []);

  const KeyCap = ({ char }: { char: string }) => {
    const isPressed = pressedKeys.has(char);
    return (
      <motion.div
        animate={{ y: isPressed ? 2 : 0, scale: isPressed ? 0.92 : 1 }}
        className={`w-6 h-6 sm:w-7 sm:h-7 flex items-center justify-center rounded text-[10px] font-bold ${
          isPressed
            ? 'bg-cyan-300 text-cyan-900'
            : 'bg-white/20 text-white border border-white/30'
        }`}
      >
        {char}
      </motion.div>
    );
  };

  return (
    <div className="w-full flex flex-col items-center gap-3">
      {/* Mode card */}
      <div className="relative h-16 sm:h-20 w-full max-w-xs">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeMode}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ y: SPRING_GENTLE, opacity: { duration: 0.2 } }}
            className={`absolute inset-0 bg-gradient-to-r ${modes[activeMode].color} rounded-xl p-3 shadow-xl`}
          >
            <div className="flex items-center gap-3">
              <span className="text-2xl sm:text-3xl">{modes[activeMode].icon}</span>
              <div>
                <h3 className="text-white font-bold text-sm sm:text-base">{modes[activeMode].name}</h3>
                <p className="text-white/80 text-xs">{modes[activeMode].desc}</p>
              </div>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Mode dots */}
      <div className="flex gap-1.5">
        {modes.map((_, idx) => (
          <div
            key={idx}
            className={`w-1.5 h-1.5 rounded-full ${activeMode === idx ? 'bg-white' : 'bg-white/40'}`}
          />
        ))}
      </div>

      {/* Keyboard */}
      <div className="bg-white/10 backdrop-blur-sm rounded-lg p-2 sm:p-3 border border-white/20">
        <div className="flex gap-0.5 mb-0.5">
          {['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'].map((key) => (
            <KeyCap key={key} char={key} />
          ))}
        </div>
        <div className="flex gap-0.5 mb-0.5 ml-2">
          {['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'].map((key) => (
            <KeyCap key={key} char={key} />
          ))}
        </div>
        <div className="flex gap-0.5 ml-4">
          {['Z', 'X', 'C', 'V', 'B', 'N', 'M'].map((key) => (
            <KeyCap key={key} char={key} />
          ))}
        </div>
      </div>

      <motion.div
        animate={{ y: [0, -3, 0] }}
        transition={{ duration: 1.5, repeat: Infinity }}
        className="px-3 py-1 bg-amber-600 text-white rounded-lg font-bold text-xs"
      >
        <span className="flex items-center gap-1">
          <Zap className="w-3 h-3" />
          120 WPM
        </span>
      </motion.div>
    </div>
  );
};

// ============================================
// QUIZZES VISUAL
// ============================================
export const QuizzesVisual: React.FC = () => {
  const [questionIdx, setQuestionIdx] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showResult, setShowResult] = useState(false);
  const [score, setScore] = useState(75);

  const questions = [
    { q: 'What does CPU stand for?', answers: ['Central Processing Unit', 'Computer Personal Unit', 'Central Program Utility'], correct: 0, topic: 'Hardware' },
    { q: 'Which key combo copies text?', answers: ['Ctrl + V', 'Ctrl + C', 'Ctrl + X'], correct: 1, topic: 'Shortcuts' },
    { q: 'What file type is a Word doc?', answers: ['.pdf', '.docx', '.xlsx'], correct: 1, topic: 'Files' },
  ];

  const currentQ = questions[questionIdx];

  useEffect(() => {
    const cycle = () => {
      setSelectedAnswer(null);
      setShowResult(false);
      setTimeout(() => setSelectedAnswer(currentQ.correct), 1500);
      setTimeout(() => {
        setShowResult(true);
        setScore(s => s + 10);
      }, 2500);
      setTimeout(() => setQuestionIdx(i => (i + 1) % questions.length), 4000);
    };
    cycle();
    const interval = setInterval(cycle, 4000);
    return () => clearInterval(interval);
  }, [questionIdx]);

  return (
    <div className="w-full flex justify-center">
      <div className="w-full max-w-xs">
        <motion.div className="backdrop-blur-xl bg-white/80 dark:bg-slate-800/80 rounded-2xl shadow-2xl border border-white/20 overflow-hidden">
          <div className="bg-gradient-to-r from-purple-700 to-fuchsia-700 p-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-white font-bold text-sm">Quick Quiz</h3>
                <p className="text-white/80 text-xs">{currentQ.topic}</p>
              </div>
              <div className="flex items-center gap-1 bg-white/20 px-2 py-1 rounded-full">
                <Zap className="w-3 h-3 text-yellow-300" />
                <span className="text-white font-bold text-xs">{score}</span>
              </div>
            </div>
          </div>

          <div className="p-3">
            <p className="text-xs font-medium text-slate-700 dark:text-slate-200 mb-3">{currentQ.q}</p>
            <div className="space-y-2">
              {currentQ.answers.map((answer, i) => (
                <div
                  key={`${questionIdx}-${i}`}
                  className={`flex items-center gap-2 p-2 rounded-lg border transition-all text-xs ${
                    showResult && i === currentQ.correct
                      ? 'bg-green-500 border-green-500 text-white'
                      : selectedAnswer === i
                      ? 'bg-purple-500 border-purple-500 text-white'
                      : 'border-slate-200 dark:border-slate-600'
                  }`}
                >
                  <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                    showResult && i === currentQ.correct ? 'bg-white/30' :
                    selectedAnswer === i ? 'bg-white/30' : 'bg-slate-100 dark:bg-slate-700'
                  }`}>
                    {showResult && i === currentQ.correct ? <CheckCircle className="w-3 h-3" /> : String.fromCharCode(65 + i)}
                  </span>
                  <span className="font-medium">{answer}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        <div className="flex justify-center gap-1.5 mt-3">
          {questions.map((_, i) => (
            <div
              key={i}
              className={`w-1.5 h-1.5 rounded-full ${questionIdx === i ? 'bg-purple-500' : 'bg-white/60'}`}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================
// TUTORIALS VISUAL
// ============================================
export const TutorialsVisual: React.FC = () => {
  const [activeTutorial, setActiveTutorial] = useState(0);
  const [activeStep, setActiveStep] = useState(0);

  const tutorials = [
    { title: 'Setting Up Email', icon: '\uD83D\uDCE7', steps: ['Open browser', 'Go to Gmail', 'Click Sign Up', 'Fill details'], color: '#EF4444' },
    { title: 'Connect to WiFi', icon: '\uD83D\uDCF6', steps: ['Click WiFi icon', 'Find network', 'Enter password', 'Connect!'], color: '#3B82F6' },
    { title: 'Install Software', icon: '\uD83D\uDCBF', steps: ['Download file', 'Open installer', 'Click Next', 'Done!'], color: '#10B981' },
  ];

  useEffect(() => {
    const stepInterval = setInterval(() => {
      setActiveStep((prev) => {
        const nextStep = prev + 1;
        if (nextStep >= tutorials[activeTutorial].steps.length) {
          setTimeout(() => {
            setActiveTutorial((t) => (t + 1) % tutorials.length);
            setActiveStep(0);
          }, 500);
          return prev;
        }
        return nextStep;
      });
    }, 1200);
    return () => clearInterval(stepInterval);
  }, [activeTutorial]);

  const currentTutorial = tutorials[activeTutorial];

  return (
    <div className="w-full flex justify-center">
      <div className="w-full max-w-xs">
        <motion.div className="backdrop-blur-xl bg-white/80 dark:bg-slate-800/80 rounded-2xl shadow-2xl border border-white/20 overflow-hidden">
          <div className="p-3" style={{ background: `linear-gradient(135deg, ${currentTutorial.color}20, transparent)` }}>
            <div className="flex items-center gap-3">
              <span className="text-3xl">{currentTutorial.icon}</span>
              <div>
                <h3 className="font-bold text-slate-800 dark:text-white text-sm">{currentTutorial.title}</h3>
                <p className="text-xs text-slate-500">Step {activeStep + 1} of {currentTutorial.steps.length}</p>
              </div>
            </div>
          </div>

          <div className="p-3 space-y-3">
            {currentTutorial.steps.map((step, i) => (
              <div key={`${activeTutorial}-${step}`} className="flex items-center gap-3">
                <div
                  className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white shadow-md`}
                  style={{ backgroundColor: i < activeStep ? '#10B981' : i === activeStep ? currentTutorial.color : '#E2E8F0' }}
                >
                  {i < activeStep ? <CheckCircle className="w-4 h-4" /> : i + 1}
                </div>
                <div className="flex-1">
                  <p className={`font-medium text-xs ${i <= activeStep ? 'text-slate-700 dark:text-slate-200' : 'text-slate-400'}`}>
                    {step}
                  </p>
                  {i === activeStep && (
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: '100%' }}
                      transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
                      className="h-0.5 mt-1 rounded-full"
                      style={{ backgroundColor: currentTutorial.color }}
                    />
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="px-3 pb-3 flex items-center justify-between">
            <span className="text-[10px] text-slate-500">Beginner friendly</span>
            <span className="flex items-center gap-1 text-amber-500 font-bold text-xs">
              <Zap className="w-3 h-3" />+50 XP
            </span>
          </div>
        </motion.div>

        <div className="flex justify-center gap-2 mt-3">
          {tutorials.map((t, i) => (
            <div
              key={t.title}
              className={`w-8 h-8 rounded-lg flex items-center justify-center bg-white/90 dark:bg-slate-700/90 shadow ${
                activeTutorial === i ? 'ring-2 ring-white' : 'opacity-60'
              }`}
            >
              <span className="text-lg">{t.icon}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================
// LEADERBOARD VISUAL
// ============================================
export const LeaderboardVisual: React.FC = () => {
  const rankings = [
    { rank: 1, name: 'TheITApprentice', xp: 2840 },
    { rank: 2, name: 'Sarah_Tech', xp: 2650 },
    { rank: 3, name: 'DaveFromIT', xp: 2480 },
    { rank: 4, name: 'You', xp: 2350, isUser: true },
    { rank: 5, name: 'TechNewbie42', xp: 2200 },
  ];

  return (
    <div className="w-full flex justify-center">
      <div className="w-full max-w-xs">
        <motion.div className="backdrop-blur-xl bg-white/80 dark:bg-slate-800/80 rounded-2xl shadow-2xl border border-white/20 overflow-hidden">
          <div className="bg-gradient-to-r from-amber-700 to-orange-700 p-3">
            <div className="flex items-center gap-3">
              <Trophy className="w-6 h-6 text-white" />
              <div>
                <h3 className="font-bold text-white text-sm">Top Learners</h3>
                <p className="text-white/80 text-xs">This Week</p>
              </div>
            </div>
          </div>

          <div className="p-2">
            {rankings.map((player) => (
              <div
                key={player.name}
                className={`flex items-center gap-2 p-2 rounded-lg mb-1 ${
                  player.isUser ? 'bg-blue-500/20 ring-1 ring-blue-500' : player.rank <= 3 ? 'bg-amber-50 dark:bg-amber-900/20' : ''
                }`}
              >
                <span className="w-6 text-center text-sm">
                  {player.rank === 1 ? '\uD83E\uDD47' : player.rank === 2 ? '\uD83E\uDD48' : player.rank === 3 ? '\uD83E\uDD49' : `#${player.rank}`}
                </span>
                <div className="flex-1 min-w-0">
                  <p className={`font-medium text-xs truncate ${
                    player.isUser ? 'text-blue-600 dark:text-blue-400' : 'text-slate-700 dark:text-slate-200'
                  }`}>
                    {player.name}
                  </p>
                </div>
                <span className="text-xs font-bold text-slate-600 dark:text-slate-300">{player.xp.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
};

// ============================================
// PROGRESS VISUAL
// ============================================
export const ProgressVisual: React.FC = () => {
  const [level, setLevel] = useState(0);
  const [xp, setXp] = useState(0);

  useEffect(() => {
    const levelTimer = setTimeout(() => setLevel(12), 500);
    const xpInterval = setInterval(() => setXp(x => x < 1850 ? x + 50 : x), 30);
    return () => {
      clearTimeout(levelTimer);
      clearInterval(xpInterval);
    };
  }, []);

  return (
    <div className="w-full flex justify-center">
      <div className="w-full max-w-xs flex flex-col items-center gap-4">
        {/* Level ring */}
        <div className="relative">
          <svg className="w-28 h-28 -rotate-90">
            <circle cx="50%" cy="50%" r="45%" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="6" />
            <motion.circle
              cx="50%" cy="50%" r="45%" fill="none" stroke="url(#progressGradient)" strokeWidth="6" strokeLinecap="round"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 0.65 }}
              transition={{ duration: 1.5, ease: [0.22, 1, 0.36, 1] }}
            />
            <defs>
              <linearGradient id="progressGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#06B6D4" />
                <stop offset="100%" stopColor="#3B82F6" />
              </linearGradient>
            </defs>
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-bold text-white">{level}</span>
            <span className="text-white/70 text-xs">Level</span>
          </div>
        </div>

        {/* Stats row */}
        <div className="flex gap-4">
          <div className="bg-white/80 dark:bg-slate-800/80 backdrop-blur rounded-xl p-3 shadow-lg">
            <div className="flex items-center gap-1 mb-1">
              <Flame className="w-4 h-4 text-orange-500" />
              <span className="font-bold text-xs text-slate-600 dark:text-slate-300">Streak</span>
            </div>
            <div className="text-xl font-bold text-slate-800 dark:text-white">7 <span className="text-xs font-normal text-slate-500">days</span></div>
          </div>
          <div className="bg-white/80 dark:bg-slate-800/80 backdrop-blur rounded-xl p-3 shadow-lg">
            <div className="flex items-center gap-1 mb-1">
              <Zap className="w-4 h-4 text-amber-500" />
              <span className="font-bold text-xs text-slate-600 dark:text-slate-300">Total XP</span>
            </div>
            <div className="text-xl font-bold text-slate-800 dark:text-white">{xp.toLocaleString()}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================
// SKILLS VISUAL
// ============================================
export const SkillsVisual: React.FC = () => {
  const [activeSkill, setActiveSkill] = useState(0);

  const skills = [
    { name: 'PC Basics', icon: '\uD83D\uDDA5\uFE0F', level: 45, color: '#3B82F6' },
    { name: 'Typing', icon: '\u2328\uFE0F', level: 67, color: '#10B981' },
    { name: 'Email', icon: '\uD83D\uDCE7', level: 52, color: '#EF4444' },
    { name: 'Internet', icon: '\uD83C\uDF10', level: 38, color: '#8B5CF6' },
  ];

  useEffect(() => {
    const interval = setInterval(() => setActiveSkill((prev) => (prev + 1) % skills.length), 1800);
    return () => clearInterval(interval);
  }, []);

  const currentSkill = skills[activeSkill];

  return (
    <div className="w-full flex justify-center">
      <div className="w-full max-w-xs">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeSkill}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            transition={{ scale: SPRING_GENTLE, opacity: { duration: 0.2 } }}
            className="backdrop-blur-xl bg-white/80 dark:bg-slate-800/80 rounded-2xl p-4 shadow-2xl border border-white/20"
          >
            <div className="text-center">
              <span className="text-4xl block mb-2">{currentSkill.icon}</span>
              <h3 className="font-bold text-lg text-slate-800 dark:text-white">{currentSkill.name}</h3>
              <div className="mt-3">
                <div className="flex justify-between text-sm mb-1">
                  <span className="font-bold" style={{ color: currentSkill.color }}>Level {currentSkill.level}</span>
                  <span className="text-slate-500">/ 99</span>
                </div>
                <div className="h-3 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${currentSkill.level}%` }}
                    transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
                    className="h-full rounded-full"
                    style={{ backgroundColor: currentSkill.color }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </AnimatePresence>

        <motion.div className="mt-4 flex justify-center">
          <div className="bg-gradient-to-r from-violet-700 to-purple-700 px-3 py-1.5 rounded-lg shadow-lg">
            <span className="text-white font-bold text-xs flex items-center gap-1">
              <Zap className="w-3 h-3" />
              Total: 297 / 594
            </span>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

// ============================================
// CERTIFICATIONS VISUAL
// ============================================
export const CertificationsVisual: React.FC = () => {
  const [activeCert, setActiveCert] = useState(0);

  const certs = [
    { name: 'PC Basics Complete', type: 'Course', date: 'Today', icon: '\uD83D\uDDA5\uFE0F' },
    { name: 'Speed Typer', type: '60 WPM achieved', date: 'Yesterday', icon: '\u2328\uFE0F' },
    { name: 'Quiz Champion', type: '10 quizzes passed', date: 'This week', icon: '\uD83E\uDDE0' },
  ];

  useEffect(() => {
    const interval = setInterval(() => setActiveCert((prev) => (prev + 1) % certs.length), 2500);
    return () => clearInterval(interval);
  }, []);

  const currentCert = certs[activeCert];

  return (
    <div className="w-full flex justify-center">
      <div className="w-full max-w-xs">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeCert}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ y: SPRING_GENTLE, opacity: { duration: 0.2 } }}
            className="backdrop-blur-xl bg-white/90 dark:bg-slate-800/90 rounded-2xl shadow-2xl border border-white/30 overflow-hidden"
          >
            <div className="h-1.5 bg-gradient-to-r from-amber-600 to-orange-600" />
            <div className="p-4 text-center">
              <span className="text-4xl block mb-2">{currentCert.icon}</span>
              <Award className="w-10 h-10 mx-auto mb-2 text-amber-500" />
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-medium">Achievement Unlocked</p>
              <h3 className="font-bold text-lg text-slate-800 dark:text-white mt-1">{currentCert.name}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300">{currentCert.type}</p>
              <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-700 flex items-center justify-center gap-1">
                <CheckCircle className="w-3 h-3 text-green-500" />
                <span className="text-xs text-green-600 dark:text-green-400 font-medium">Earned {currentCert.date}</span>
              </div>
            </div>
          </motion.div>
        </AnimatePresence>

        <div className="flex justify-center gap-1.5 mt-3">
          {certs.map((_, idx) => (
            <div key={idx} className={`w-1.5 h-1.5 rounded-full ${activeCert === idx ? 'bg-amber-500' : 'bg-white/50'}`} />
          ))}
        </div>

        <div className="flex justify-center gap-2 mt-3">
          {[Medal, Trophy, Star].map((Icon, i) => (
            <motion.div
              key={i}
              animate={{ y: [0, -4, 0] }}
              transition={{ duration: 1.5, delay: i * 0.08, repeat: Infinity }}
              className="w-8 h-8 bg-white/90 dark:bg-slate-700/90 rounded-lg flex items-center justify-center shadow"
            >
              <Icon className="w-4 h-4 text-amber-500" />
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================
// CHALLENGES VISUAL
// ============================================
export const ChallengesVisual: React.FC = () => {
  const [checkedTasks, setCheckedTasks] = useState<number[]>([]);

  const tasks = [
    { label: 'Complete a typing test', xp: 50 },
    { label: 'Pass a quiz with 80%+', xp: 75 },
    { label: 'Finish a tutorial step', xp: 40 },
  ];

  useEffect(() => {
    const timers = [
      setTimeout(() => setCheckedTasks([0]), 1200),
      setTimeout(() => setCheckedTasks([0, 1]), 2400),
      setTimeout(() => setCheckedTasks([0, 1, 2]), 3600),
      setTimeout(() => setCheckedTasks([]), 5000),
    ];
    const interval = setInterval(() => {
      setCheckedTasks([]);
      timers.push(
        setTimeout(() => setCheckedTasks([0]), 1200),
        setTimeout(() => setCheckedTasks([0, 1]), 2400),
        setTimeout(() => setCheckedTasks([0, 1, 2]), 3600),
        setTimeout(() => setCheckedTasks([]), 5000),
      );
    }, 5500);
    return () => {
      timers.forEach(clearTimeout);
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="w-full flex justify-center">
      <div className="relative w-full max-w-xs">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ y: SPRING_SNAPPY, opacity: { duration: 0.2, ease: 'easeOut' } }}
          className="backdrop-blur-xl bg-white/90 dark:bg-slate-800/90 rounded-2xl shadow-2xl border border-white/30 overflow-hidden"
        >
          <div className="bg-gradient-to-r from-rose-700 to-red-700 p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Flame className="w-6 h-6 text-white" />
                <div>
                  <h3 className="text-white font-bold text-sm">Daily Challenges</h3>
                  <p className="text-white/80 text-xs">{checkedTasks.length} / {tasks.length} complete</p>
                </div>
              </div>
            </div>
          </div>

          <div className="p-3 space-y-2">
            {tasks.map((task, i) => {
              const done = checkedTasks.includes(i);
              return (
                <motion.div
                  key={task.label}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ x: { ...SPRING_SNAPPY, delay: i * STAGGER }, opacity: { duration: 0.2, delay: i * STAGGER } }}
                  className={`flex items-center gap-2 p-2 rounded-lg ${done ? 'bg-green-50 dark:bg-green-900/20' : ''}`}
                >
                  <motion.div
                    animate={{ scale: done ? [1, 1.2, 1] : 1 }}
                    transition={SPRING_BOUNCY}
                    className={`w-5 h-5 rounded-full flex items-center justify-center ${
                      done ? 'bg-green-500 text-white' : 'border-2 border-slate-300 dark:border-slate-600'
                    }`}
                  >
                    {done && <CheckCircle className="w-3.5 h-3.5" />}
                  </motion.div>
                  <span className={`flex-1 text-xs font-medium ${
                    done ? 'text-green-600 dark:text-green-400 line-through' : 'text-slate-700 dark:text-slate-200'
                  }`}>
                    {task.label}
                  </span>
                  <span className="text-[10px] font-bold text-amber-500">+{task.xp} XP</span>
                </motion.div>
              );
            })}
          </div>
        </motion.div>

        {/* Streak badge */}
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1, y: [0, -4, 0] }}
          transition={{ scale: { delay: 0.3, ...SPRING_BOUNCY }, y: { duration: 2, repeat: Infinity } }}
          className="absolute -top-2 -right-2 px-2.5 py-1.5 bg-gradient-to-r from-orange-400 to-red-500 rounded-lg shadow-lg"
        >
          <span className="flex items-center gap-1 text-white font-bold text-xs">
            <Flame className="w-3 h-3" />
            7 day streak
          </span>
        </motion.div>
      </div>
    </div>
  );
};

// Export mapping
export const slideVisuals: Record<string, React.FC> = {
  welcome: WelcomeVisual,
  courses: CoursesVisual,
  typing: TypingVisual,
  quizzes: QuizzesVisual,
  tutorials: TutorialsVisual,
  leaderboard: LeaderboardVisual,
  progress: ProgressVisual,
  skills: SkillsVisual,
  certifications: CertificationsVisual,
  challenges: ChallengesVisual,
};

export default slideVisuals;
