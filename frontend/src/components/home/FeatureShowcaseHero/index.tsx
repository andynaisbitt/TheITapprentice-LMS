// src/components/home/FeatureShowcaseHero/index.tsx
/**
 * Feature Showcase Hero - Premium auto-cycling hero section
 * Highlights LMS features: Courses, Typing, Quizzes, Tutorials, Leaderboards, Progress
 * Mobile-first with touch swipe support
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence, PanInfo } from 'framer-motion';
import { Link } from 'react-router-dom';
import { ArrowRight, ChevronLeft, ChevronRight, Pause, Play } from 'lucide-react';
import { featureSlides, FeatureSlide } from './slideData';
import { useAuth } from '../../../state/contexts/AuthContext';

const AUTO_ADVANCE_INTERVAL = 6000; // 6 seconds per slide
const SWIPE_THRESHOLD = 50; // Minimum swipe distance

// Animation variants for slide transitions
const slideVariants = {
  enter: (direction: number) => ({
    x: direction > 0 ? '100%' : '-100%',
    opacity: 0,
    scale: 0.95,
  }),
  center: {
    x: 0,
    opacity: 1,
    scale: 1,
    transition: {
      duration: 0.5,
      ease: [0.32, 0.72, 0, 1] as const,
    },
  },
  exit: (direction: number) => ({
    x: direction < 0 ? '100%' : '-100%',
    opacity: 0,
    scale: 0.95,
    transition: {
      duration: 0.4,
      ease: [0.32, 0.72, 0, 1] as const,
    },
  }),
};

// Icon animation variants
const iconVariants = {
  initial: { scale: 0.8, opacity: 0, rotate: -10 },
  animate: {
    scale: 1,
    opacity: 1,
    rotate: 0,
    transition: {
      duration: 0.6,
      delay: 0.2,
      ease: 'easeOut' as const,
    },
  },
};

// Text stagger animation
const textContainerVariants = {
  initial: { opacity: 0 },
  animate: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.3,
    },
  },
};

const textItemVariants = {
  initial: { opacity: 0, y: 20 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: 'easeOut' as const },
  },
};

export const FeatureShowcaseHero: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [currentIndex, setCurrentIndex] = useState(0);
  const [direction, setDirection] = useState(1);
  const [isPaused, setIsPaused] = useState(false);
  const [isHovering, setIsHovering] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const currentSlide = featureSlides[currentIndex];

  // Navigate to specific slide
  const goToSlide = useCallback((index: number) => {
    setDirection(index > currentIndex ? 1 : -1);
    setCurrentIndex(index);
  }, [currentIndex]);

  // Navigate to next slide
  const nextSlide = useCallback(() => {
    setDirection(1);
    setCurrentIndex((prev) => (prev + 1) % featureSlides.length);
  }, []);

  // Navigate to previous slide
  const prevSlide = useCallback(() => {
    setDirection(-1);
    setCurrentIndex((prev) => (prev - 1 + featureSlides.length) % featureSlides.length);
  }, []);

  // Auto-advance timer
  useEffect(() => {
    if (isPaused || isHovering) return;

    const timer = setInterval(nextSlide, AUTO_ADVANCE_INTERVAL);
    return () => clearInterval(timer);
  }, [isPaused, isHovering, nextSlide]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft') prevSlide();
      if (e.key === 'ArrowRight') nextSlide();
      if (e.key === ' ') {
        e.preventDefault();
        setIsPaused((p) => !p);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [nextSlide, prevSlide]);

  // Handle swipe gestures
  const handleDragEnd = (_: any, info: PanInfo) => {
    const { offset, velocity } = info;

    if (Math.abs(offset.x) > SWIPE_THRESHOLD || Math.abs(velocity.x) > 500) {
      if (offset.x > 0) {
        prevSlide();
      } else {
        nextSlide();
      }
    }
  };

  // Get CTA link - redirect to login if not authenticated for dashboard
  const getCtaLink = (slide: FeatureSlide) => {
    if (slide.id === 'progress' && !isAuthenticated) {
      return '/login';
    }
    return slide.ctaLink;
  };

  return (
    <section
      ref={containerRef}
      className="relative overflow-hidden"
      onMouseEnter={() => setIsHovering(true)}
      onMouseLeave={() => setIsHovering(false)}
      aria-label="Feature showcase"
      role="region"
    >
      {/* Background with animated gradient */}
      <AnimatePresence mode="wait">
        <motion.div
          key={currentSlide.id}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.5 }}
          className={`absolute inset-0 bg-gradient-to-br ${currentSlide.gradient}`}
        />
      </AnimatePresence>

      {/* Animated background pattern */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmZmZmYiIGZpbGwtb3BhY2l0eT0iMC4xIj48Y2lyY2xlIGN4PSIzMCIgY3k9IjMwIiByPSIyIi8+PC9nPjwvZz48L3N2Zz4=')]" />
      </div>

      {/* Floating orbs decoration */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <motion.div
          animate={{
            x: [0, 30, 0],
            y: [0, -20, 0],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
          className="absolute top-20 left-[10%] w-64 h-64 bg-white/10 rounded-full blur-3xl"
        />
        <motion.div
          animate={{
            x: [0, -20, 0],
            y: [0, 30, 0],
          }}
          transition={{
            duration: 10,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
          className="absolute bottom-20 right-[10%] w-80 h-80 bg-white/10 rounded-full blur-3xl"
        />
      </div>

      {/* Main content - fixed height container to prevent layout shift */}
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-20 lg:py-28">
        <div className="min-h-[280px] sm:min-h-[260px] lg:min-h-[240px]">
          <AnimatePresence mode="wait" custom={direction}>
            <motion.div
              key={currentSlide.id}
              custom={direction}
              variants={slideVariants}
              initial="enter"
              animate="center"
              exit="exit"
              drag="x"
              dragConstraints={{ left: 0, right: 0 }}
              dragElastic={0.1}
              onDragEnd={handleDragEnd}
              className="flex flex-col lg:flex-row items-center gap-8 lg:gap-16 cursor-grab active:cursor-grabbing"
            >
            {/* Icon Section */}
            <motion.div
              variants={iconVariants}
              initial="initial"
              animate="animate"
              className="flex-shrink-0"
            >
              <div className={`relative w-32 h-32 sm:w-40 sm:h-40 lg:w-48 lg:h-48 rounded-3xl bg-gradient-to-br ${currentSlide.iconGradient} shadow-2xl flex items-center justify-center`}>
                {/* Glow effect */}
                <div className={`absolute inset-0 rounded-3xl bg-gradient-to-br ${currentSlide.iconGradient} blur-2xl opacity-50`} />

                {/* Icon */}
                <currentSlide.icon className="relative w-16 h-16 sm:w-20 sm:h-20 lg:w-24 lg:h-24 text-white" strokeWidth={1.5} />

                {/* Animated ring */}
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
                  className="absolute inset-0 rounded-3xl border-2 border-white/20 border-dashed"
                />
              </div>
            </motion.div>

            {/* Text Content */}
            <motion.div
              variants={textContainerVariants}
              initial="initial"
              animate="animate"
              className="flex-1 text-center lg:text-left"
            >
              {/* Badge */}
              <motion.div variants={textItemVariants} className="inline-flex items-center gap-2 px-4 py-1.5 bg-white/15 backdrop-blur-sm rounded-full text-white/90 text-sm font-medium mb-4">
                <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
                Feature {currentIndex + 1} of {featureSlides.length}
              </motion.div>

              {/* Headline */}
              <motion.h1
                variants={textItemVariants}
                className="text-3xl sm:text-4xl lg:text-5xl xl:text-6xl font-bold text-white mb-4 leading-tight"
              >
                {currentSlide.headline}
              </motion.h1>

              {/* Subtext */}
              <motion.p
                variants={textItemVariants}
                className="text-lg sm:text-xl text-white/80 mb-8 max-w-xl mx-auto lg:mx-0"
              >
                {currentSlide.subtext}
              </motion.p>

              {/* CTA Button */}
              <motion.div variants={textItemVariants}>
                <Link
                  to={getCtaLink(currentSlide)}
                  className="group inline-flex items-center gap-3 px-8 py-4 bg-white text-gray-900 rounded-xl font-semibold text-lg shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300"
                >
                  {currentSlide.cta}
                  <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </Link>
              </motion.div>
            </motion.div>
          </motion.div>
        </AnimatePresence>
        </div>

        {/* Navigation Controls */}
        <div className="mt-12 flex flex-col sm:flex-row items-center justify-between gap-6">
          {/* Slide Indicators */}
          <div className="flex items-center gap-2">
            {featureSlides.map((slide, index) => (
              <button
                key={slide.id}
                onClick={() => goToSlide(index)}
                className={`group relative h-2 rounded-full transition-all duration-300 ${
                  index === currentIndex
                    ? 'w-8 bg-white'
                    : 'w-2 bg-white/40 hover:bg-white/60'
                }`}
                aria-label={`Go to ${slide.headline}`}
                aria-current={index === currentIndex ? 'true' : 'false'}
              >
                {/* Progress indicator for current slide */}
                {index === currentIndex && !isPaused && !isHovering && (
                  <motion.div
                    initial={{ width: '0%' }}
                    animate={{ width: '100%' }}
                    transition={{ duration: AUTO_ADVANCE_INTERVAL / 1000, ease: 'linear' }}
                    className="absolute inset-0 bg-white/50 rounded-full"
                  />
                )}
              </button>
            ))}
          </div>

          {/* Arrow Navigation + Pause */}
          <div className="flex items-center gap-3">
            {/* Pause/Play Button */}
            <button
              onClick={() => setIsPaused((p) => !p)}
              className="p-2 rounded-full bg-white/10 hover:bg-white/20 text-white transition-colors"
              aria-label={isPaused ? 'Play slideshow' : 'Pause slideshow'}
            >
              {isPaused ? <Play className="w-5 h-5" /> : <Pause className="w-5 h-5" />}
            </button>

            {/* Previous */}
            <button
              onClick={prevSlide}
              className="p-3 rounded-full bg-white/10 hover:bg-white/20 text-white transition-colors"
              aria-label="Previous slide"
            >
              <ChevronLeft className="w-6 h-6" />
            </button>

            {/* Next */}
            <button
              onClick={nextSlide}
              className="p-3 rounded-full bg-white/10 hover:bg-white/20 text-white transition-colors"
              aria-label="Next slide"
            >
              <ChevronRight className="w-6 h-6" />
            </button>
          </div>
        </div>
      </div>

      {/* Wave divider */}
      <div className="absolute bottom-0 left-0 right-0">
        <svg
          viewBox="0 0 1440 120"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-12 sm:h-16"
          preserveAspectRatio="none"
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

export default FeatureShowcaseHero;
