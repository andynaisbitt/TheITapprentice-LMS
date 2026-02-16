// src/components/home/FeatureShowcaseHero/index.tsx
/**
 * Feature Showcase Hero - Premium auto-cycling hero section
 * Mobile-first with proper viewport sizing and visual polish
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence, PanInfo } from 'framer-motion';
import { Link } from 'react-router-dom';
import { ArrowRight, ChevronLeft, ChevronRight, ChevronDown, Pause, Play } from 'lucide-react';
import { featureSlides, FeatureSlide, SPRING_SNAPPY, SPRING_BOUNCY, SPRING_GENTLE } from './slideData';
import { slideVisuals } from './SlideVisuals';
import { useAuth } from '../../../state/contexts/AuthContext';

const AUTO_ADVANCE_INTERVAL = 6000;
const SWIPE_THRESHOLD = 50;

export const FeatureShowcaseHero: React.FC = () => {
  const { isAuthenticated, user } = useAuth();
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [isHovering, setIsHovering] = useState(false);
  const [showSwipeHint, setShowSwipeHint] = useState(true);

  const currentSlide = featureSlides[currentIndex];
  const isWelcomeSlide = currentSlide.id === 'welcome';

  const goToSlide = useCallback((index: number) => {
    setCurrentIndex(index);
    setShowSwipeHint(false);
  }, []);

  const nextSlide = useCallback(() => {
    setCurrentIndex((prev) => (prev + 1) % featureSlides.length);
    setShowSwipeHint(false);
  }, []);

  const prevSlide = useCallback(() => {
    setCurrentIndex((prev) => (prev - 1 + featureSlides.length) % featureSlides.length);
    setShowSwipeHint(false);
  }, []);

  // Auto-advance
  useEffect(() => {
    if (isPaused || isHovering) return;
    const timer = setInterval(nextSlide, AUTO_ADVANCE_INTERVAL);
    return () => clearInterval(timer);
  }, [isPaused, isHovering, nextSlide]);

  // Hide swipe hint after 5 seconds
  useEffect(() => {
    const timer = setTimeout(() => setShowSwipeHint(false), 5000);
    return () => clearTimeout(timer);
  }, []);

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

  // Swipe handling
  const handleDragEnd = (_: unknown, info: PanInfo) => {
    if (Math.abs(info.offset.x) > SWIPE_THRESHOLD || Math.abs(info.velocity.x) > 500) {
      if (info.offset.x > 0) prevSlide();
      else nextSlide();
    }
  };

  const getCtaLink = (slide: FeatureSlide) => {
    if (slide.id === 'progress' && !isAuthenticated) return '/login';
    return slide.ctaLink;
  };

  const scrollToContent = () => {
    window.scrollBy({ top: window.innerHeight * 0.85, behavior: 'smooth' });
  };

  // Badge text: "Welcome" for welcome slide, "Feature N of 9" for others
  const getBadgeText = () => {
    if (isWelcomeSlide) return 'Welcome';
    // Exclude welcome slide from the feature count
    const featureIndex = featureSlides.slice(1).findIndex(s => s.id === currentSlide.id) + 1;
    return `Feature ${featureIndex} of ${featureSlides.length - 1}`;
  };

  // Personalized headline for welcome slide
  const getHeadline = () => {
    if (isWelcomeSlide && isAuthenticated && user?.first_name) {
      return `Welcome back, ${user.first_name}!`;
    }
    return currentSlide.headline;
  };

  return (
    <section
      className="relative h-[80dvh] sm:h-[88dvh] lg:h-[100dvh] flex flex-col overflow-hidden"
      onMouseEnter={() => setIsHovering(true)}
      onMouseLeave={() => setIsHovering(false)}
      aria-label="Feature showcase"
    >
      {/* Background gradient with crossfade */}
      <AnimatePresence mode="wait">
        <motion.div
          key={currentSlide.id}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
          className={`absolute inset-0 bg-gradient-to-br ${currentSlide.gradient}`}
        />
      </AnimatePresence>

      {/* Subtle dot pattern */}
      <div className="absolute inset-0 opacity-[0.03] bg-[radial-gradient(circle_at_1px_1px,white_1px,transparent_0)] bg-[length:20px_20px]" />

      {/* Floating orbs - hidden on mobile for cleaner look */}
      <div className="hidden sm:block absolute inset-0 overflow-hidden pointer-events-none">
        <motion.div
          animate={{ x: [0, 30, 0], y: [0, -20, 0] }}
          transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
          className="absolute top-1/4 left-[10%] w-48 h-48 lg:w-64 lg:h-64 bg-white/10 rounded-full blur-3xl"
        />
        <motion.div
          animate={{ x: [0, -20, 0], y: [0, 30, 0] }}
          transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut' }}
          className="absolute bottom-1/4 right-[10%] w-56 h-56 lg:w-80 lg:h-80 bg-white/10 rounded-full blur-3xl"
        />
      </div>

      {/* Main content area */}
      <div className="relative flex-1 flex flex-col pt-4 sm:pt-8">
        {/* Slide content */}
        <div className="flex-1 flex items-center justify-center">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentSlide.id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ x: SPRING_GENTLE, opacity: { duration: 0.25 } }}
              drag="x"
              dragConstraints={{ left: 0, right: 0 }}
              dragElastic={0.15}
              dragTransition={{ bounceStiffness: 300, bounceDamping: 20 }}
              onDragEnd={handleDragEnd}
              className="w-full cursor-grab active:cursor-grabbing"
            >
              <div className="max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8">
                <div className="flex flex-col lg:grid lg:grid-cols-2 lg:gap-12 lg:items-center">
                  {/* Visual */}
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ scale: { ...SPRING_SNAPPY, delay: 0.04 }, opacity: { duration: 0.2 } }}
                    className="flex justify-center lg:justify-start mb-2 sm:mb-4 lg:mb-0"
                  >
                    <div className="w-full max-w-[280px] sm:max-w-[320px] lg:max-w-[400px]">
                      {slideVisuals[currentSlide.id] ? (
                        React.createElement(slideVisuals[currentSlide.id])
                      ) : (
                        <div className="aspect-square flex items-center justify-center">
                          <motion.div
                            animate={{ rotate: [0, 5, -5, 0] }}
                            transition={{ duration: 4, repeat: Infinity }}
                            className={`w-20 h-20 sm:w-28 sm:h-28 rounded-2xl bg-gradient-to-br ${currentSlide.iconGradient} shadow-2xl flex items-center justify-center`}
                          >
                            <currentSlide.icon className="w-10 h-10 sm:w-14 sm:h-14 text-white" strokeWidth={1.5} />
                          </motion.div>
                        </div>
                      )}
                    </div>
                  </motion.div>

                  {/* Text content */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ y: { ...SPRING_SNAPPY, delay: 0.08 }, opacity: { duration: 0.2 } }}
                    className="text-center lg:text-left"
                  >
                    {/* Feature badge */}
                    <motion.div
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ scale: SPRING_BOUNCY, opacity: { duration: 0.2 } }}
                      className="inline-flex items-center gap-2 px-3 py-1.5 bg-white/15 backdrop-blur-sm rounded-full text-white/90 text-xs sm:text-sm font-medium mb-2"
                    >
                      <motion.span
                        animate={{ scale: [1, 1.2, 1] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="w-1.5 h-1.5 rounded-full bg-white"
                      />
                      {getBadgeText()}
                    </motion.div>

                    {/* Headline */}
                    <h1 className="text-2xl sm:text-3xl lg:text-4xl xl:text-5xl font-bold text-white mb-1.5 sm:mb-2 leading-tight">
                      {getHeadline()}
                    </h1>

                    {/* Subtext */}
                    <p className="text-sm sm:text-base lg:text-lg text-white/80 mb-3 sm:mb-4 max-w-md mx-auto lg:mx-0">
                      {currentSlide.subtext}
                    </p>

                    {/* CTA Button */}
                    <motion.div
                      whileHover={{ scale: 1.04 }}
                      whileTap={{ scale: 0.97 }}
                      transition={SPRING_SNAPPY}
                      className="inline-block"
                    >
                      <Link
                        to={getCtaLink(currentSlide)}
                        className="group inline-flex items-center gap-2 px-5 sm:px-6 py-2.5 sm:py-3 bg-white text-gray-900 rounded-xl font-semibold text-sm sm:text-base shadow-xl hover:shadow-2xl"
                      >
                        {currentSlide.cta}
                        <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                      </Link>
                    </motion.div>
                  </motion.div>
                </div>
              </div>
            </motion.div>
          </AnimatePresence>
        </div>

        {/* Bottom section - controls + scroll hint */}
        <div className="relative z-10 px-4 sm:px-6 lg:px-8 pb-8 sm:pb-12">
          {/* Swipe hint - mobile only */}
          <AnimatePresence>
            {showSwipeHint && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="sm:hidden flex justify-center mb-4"
              >
                <div className="flex items-center gap-2 px-3 py-1.5 bg-white/10 backdrop-blur-sm rounded-full text-white/70 text-xs">
                  <ChevronLeft className="w-3 h-3" />
                  <span>Swipe to explore</span>
                  <ChevronRight className="w-3 h-3" />
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Controls bar */}
          <div className="max-w-7xl mx-auto flex items-center justify-between">
            {/* Progress dots */}
            <div className="flex items-center gap-1.5 sm:gap-2">
              {featureSlides.map((slide, index) => (
                <motion.button
                  key={slide.id}
                  layout
                  transition={SPRING_SNAPPY}
                  onClick={() => goToSlide(index)}
                  className={`relative h-2 rounded-full ${
                    index === currentIndex
                      ? 'w-6 sm:w-8 bg-white'
                      : 'w-2 bg-white/40 hover:bg-white/60'
                  }`}
                  aria-label={`Go to ${slide.headline}`}
                >
                  {index === currentIndex && !isPaused && !isHovering && (
                    <motion.div
                      key={`progress-${currentIndex}`}
                      initial={{ width: '0%' }}
                      animate={{ width: '100%' }}
                      transition={{ duration: AUTO_ADVANCE_INTERVAL / 1000, ease: 'linear' }}
                      className="absolute inset-0 bg-white/50 rounded-full"
                    />
                  )}
                </motion.button>
              ))}
            </div>

            {/* Navigation controls */}
            <div className="flex items-center gap-1.5 sm:gap-2">
              <motion.button
                whileTap={{ scale: 0.9 }}
                whileHover={{ scale: 1.08 }}
                transition={SPRING_SNAPPY}
                onClick={() => setIsPaused((p) => !p)}
                className="p-2 rounded-full bg-white/10 hover:bg-white/20 text-white"
                aria-label={isPaused ? 'Play' : 'Pause'}
              >
                {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
              </motion.button>
              <motion.button
                whileTap={{ scale: 0.9 }}
                whileHover={{ scale: 1.08 }}
                transition={SPRING_SNAPPY}
                onClick={prevSlide}
                className="p-2 rounded-full bg-white/10 hover:bg-white/20 text-white"
                aria-label="Previous"
              >
                <ChevronLeft className="w-5 h-5" />
              </motion.button>
              <motion.button
                whileTap={{ scale: 0.9 }}
                whileHover={{ scale: 1.08 }}
                transition={SPRING_SNAPPY}
                onClick={nextSlide}
                className="p-2 rounded-full bg-white/10 hover:bg-white/20 text-white"
                aria-label="Next"
              >
                <ChevronRight className="w-5 h-5" />
              </motion.button>
            </div>
          </div>

          {/* Scroll indicator */}
          <motion.button
            onClick={scrollToContent}
            animate={{ y: [0, 6, 0] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
            className="absolute left-1/2 -translate-x-1/2 bottom-4 flex flex-col items-center gap-1 text-white/60 hover:text-white/80 transition-colors cursor-pointer"
          >
            <span className="text-[10px] sm:text-xs font-medium tracking-wider uppercase">Scroll</span>
            <ChevronDown className="w-5 h-5" />
          </motion.button>
        </div>
      </div>

      {/* Wave divider */}
      <div className="absolute bottom-0 left-0 right-0 pointer-events-none">
        <svg
          viewBox="0 0 1440 60"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-6 sm:h-10"
          preserveAspectRatio="none"
        >
          <path
            d="M0 60L48 55C96 50 192 40 288 35C384 30 480 30 576 32.5C672 35 768 40 864 42.5C960 45 1056 45 1152 42.5C1248 40 1344 35 1392 32.5L1440 30V60H0Z"
            fill="currentColor"
            className="text-gray-50 dark:text-slate-900"
          />
        </svg>
      </div>
    </section>
  );
};

export default FeatureShowcaseHero;
