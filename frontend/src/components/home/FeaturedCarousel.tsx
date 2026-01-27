// src/components/home/FeaturedCarousel.tsx
/**
 * Featured Posts Carousel - Premium mobile-first design
 * Animated showcase of top posts with smooth transitions
 */

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence, PanInfo } from 'framer-motion';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import { ChevronLeft, ChevronRight, Calendar, Clock, ArrowRight, Sparkles } from 'lucide-react';
import { resolveImageUrl } from '../../utils/imageUrl';
import { CarouselSkeleton } from './skeletons/CarouselSkeleton';
import { useSiteSettings } from '../../store/useSiteSettingsStore';

interface FeaturedPost {
  id: number;
  title: string;
  slug: string;
  excerpt: string;
  featured_image?: string | null;
  published_at: string | null;
  categories: Array<{ id: number; name: string; color?: string | null; icon?: string | null }>;
  view_count?: number;
}

interface FeaturedCarouselProps {
  limit?: number;
}

const SWIPE_THRESHOLD = 50;

export const FeaturedCarousel: React.FC<FeaturedCarouselProps> = ({ limit }) => {
  const { settings } = useSiteSettings();
  const [posts, setPosts] = useState<FeaturedPost[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [direction, setDirection] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    loadFeaturedPosts();
  }, []);

  // Check for reduced motion preference
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mediaQuery.matches);

    const handleChange = () => setReducedMotion(mediaQuery.matches);
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const loadFeaturedPosts = async () => {
    try {
      const effectiveLimit = limit || settings.carouselLimit || 5;
      const data = await blogApi.getFeatured(effectiveLimit);
      setPosts(data);
    } catch (error) {
      console.error('Failed to load featured posts:', error);
    } finally {
      setLoading(false);
    }
  };

  const nextSlide = useCallback(() => {
    setDirection(1);
    setCurrentIndex((prev) => (prev + 1) % posts.length);
  }, [posts.length]);

  const prevSlide = useCallback(() => {
    setDirection(-1);
    setCurrentIndex((prev) => (prev - 1 + posts.length) % posts.length);
  }, [posts.length]);

  // Auto-play carousel
  useEffect(() => {
    if (posts.length === 0 || !settings.carouselAutoplay) return;
    const interval = setInterval(nextSlide, settings.carouselInterval || 7000);
    return () => clearInterval(interval);
  }, [posts.length, settings.carouselAutoplay, settings.carouselInterval, nextSlide]);

  // Handle swipe gestures for mobile
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

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  if (loading) {
    return <CarouselSkeleton />;
  }

  if (posts.length === 0) {
    return null;
  }

  const slideVariants = {
    enter: (direction: number) => ({
      x: direction > 0 ? '100%' : '-100%',
      opacity: 0,
    }),
    center: {
      x: 0,
      opacity: 1,
      transition: {
        duration: reducedMotion ? 0 : 0.4,
        ease: [0.32, 0.72, 0, 1] as const,
      },
    },
    exit: (direction: number) => ({
      x: direction < 0 ? '100%' : '-100%',
      opacity: 0,
      transition: {
        duration: reducedMotion ? 0 : 0.3,
        ease: [0.32, 0.72, 0, 1] as const,
      },
    }),
  };

  const currentPost = posts[currentIndex];

  return (
    <div className="relative">
      {/* Mobile Card Design */}
      <div className="block lg:hidden">
        <div className="relative overflow-hidden rounded-2xl bg-white dark:bg-slate-800 shadow-xl border border-slate-200 dark:border-slate-700">
          <AnimatePresence mode="wait" custom={direction}>
            <motion.div
              key={currentIndex}
              custom={direction}
              variants={slideVariants}
              initial="enter"
              animate="center"
              exit="exit"
              drag="x"
              dragConstraints={{ left: 0, right: 0 }}
              dragElastic={0.1}
              onDragEnd={handleDragEnd}
              className="cursor-grab active:cursor-grabbing"
            >
              {/* Mobile Image */}
              <div className="relative aspect-[16/10] overflow-hidden">
                {currentPost.featured_image ? (
                  <img
                    src={resolveImageUrl(currentPost.featured_image)}
                    alt={currentPost.title}
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <div className="w-full h-full bg-gradient-to-br from-blue-500 via-indigo-500 to-purple-600 flex items-center justify-center">
                    <Sparkles className="w-16 h-16 text-white/50" />
                  </div>
                )}

                {/* Gradient overlay */}
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-black/20 to-transparent" />

                {/* Category badge on image */}
                {currentPost.categories?.[0] && (
                  <div className="absolute top-4 left-4">
                    <span
                      className="px-3 py-1.5 rounded-full text-xs font-semibold backdrop-blur-sm"
                      style={{
                        backgroundColor: currentPost.categories[0].color
                          ? `${currentPost.categories[0].color}cc`
                          : 'rgba(79, 70, 229, 0.9)',
                        color: '#fff',
                      }}
                    >
                      {currentPost.categories[0].name}
                    </span>
                  </div>
                )}

                {/* Slide counter */}
                <div className="absolute top-4 right-4 px-3 py-1.5 rounded-full bg-black/50 backdrop-blur-sm text-white text-xs font-medium">
                  {currentIndex + 1} / {posts.length}
                </div>
              </div>

              {/* Mobile Content */}
              <div className="p-5">
                {/* Title */}
                <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2 line-clamp-2 leading-tight">
                  {currentPost.title}
                </h3>

                {/* Excerpt */}
                <p className="text-slate-600 dark:text-slate-400 text-sm mb-4 line-clamp-2">
                  {currentPost.excerpt}
                </p>

                {/* Meta + CTA Row */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-500">
                    <div className="flex items-center gap-1">
                      <Calendar size={14} />
                      <span>{currentPost.published_at ? formatDate(currentPost.published_at) : 'Draft'}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock size={14} />
                      <span>5 min</span>
                    </div>
                  </div>

                  <Link
                    to={`/blog/${currentPost.slug}`}
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors"
                  >
                    Read
                    <ArrowRight size={16} />
                  </Link>
                </div>
              </div>
            </motion.div>
          </AnimatePresence>

          {/* Mobile Navigation Dots */}
          <div className="absolute bottom-20 left-0 right-0 flex justify-center gap-1.5 z-10">
            {posts.map((_, index) => (
              <button
                key={index}
                onClick={() => {
                  setDirection(index > currentIndex ? 1 : -1);
                  setCurrentIndex(index);
                }}
                className="p-1.5 touch-manipulation"
                aria-label={`Go to slide ${index + 1}`}
              >
                <div
                  className={`h-1.5 rounded-full transition-all ${
                    index === currentIndex
                      ? 'w-6 bg-blue-600'
                      : 'w-1.5 bg-slate-300 dark:bg-slate-600'
                  }`}
                />
              </button>
            ))}
          </div>
        </div>

        {/* Mobile Arrow Buttons (below card) */}
        {posts.length > 1 && (
          <div className="flex justify-center gap-3 mt-4">
            <button
              onClick={prevSlide}
              className="p-3 bg-white dark:bg-slate-800 rounded-full shadow-md border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
              aria-label="Previous article"
            >
              <ChevronLeft size={20} className="text-slate-700 dark:text-slate-300" />
            </button>
            <button
              onClick={nextSlide}
              className="p-3 bg-white dark:bg-slate-800 rounded-full shadow-md border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
              aria-label="Next article"
            >
              <ChevronRight size={20} className="text-slate-700 dark:text-slate-300" />
            </button>
          </div>
        )}
      </div>

      {/* Desktop Layout */}
      <div className="hidden lg:block">
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-800 dark:to-slate-900 shadow-2xl border border-slate-200 dark:border-slate-700">
          <div className="relative h-[550px]">
            <AnimatePresence initial={false} mode="wait" custom={direction}>
              <motion.div
                key={currentIndex}
                custom={direction}
                variants={slideVariants}
                initial="enter"
                animate="center"
                exit="exit"
                className="absolute inset-0"
              >
                <div className="grid grid-cols-2 h-full">
                  {/* Image Side */}
                  <div className="relative overflow-hidden">
                    {currentPost.featured_image ? (
                      <img
                        src={resolveImageUrl(currentPost.featured_image)}
                        alt={currentPost.title}
                        className="absolute inset-0 w-full h-full object-cover"
                      />
                    ) : (
                      <div className="absolute inset-0 bg-gradient-to-br from-blue-500 via-indigo-500 to-purple-600 flex items-center justify-center">
                        <Sparkles className="w-24 h-24 text-white/30" />
                      </div>
                    )}
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent to-black/20" />
                  </div>

                  {/* Content Side */}
                  <div className="relative flex flex-col justify-center p-12 xl:p-16">
                    {/* Category Badge */}
                    {currentPost.categories?.[0] && (
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.1 }}
                        className="mb-4"
                      >
                        <span
                          className="inline-block px-4 py-1.5 rounded-full text-sm font-semibold"
                          style={{
                            backgroundColor: currentPost.categories[0].color
                              ? `${currentPost.categories[0].color}20`
                              : '#e0e7ff',
                            color: currentPost.categories[0].color || '#4f46e5',
                          }}
                        >
                          {currentPost.categories[0].name}
                        </span>
                      </motion.div>
                    )}

                    {/* Title */}
                    <motion.h2
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.2 }}
                      className="text-3xl xl:text-4xl 2xl:text-5xl font-bold text-slate-900 dark:text-white mb-4 leading-tight"
                    >
                      {currentPost.title}
                    </motion.h2>

                    {/* Excerpt */}
                    <motion.p
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.3 }}
                      className="text-slate-600 dark:text-slate-300 text-lg mb-6 line-clamp-3"
                    >
                      {currentPost.excerpt}
                    </motion.p>

                    {/* Meta Info */}
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.4 }}
                      className="flex items-center gap-6 text-sm text-slate-500 dark:text-slate-400 mb-8"
                    >
                      <div className="flex items-center gap-2">
                        <Calendar size={18} />
                        <span>{currentPost.published_at ? formatDate(currentPost.published_at) : 'Draft'}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Clock size={18} />
                        <span>5 min read</span>
                      </div>
                    </motion.div>

                    {/* CTA Button */}
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.5 }}
                    >
                      <Link
                        to={`/blog/${currentPost.slug}`}
                        className="group inline-flex items-center gap-2 px-8 py-4 bg-blue-600 text-white rounded-xl font-semibold text-lg hover:bg-blue-700 transition-all shadow-lg hover:shadow-xl"
                      >
                        Read Article
                        <ArrowRight size={20} className="group-hover:translate-x-1 transition-transform" />
                      </Link>
                    </motion.div>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>

            {/* Desktop Navigation Arrows */}
            {posts.length > 1 && (
              <>
                <button
                  onClick={prevSlide}
                  className="absolute left-4 top-1/2 -translate-y-1/2 p-3 bg-white/90 dark:bg-slate-800/90 rounded-full shadow-lg hover:bg-white dark:hover:bg-slate-800 transition-colors backdrop-blur-sm z-10"
                  aria-label="Previous slide"
                >
                  <ChevronLeft size={24} className="text-slate-700 dark:text-slate-300" />
                </button>
                <button
                  onClick={nextSlide}
                  className="absolute right-4 top-1/2 -translate-y-1/2 p-3 bg-white/90 dark:bg-slate-800/90 rounded-full shadow-lg hover:bg-white dark:hover:bg-slate-800 transition-colors backdrop-blur-sm z-10"
                  aria-label="Next slide"
                >
                  <ChevronRight size={24} className="text-slate-700 dark:text-slate-300" />
                </button>
              </>
            )}

            {/* Desktop Dots */}
            <div className="absolute bottom-6 left-0 right-0 flex justify-center gap-2 z-10">
              {posts.map((_, index) => (
                <button
                  key={index}
                  onClick={() => {
                    setDirection(index > currentIndex ? 1 : -1);
                    setCurrentIndex(index);
                  }}
                  className="p-1.5"
                  aria-label={`Go to slide ${index + 1}`}
                >
                  <div
                    className={`h-2 rounded-full transition-all ${
                      index === currentIndex
                        ? 'w-8 bg-blue-600'
                        : 'w-2 bg-slate-400 dark:bg-slate-600 hover:bg-slate-500'
                    }`}
                  />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FeaturedCarousel;
