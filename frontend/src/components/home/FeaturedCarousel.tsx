// src/components/home/FeaturedCarousel.tsx
/**
 * Featured Posts Carousel - Animated showcase of top posts
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import { ChevronLeft, ChevronRight, Calendar, Clock, ArrowRight } from 'lucide-react';
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

export const FeaturedCarousel: React.FC<FeaturedCarouselProps> = ({ limit }) => {
  const { settings } = useSiteSettings();
  const [posts, setPosts] = useState<FeaturedPost[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [direction, setDirection] = useState(0);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 1024);

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

  // Update isMobile on window resize
  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 1024);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
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

  const nextSlide = () => {
    setDirection(1);
    setCurrentIndex((prev) => (prev + 1) % posts.length);
  };

  const prevSlide = () => {
    setDirection(-1);
    setCurrentIndex((prev) => (prev - 1 + posts.length) % posts.length);
  };

  // Auto-play carousel with configurable interval
  useEffect(() => {
    if (posts.length === 0 || !settings.carouselAutoplay) return;
    const interval = setInterval(nextSlide, settings.carouselInterval || 7000);
    return () => clearInterval(interval);
  }, [posts.length, settings.carouselAutoplay, settings.carouselInterval]);

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

  // Crossfade animation variants for smooth transitions
  // Mobile: opacity-only (no scale to prevent GPU glitches)
  // Desktop: subtle scale for elegance
  const crossfadeVariants = {
    enter: {
      opacity: 0,
      scale: isMobile ? 1 : 1.02, // Reduced scale, mobile gets none
      zIndex: 0,
    },
    center: {
      opacity: 1,
      scale: 1,
      zIndex: 1,
    },
    exit: {
      opacity: 0,
      scale: isMobile ? 1 : 0.98, // Reduced scale, mobile gets none
      zIndex: 0,
    },
  };

  const currentPost = posts[currentIndex];

  return (
    <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-indigo-50 to-purple-50 dark:from-gray-800 dark:to-gray-900 shadow-2xl">
      <div className="relative lg:h-[600px]">
        <AnimatePresence initial={false} mode="wait">
          <motion.div
            key={currentIndex}
            variants={crossfadeVariants}
            initial="enter"
            animate="center"
            exit="exit"
            transition={{
              duration: reducedMotion ? 0 : (isMobile ? 0.4 : 0.6), // Faster on mobile
              ease: [0.32, 0.72, 0, 1], // Smoother easing for mobile
            }}
            className="lg:absolute lg:inset-0"
          >
            <div className="grid grid-cols-1 lg:grid-cols-2 lg:h-full">
              {/* Image Side */}
              <div className="relative overflow-hidden min-h-[300px] lg:min-h-0">
                {currentPost.featured_image ? (
                  <img
                    src={resolveImageUrl(currentPost.featured_image)}
                    alt={currentPost.title}
                    className="absolute inset-0 w-full h-full object-cover"
                  />
                ) : (
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500"></div>
                )}
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-black/20 to-transparent lg:bg-gradient-to-r"></div>
              </div>

              {/* Content Side */}
              <div className="relative flex flex-col justify-center p-6 sm:p-8 md:p-12 lg:p-16 z-10">
                {/* Category Badge */}
                {currentPost.categories && currentPost.categories[0] && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
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
                  transition={{ delay: 0.3 }}
                  className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-white mb-3 sm:mb-4 leading-tight"
                >
                  {currentPost.title}
                </motion.h2>

                {/* Excerpt */}
                <motion.p
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 }}
                  className="text-gray-600 dark:text-gray-300 text-base sm:text-lg mb-4 sm:mb-6 line-clamp-2 sm:line-clamp-3"
                >
                  {currentPost.excerpt}
                </motion.p>

                {/* Meta Info */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.5 }}
                  className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400 mb-8"
                >
                  <div className="flex items-center gap-1.5">
                    <Calendar size={16} />
                    <span>{currentPost.published_at ? formatDate(currentPost.published_at) : 'Draft'}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Clock size={16} />
                    <span>5 min read</span>
                  </div>
                </motion.div>

                {/* CTA Button */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.6 }}
                  className="relative z-10"
                >
                  <Link
                    to={`/blog/${currentPost.slug}`}
                    className="group inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-all shadow-lg hover:shadow-xl touch-manipulation"
                  >
                    <span>Read Article</span>
                    <ArrowRight
                      size={20}
                      className="group-hover:translate-x-1 transition-transform"
                    />
                  </Link>
                </motion.div>
              </div>
            </div>
          </motion.div>
        </AnimatePresence>

        {/* Navigation Arrows - Mobile Optimized with fixed positioning */}
        {posts.length > 1 && (
          <div className="absolute inset-0 pointer-events-none z-20">
            <div className="relative h-full flex items-center justify-between px-2 sm:px-4">
              <button
                onClick={prevSlide}
                className="pointer-events-auto p-3 sm:p-3.5 bg-white/95 dark:bg-gray-800/95 rounded-full shadow-xl hover:bg-white dark:hover:bg-gray-800 transition-colors backdrop-blur-sm touch-manipulation active:scale-90"
                aria-label="Previous slide"
              >
                <ChevronLeft size={20} className="sm:w-6 sm:h-6 text-gray-700 dark:text-gray-300" />
              </button>
              <button
                onClick={nextSlide}
                className="pointer-events-auto p-3 sm:p-3.5 bg-white/95 dark:bg-gray-800/95 rounded-full shadow-xl hover:bg-white dark:hover:bg-gray-800 transition-colors backdrop-blur-sm touch-manipulation active:scale-90"
                aria-label="Next slide"
              >
                <ChevronRight size={20} className="sm:w-6 sm:h-6 text-gray-700 dark:text-gray-300" />
              </button>
            </div>
          </div>
        )}

        {/* Dots Indicator - Mobile Optimized with larger touch targets */}
        <div className="absolute bottom-4 sm:bottom-6 left-0 right-0 flex justify-center gap-1 sm:gap-2 z-10">
          {posts.map((_, index) => (
            <button
              key={index}
              onClick={() => {
                setDirection(index > currentIndex ? 1 : -1);
                setCurrentIndex(index);
              }}
              className={`touch-manipulation p-2 transition-all active:scale-95`}
              aria-label={`Go to slide ${index + 1}`}
            >
              <div
                className={`h-2 rounded-full transition-all ${
                  index === currentIndex
                    ? 'w-8 bg-blue-600 dark:bg-blue-500'
                    : 'w-2 bg-gray-400 dark:bg-gray-500'
                }`}
              />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default FeaturedCarousel;
