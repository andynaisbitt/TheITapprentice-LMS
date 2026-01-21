// src/components/home/FeaturedCoursesCarousel.tsx
/**
 * Featured Courses Carousel - Homepage component showcasing courses
 * Displays featured courses in a horizontal scrollable carousel
 */

import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
  GraduationCap,
  Clock,
  Users,
  ChevronLeft,
  ChevronRight,
  Star,
  BookOpen,
  Play,
  Loader2,
} from 'lucide-react';
import { coursesApi } from '../../plugins/courses/services/coursesApi';
import type { Course } from '../../plugins/courses/types';

const LEVEL_COLORS = {
  beginner: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  intermediate: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  advanced: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
};

export const FeaturedCoursesCarousel: React.FC = () => {
  const [courses, setCourses] = useState<Course[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(true);

  useEffect(() => {
    const fetchCourses = async () => {
      try {
        const response = await coursesApi.getCourses({
          is_featured: true,
          status: 'published',
          page_size: 10,
        });
        setCourses(response.courses);
      } catch {
        setError('Failed to load courses');
      } finally {
        setLoading(false);
      }
    };

    fetchCourses();
  }, []);

  const checkScrollButtons = () => {
    if (scrollContainerRef.current) {
      const { scrollLeft, scrollWidth, clientWidth } = scrollContainerRef.current;
      setCanScrollLeft(scrollLeft > 0);
      setCanScrollRight(scrollLeft < scrollWidth - clientWidth - 10);
    }
  };

  useEffect(() => {
    checkScrollButtons();
    const container = scrollContainerRef.current;
    if (container) {
      container.addEventListener('scroll', checkScrollButtons);
      window.addEventListener('resize', checkScrollButtons);
      return () => {
        container.removeEventListener('scroll', checkScrollButtons);
        window.removeEventListener('resize', checkScrollButtons);
      };
    }
  }, [courses]);

  const scroll = (direction: 'left' | 'right') => {
    if (scrollContainerRef.current) {
      const scrollAmount = 360; // Card width + gap
      const newScroll =
        scrollContainerRef.current.scrollLeft +
        (direction === 'left' ? -scrollAmount : scrollAmount);
      scrollContainerRef.current.scrollTo({
        left: newScroll,
        behavior: 'smooth',
      });
    }
  };

  if (loading) {
    return (
      <section className="py-8">
        <div className="flex items-center justify-center h-64">
          <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
        </div>
      </section>
    );
  }

  if (error || courses.length === 0) {
    return null; // Hide section if no courses
  }

  return (
    <section className="bg-white dark:bg-gray-800 py-12 sm:py-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <GraduationCap className="w-7 h-7 text-indigo-600 dark:text-indigo-400" />
              <h2 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
                Featured Courses
              </h2>
            </div>
            <p className="text-gray-600 dark:text-gray-400">
              Structured learning paths to master new skills
            </p>
          </div>

          {/* Navigation buttons */}
          <div className="hidden sm:flex items-center gap-2">
            <button
              onClick={() => scroll('left')}
              disabled={!canScrollLeft}
              className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              aria-label="Scroll left"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <button
              onClick={() => scroll('right')}
              disabled={!canScrollRight}
              className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              aria-label="Scroll right"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Carousel */}
        <div className="relative">
          <div
            ref={scrollContainerRef}
            className="flex gap-6 overflow-x-auto scrollbar-hide pb-4 snap-x snap-mandatory"
            style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
          >
            {courses.map((course, index) => (
              <CourseCard key={course.id} course={course} index={index} />
            ))}

            {/* View All Card */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: courses.length * 0.1 }}
              className="flex-shrink-0 w-[320px] snap-center"
            >
              <Link
                to="/courses"
                className="group flex flex-col items-center justify-center h-full min-h-[380px] rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600 hover:border-indigo-400 dark:hover:border-indigo-500 transition-colors"
              >
                <div className="p-4 bg-gray-100 dark:bg-gray-700 rounded-full mb-4 group-hover:bg-indigo-100 dark:group-hover:bg-indigo-900/30 transition-colors">
                  <BookOpen className="w-8 h-8 text-gray-500 dark:text-gray-400 group-hover:text-indigo-600 dark:group-hover:text-indigo-400" />
                </div>
                <span className="text-lg font-semibold text-gray-700 dark:text-gray-300 group-hover:text-indigo-600 dark:group-hover:text-indigo-400">
                  View All Courses
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  Explore our full catalog
                </span>
              </Link>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
};

// Individual course card
interface CourseCardProps {
  course: Course;
  index: number;
}

const CourseCard: React.FC<CourseCardProps> = ({ course, index }) => {
  // Defensive: default to 'beginner' if level is undefined
  const level = course.level || 'beginner';
  const levelClass = LEVEL_COLORS[level] || LEVEL_COLORS.beginner;

  // Defensive: format level display safely
  const levelDisplay = level.charAt(0).toUpperCase() + level.slice(1);

  // Defensive: default enrollment count to 0
  const enrollmentCount = course.enrollment_count ?? 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.1 }}
      className="flex-shrink-0 w-[320px] snap-center"
    >
      <Link
        to={`/courses/${course.id}`}
        className="group block bg-white dark:bg-gray-900 rounded-xl shadow-md hover:shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden transition-all duration-300"
      >
        {/* Course Image */}
        <div className="relative h-40 bg-gradient-to-br from-indigo-500 to-purple-600 overflow-hidden">
          {course.image ? (
            <img
              src={course.image}
              alt={course.title || 'Course'}
              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
            />
          ) : (
            <div className="absolute inset-0 flex items-center justify-center">
              <GraduationCap className="w-16 h-16 text-white/30" />
            </div>
          )}
          {/* Overlay on hover */}
          <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center opacity-0 group-hover:opacity-100">
            <div className="p-3 bg-white/90 rounded-full">
              <Play className="w-6 h-6 text-indigo-600" />
            </div>
          </div>
          {/* Premium badge */}
          {course.is_premium && (
            <div className="absolute top-3 right-3 px-2 py-1 bg-yellow-400 text-yellow-900 text-xs font-bold rounded-full flex items-center gap-1">
              <Star className="w-3 h-3 fill-current" />
              Premium
            </div>
          )}
        </div>

        {/* Content */}
        <div className="p-4">
          {/* Level badge */}
          <div className="mb-2">
            <span
              className={`px-2 py-0.5 text-xs font-medium rounded-full ${levelClass}`}
            >
              {levelDisplay}
            </span>
          </div>

          {/* Title */}
          <h3 className="font-semibold text-gray-900 dark:text-white mb-2 line-clamp-2 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
            {course.title || 'Untitled Course'}
          </h3>

          {/* Short description */}
          {course.short_description && (
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3 line-clamp-2">
              {course.short_description}
            </p>
          )}

          {/* Stats */}
          <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
            {course.estimated_hours != null && (
              <span className="flex items-center gap-1">
                <Clock className="w-4 h-4" />
                {course.estimated_hours}h
              </span>
            )}
            <span className="flex items-center gap-1">
              <Users className="w-4 h-4" />
              {enrollmentCount.toLocaleString()}
            </span>
            {course.modules && course.modules.length > 0 && (
              <span className="flex items-center gap-1">
                <BookOpen className="w-4 h-4" />
                {course.modules.length} modules
              </span>
            )}
          </div>

          {/* XP reward */}
          {course.xp_reward != null && course.xp_reward > 0 && (
            <div className="mt-3 pt-3 border-t border-gray-100 dark:border-gray-700">
              <span className="text-sm font-medium text-indigo-600 dark:text-indigo-400">
                +{course.xp_reward} XP on completion
              </span>
            </div>
          )}
        </div>
      </Link>
    </motion.div>
  );
};

export default FeaturedCoursesCarousel;
