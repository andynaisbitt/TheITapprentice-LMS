// src/pages/courses/CoursesList.tsx
/**
 * Courses List Page - Backend Connected
 * Displays all available courses from database
 * Supports light/dark mode
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  BookOpen,
  Clock,
  Users,
  Star,
  TrendingUp,
  Search,
  ChevronRight,
  Award,
  Target,
  Zap,
  GraduationCap
} from 'lucide-react';
import { coursesApi } from '../../services/coursesApi';
import { Course, CourseLevel, CourseFilters } from '../../types';

// Placeholder components until fully implemented
const XPBadge: React.FC<{ xp?: number; size?: string; variant?: string; showLabel?: boolean }> = ({ xp }) =>
  xp ? <span className="text-xs bg-purple-100 dark:bg-purple-900/50 text-purple-700 dark:text-purple-300 px-2 py-1 rounded-full font-medium">{xp} XP</span> : null;

const SkillBadges: React.FC<{ skills?: string[]; limit?: number; size?: string; showIcon?: boolean }> = ({ skills, limit }) => {
  const displaySkills = limit ? skills?.slice(0, limit) : skills;
  return displaySkills?.length ? (
    <div className="flex gap-1.5 flex-wrap">
      {displaySkills.map(s => (
        <span key={s} className="text-xs bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300 px-2 py-1 rounded-md">
          {s}
        </span>
      ))}
    </div>
  ) : null;
};

const CategoryBadge: React.FC<{ category?: string; categoryId?: number; size?: string }> = ({ category }) =>
  category ? <span className="text-xs bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 px-2 py-1 rounded-md font-medium">{category}</span> : null;

const DailyChallengesWidget: React.FC<{ variant?: string }> = () => null;

const CoursesList: React.FC = () => {
  const navigate = useNavigate();
  const [courses, setCourses] = useState<Course[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<CourseFilters>({
    page: 1,
    page_size: 12
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [totalCourses, setTotalCourses] = useState(0);

  // Fetch courses from backend
  useEffect(() => {
    const fetchCourses = async () => {
      try {
        setIsLoading(true);
        setError(null);

        const response = await coursesApi.getCourses(filters);
        setCourses(response.courses);
        setTotalCourses(response.total);
      } catch (err: any) {
        console.error('Error fetching courses:', err);
        setError('Failed to load courses. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchCourses();
  }, [filters]);

  // Handle search
  const handleSearch = (query: string) => {
    setSearchQuery(query);
    setFilters(prev => ({ ...prev, search: query, page: 1 }));
  };

  // Handle level filter
  const handleLevelFilter = (level: CourseLevel | undefined) => {
    setFilters(prev => ({ ...prev, level, page: 1 }));
  };

  // Get level badge styles (works in both light and dark)
  const getLevelColor = (level: CourseLevel) => {
    switch (level) {
      case 'beginner':
        return 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30';
      case 'intermediate':
        return 'bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30';
      case 'advanced':
        return 'bg-rose-100 dark:bg-rose-500/20 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30';
      default:
        return 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-500/30';
    }
  };

  // Get level icon
  const getLevelIcon = (level: CourseLevel) => {
    switch (level) {
      case 'beginner': return <Target size={14} />;
      case 'intermediate': return <TrendingUp size={14} />;
      case 'advanced': return <Zap size={14} />;
      default: return <BookOpen size={14} />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/30 dark:from-slate-900 dark:via-blue-900/10 dark:to-purple-900/10">
      <div className="max-w-7xl mx-auto px-4 py-12">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          {/* Icon */}
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 text-white mb-6 shadow-lg shadow-blue-500/25">
            <GraduationCap size={32} />
          </div>

          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4">
            Explore Our{' '}
            <span className="bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-purple-500 bg-clip-text text-transparent">
              Courses
            </span>
          </h1>
          <p className="text-lg text-slate-600 dark:text-slate-300 max-w-3xl mx-auto">
            Master IT skills with expert-designed courses. Learn at your own pace with hands-on projects.
          </p>

          {/* Stats */}
          <div className="mt-8 flex items-center justify-center gap-8 text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-2">
              <BookOpen size={20} className="text-blue-500 dark:text-blue-400" />
              <span className="font-medium">{totalCourses} Courses</span>
            </div>
            <div className="flex items-center gap-2">
              <Users size={20} className="text-indigo-500 dark:text-purple-400" />
              <span className="font-medium">Expert Instructors</span>
            </div>
            <div className="flex items-center gap-2">
              <Award size={20} className="text-emerald-500 dark:text-green-400" />
              <span className="font-medium">Certificates</span>
            </div>
          </div>
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white/80 dark:bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 mb-8 border border-slate-200 dark:border-slate-700/50 shadow-sm"
        >
          <div className="flex flex-col md:flex-row gap-4 items-center">
            {/* Search */}
            <div className="flex-1 w-full">
              <div className="relative">
                <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-slate-400" size={20} />
                <input
                  type="text"
                  placeholder="Search courses..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700 rounded-xl
                           text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500
                           focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                />
              </div>
            </div>

            {/* Level Filter */}
            <div className="flex gap-2 flex-wrap justify-center">
              <button
                onClick={() => handleLevelFilter(undefined)}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  !filters.level
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-500/25'
                    : 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                All
              </button>
              <button
                onClick={() => handleLevelFilter('beginner')}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  filters.level === 'beginner'
                    ? 'bg-emerald-500 text-white shadow-md shadow-emerald-500/25'
                    : 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                Beginner
              </button>
              <button
                onClick={() => handleLevelFilter('intermediate')}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  filters.level === 'intermediate'
                    ? 'bg-amber-500 text-white shadow-md shadow-amber-500/25'
                    : 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                Intermediate
              </button>
              <button
                onClick={() => handleLevelFilter('advanced')}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  filters.level === 'advanced'
                    ? 'bg-rose-500 text-white shadow-md shadow-rose-500/25'
                    : 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                Advanced
              </button>
            </div>
          </div>
        </motion.div>

        {/* Loading State */}
        {isLoading && (
          <div className="flex justify-center items-center py-20">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-2xl p-6 text-center">
            <p className="text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        {/* Daily Challenges Widget */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mb-8"
        >
          <DailyChallengesWidget variant="compact" />
        </motion.div>

        {/* Courses Grid */}
        {!isLoading && !error && courses.length > 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          >
            {courses.map((course, index) => (
              <motion.div
                key={course.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                whileHover={{ y: -8, scale: 1.02 }}
                onClick={() => navigate(`/courses/${course.id}`)}
                className="bg-white dark:bg-gradient-to-br dark:from-slate-800/80 dark:to-slate-900/80 rounded-2xl
                         overflow-hidden border border-slate-200 dark:border-slate-700/50
                         hover:border-blue-300 dark:hover:border-blue-500/50
                         cursor-pointer transition-all duration-300 group shadow-sm hover:shadow-lg"
              >
                {/* Course Image */}
                <div className="relative h-48 bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-500/20 dark:to-purple-500/20 overflow-hidden">
                  {course.image ? (
                    <img
                      src={course.image}
                      alt={course.title}
                      className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center">
                      <BookOpen size={64} className="text-blue-400 dark:text-blue-400 opacity-50" />
                    </div>
                  )}

                  {/* Level Badge */}
                  <div className="absolute top-4 left-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium border flex items-center gap-1 backdrop-blur-sm ${getLevelColor(course.level)}`}>
                      {getLevelIcon(course.level)}
                      {course.level}
                    </span>
                  </div>

                  {/* Premium Badge */}
                  {course.is_premium && (
                    <div className="absolute top-4 right-4">
                      <span className="px-3 py-1 rounded-full text-xs font-medium bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-500/30 flex items-center gap-1 backdrop-blur-sm">
                        <Star size={12} />
                        Premium
                      </span>
                    </div>
                  )}
                </div>

                {/* Course Content */}
                <div className="p-6">
                  <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2 line-clamp-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                    {course.title}
                  </h3>

                  <p className="text-slate-500 dark:text-slate-400 text-sm mb-4 line-clamp-2">
                    {course.short_description || course.description}
                  </p>

                  {/* Stats */}
                  <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400 mb-4">
                    <div className="flex items-center gap-1">
                      <Clock size={14} />
                      <span>{course.estimated_hours}h</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Users size={14} />
                      <span>{course.enrollment_count} enrolled</span>
                    </div>
                    {course.difficulty_rating > 0 && (
                      <div className="flex items-center gap-1">
                        <Star size={14} className="fill-amber-400 text-amber-400" />
                        <span>{course.difficulty_rating}/5</span>
                      </div>
                    )}
                  </div>

                  {/* XP Reward */}
                  <div className="mb-3">
                    <XPBadge xp={course.xp_reward} size="medium" variant="prominent" showLabel />
                  </div>

                  {/* Category Badge */}
                  {course.category_id && (
                    <div className="mb-3">
                      <CategoryBadge categoryId={course.category_id} size="small" />
                    </div>
                  )}

                  {/* Skills Tags */}
                  {(course.related_skills && course.related_skills.length > 0) && (
                    <div className="mb-4">
                      <SkillBadges skills={course.related_skills} limit={3} size="small" showIcon />
                    </div>
                  )}

                  {/* Action Button */}
                  <button className="w-full px-4 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-500 dark:to-purple-500
                                   text-white font-semibold rounded-xl hover:from-blue-700 hover:to-indigo-700
                                   dark:hover:from-blue-600 dark:hover:to-purple-600
                                   transition-all flex items-center justify-center gap-2
                                   group-hover:gap-4 duration-300 shadow-md shadow-blue-500/25">
                    View Course
                    <ChevronRight size={18} />
                  </button>
                </div>
              </motion.div>
            ))}
          </motion.div>
        )}

        {/* Empty State */}
        {!isLoading && !error && courses.length === 0 && (
          <div className="text-center py-20">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-slate-100 dark:bg-slate-800 mb-6">
              <BookOpen size={40} className="text-slate-400" />
            </div>
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">No Courses Found</h3>
            <p className="text-slate-500 dark:text-slate-400 max-w-md mx-auto">
              {searchQuery || filters.level || filters.category
                ? 'Try adjusting your filters or search query'
                : 'Courses will appear here once they are added to the system'}
            </p>
          </div>
        )}

        {/* Pagination */}
        {totalCourses > (filters.page_size || 12) && (
          <div className="flex justify-center mt-12 gap-2">
            <button
              onClick={() => setFilters(prev => ({ ...prev, page: Math.max(1, (prev.page || 1) - 1) }))}
              disabled={(filters.page || 1) === 1}
              className="px-4 py-2 bg-white dark:bg-slate-800 text-slate-700 dark:text-white rounded-lg
                       border border-slate-200 dark:border-slate-700
                       disabled:opacity-50 disabled:cursor-not-allowed
                       hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              Previous
            </button>
            <span className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium">
              Page {filters.page || 1}
            </span>
            <button
              onClick={() => setFilters(prev => ({ ...prev, page: (prev.page || 1) + 1 }))}
              disabled={(filters.page || 1) * (filters.page_size || 12) >= totalCourses}
              className="px-4 py-2 bg-white dark:bg-slate-800 text-slate-700 dark:text-white rounded-lg
                       border border-slate-200 dark:border-slate-700
                       disabled:opacity-50 disabled:cursor-not-allowed
                       hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default CoursesList;
