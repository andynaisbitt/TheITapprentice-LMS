// frontend/src/plugins/tutorials/components/TutorialCard.tsx
/**
 * Tutorial Card Component
 * Displays a single tutorial in a card format for browse/list views
 */
import React from 'react';
import { Link } from 'react-router-dom';
import type { TutorialListItem } from '../types';

interface TutorialCardProps {
  tutorial: TutorialListItem;
}

const difficultyColors = {
  beginner: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
  intermediate: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
  advanced: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
};

export const TutorialCard: React.FC<TutorialCardProps> = ({ tutorial }) => {
  const {
    slug,
    title,
    description,
    difficulty,
    estimated_time_minutes,
    category,
    thumbnail_url,
    xp_reward,
    related_skills,
    view_count,
    completion_count,
    user_progress_percentage,
    user_completed,
  } = tutorial;

  return (
    <Link
      to={`/tutorials/${slug}`}
      className="block bg-white dark:bg-gray-800 rounded-lg shadow-md hover:shadow-xl transition-all duration-200 overflow-hidden group"
    >
      {/* Thumbnail */}
      <div className="relative h-48 bg-gradient-to-br from-blue-500 to-purple-600 overflow-hidden">
        {thumbnail_url ? (
          <img
            src={thumbnail_url}
            alt={title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center text-white text-6xl font-bold opacity-20">
            {title.charAt(0)}
          </div>
        )}

        {/* Progress overlay (if user started) */}
        {user_progress_percentage !== undefined && user_progress_percentage !== null && (
          <div className="absolute bottom-0 left-0 right-0 bg-black bg-opacity-60">
            <div className="px-4 py-2 flex items-center justify-between text-white text-sm">
              <span>{user_progress_percentage}% complete</span>
              {user_completed && (
                <span className="px-2 py-1 bg-green-500 rounded text-xs font-semibold">
                  ✓ Completed
                </span>
              )}
            </div>
            <div className="h-1 bg-gray-700">
              <div
                className="h-full bg-gradient-to-r from-green-400 to-blue-500 transition-all"
                style={{ width: `${user_progress_percentage}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Content */}
      <div className="p-5">
        {/* Category & Difficulty */}
        <div className="flex items-center gap-2 mb-3">
          {category && (
            <span
              className="px-2 py-1 rounded text-xs font-medium"
              style={{
                backgroundColor: category.color || '#3B82F6',
                color: 'white',
              }}
            >
              {category.icon && <span className="mr-1">{category.icon}</span>}
              {category.name}
            </span>
          )}
          <span className={`px-2 py-1 rounded text-xs font-medium ${difficultyColors[difficulty]}`}>
            {difficulty}
          </span>
        </div>

        {/* Title */}
        <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
          {title}
        </h3>

        {/* Description */}
        {description && (
          <p className="text-gray-600 dark:text-gray-400 text-sm mb-4 line-clamp-2">
            {description}
          </p>
        )}

        {/* Skills */}
        {related_skills && related_skills.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-4">
            {related_skills.slice(0, 3).map((skill, idx) => (
              <span
                key={idx}
                className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded text-xs"
              >
                {skill}
              </span>
            ))}
            {related_skills.length > 3 && (
              <span className="px-2 py-1 text-gray-500 dark:text-gray-400 text-xs">
                +{related_skills.length - 3} more
              </span>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 pt-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-4">
            {estimated_time_minutes && (
              <span className="flex items-center gap-1">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {estimated_time_minutes}m
              </span>
            )}
            <span className="flex items-center gap-1">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              {view_count}
            </span>
          </div>
          <div className="flex items-center gap-1 font-semibold text-yellow-600 dark:text-yellow-400">
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
            </svg>
            +{xp_reward} XP
          </div>
        </div>
      </div>
    </Link>
  );
};
