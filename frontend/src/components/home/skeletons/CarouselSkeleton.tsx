// src/components/home/skeletons/CarouselSkeleton.tsx
/**
 * Skeleton loader for FeaturedCarousel
 * Matches the carousel layout for smooth loading experience
 */

export const CarouselSkeleton: React.FC = () => {
  return (
    <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-gray-200 to-gray-300 dark:from-gray-800 dark:to-gray-900 shadow-2xl h-96 lg:h-[600px] animate-pulse">
      <div className="grid grid-cols-1 lg:grid-cols-2 h-full">
        {/* Image Skeleton */}
        <div className="relative overflow-hidden min-h-[300px] lg:min-h-0 bg-gradient-to-br from-gray-300 to-gray-400 dark:from-gray-700 dark:to-gray-800" />

        {/* Content Skeleton */}
        <div className="flex flex-col justify-center p-6 sm:p-8 md:p-12 lg:p-16 space-y-4">
          {/* Category badge skeleton */}
          <div className="h-7 bg-gray-300 dark:bg-gray-700 rounded-full w-24" />

          {/* Title skeleton (2 lines) */}
          <div className="space-y-3">
            <div className="h-10 bg-gray-300 dark:bg-gray-700 rounded w-full" />
            <div className="h-10 bg-gray-300 dark:bg-gray-700 rounded w-4/5" />
          </div>

          {/* Excerpt skeleton (3 lines) */}
          <div className="space-y-2 pt-2">
            <div className="h-5 bg-gray-300 dark:bg-gray-700 rounded w-full" />
            <div className="h-5 bg-gray-300 dark:bg-gray-700 rounded w-full" />
            <div className="h-5 bg-gray-300 dark:bg-gray-700 rounded w-2/3" />
          </div>

          {/* Meta info skeleton */}
          <div className="flex items-center gap-4 pt-2">
            <div className="h-4 bg-gray-300 dark:bg-gray-700 rounded w-24" />
            <div className="h-4 bg-gray-300 dark:bg-gray-700 rounded w-20" />
          </div>

          {/* Button skeleton */}
          <div className="h-12 bg-gray-300 dark:bg-gray-700 rounded-lg w-32 mt-4" />
        </div>
      </div>
    </div>
  );
};

export default CarouselSkeleton;
