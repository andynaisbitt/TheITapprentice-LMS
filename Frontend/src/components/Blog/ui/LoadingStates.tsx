import React from 'react';

interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'rectangular' | 'circular';
  width?: string | number;
  height?: string | number;
  lines?: number;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  className = '',
  variant = 'text',
  width,
  height,
  lines = 1
}) => {
  const getVariantClasses = () => {
    switch (variant) {
      case 'circular':
        return 'rounded-full';
      case 'rectangular':
        return 'rounded';
      default:
        return 'rounded-sm';
    }
  };

  const baseClasses = `animate-pulse bg-muted ${getVariantClasses()} ${className}`;
  
  const style = {
    width: typeof width === 'number' ? `${width}px` : width,
    height: typeof height === 'number' ? `${height}px` : height
  };

  if (lines > 1) {
    return (
      <div className="space-y-2">
        {Array.from({ length: lines }, (_, index) => (
          <div
            key={index}
            className={`${baseClasses} ${index === lines - 1 ? 'w-3/4' : 'w-full'}`}
            style={index === 0 ? style : { height: style.height }}
          />
        ))}
      </div>
    );
  }

  return <div className={baseClasses} style={style} />;
};

interface BlogCardSkeletonProps {
  variant?: 'default' | 'featured' | 'compact';
}

export const BlogCardSkeleton: React.FC<BlogCardSkeletonProps> = ({ 
  variant = 'default' 
}) => {
  if (variant === 'compact') {
    return (
      <div className="flex gap-4 p-4 bg-card rounded-lg border border-border">
        <Skeleton variant="rectangular" width={80} height={80} className="flex-shrink-0" />
        <div className="flex-1 space-y-3">
          <Skeleton height={16} className="w-full" />
          <Skeleton height={16} className="w-3/4" />
          <div className="flex gap-2">
            <Skeleton height={12} width={60} />
            <Skeleton height={12} width={40} />
          </div>
        </div>
      </div>
    );
  }

  if (variant === 'featured') {
    return (
      <div className="bg-card rounded-lg border border-border overflow-hidden">
        <Skeleton variant="rectangular" height={256} className="w-full" />
        <div className="p-6 space-y-4">
          <div className="flex gap-2">
            <Skeleton height={20} width={60} className="rounded-full" />
            <Skeleton height={20} width={80} className="rounded-full" />
            <Skeleton height={20} width={70} className="rounded-full" />
          </div>
          <Skeleton height={24} lines={2} />
          <Skeleton height={16} lines={3} />
          <div className="flex items-center justify-between pt-4">
            <div className="flex items-center gap-3">
              <Skeleton variant="circular" width={32} height={32} />
              <div className="space-y-1">
                <Skeleton height={14} width={80} />
                <Skeleton height={12} width={60} />
              </div>
            </div>
            <Skeleton height={16} width={60} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg border border-border overflow-hidden">
      <Skeleton variant="rectangular" height={192} className="w-full" />
      <div className="p-6 space-y-4">
        <div className="flex gap-2">
          <Skeleton height={20} width={60} className="rounded-full" />
          <Skeleton height={20} width={80} className="rounded-full" />
        </div>
        <Skeleton height={20} lines={2} />
        <Skeleton height={16} lines={2} />
        <div className="flex items-center justify-between pt-4 border-t border-border">
          <div className="flex items-center gap-3">
            <Skeleton variant="circular" width={32} height={32} />
            <Skeleton height={14} width={80} />
          </div>
          <Skeleton height={14} width={60} />
        </div>
      </div>
    </div>
  );
};

interface BlogGridSkeletonProps {
  count?: number;
  variant?: 'default' | 'featured' | 'compact';
  columns?: 1 | 2 | 3 | 4;
}

export const BlogGridSkeleton: React.FC<BlogGridSkeletonProps> = ({
  count = 6,
  variant = 'default',
  columns = 3
}) => {
  const getGridClasses = () => {
    const columnClasses = {
      1: 'grid-cols-1',
      2: 'grid-cols-1 sm:grid-cols-2',
      3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
      4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
    };
    return variant === 'compact' ? 'flex flex-col gap-6' : `grid ${columnClasses[columns]} gap-8`;
  };

  return (
    <div className={getGridClasses()}>
      {Array.from({ length: count }, (_, index) => (
        <BlogCardSkeleton 
          key={index} 
          variant={index === 0 && variant === 'featured' ? 'featured' : variant} 
        />
      ))}
    </div>
  );
};

interface SearchBarSkeletonProps {
  showFilters?: boolean;
}

export const SearchBarSkeleton: React.FC<SearchBarSkeletonProps> = ({ 
  showFilters = true 
}) => {
  return (
    <div className="space-y-6">
      <div className="max-w-lg mx-auto">
        <Skeleton height={48} className="w-full rounded-lg" />
      </div>
      
      {showFilters && (
        <div className="flex justify-center">
          <div className="flex gap-3">
            {Array.from({ length: 5 }, (_, index) => (
              <Skeleton 
                key={index} 
                height={32} 
                width={80 + Math.random() * 40} 
                className="rounded-full" 
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = 'md', 
  className = '' 
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12'
  };

  return (
    <div className={`animate-spin rounded-full border-2 border-muted border-t-primary ${sizeClasses[size]} ${className}`} />
  );
};

interface LoadingOverlayProps {
  isLoading: boolean;
  children: React.ReactNode;
  message?: string;
}

export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  isLoading,
  children,
  message = 'Loading...'
}) => {
  return (
    <div className="relative">
      {children}
      {isLoading && (
        <div className="absolute inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="text-center">
            <LoadingSpinner size="lg" className="mx-auto mb-4" />
            <p className="text-muted-foreground">{message}</p>
          </div>
        </div>
      )}
    </div>
  );
};

const LoadingStates = {
  Skeleton,
  BlogCardSkeleton,
  BlogGridSkeleton,
  SearchBarSkeleton,
  LoadingSpinner,
  LoadingOverlay
};

export default LoadingStates;