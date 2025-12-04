import React from 'react';
import { Bookmark, BookmarkCheck } from 'lucide-react';

interface BookmarkButtonProps {
  postId: string;
  isBookmarked: boolean;
  onToggle: (postId: string) => void;
  variant?: 'default' | 'compact' | 'icon-only';
  className?: string;
  showLabel?: boolean;
}

const BookmarkButton: React.FC<BookmarkButtonProps> = ({
  postId,
  isBookmarked,
  onToggle,
  variant = 'default',
  className = '',
  showLabel = true
}) => {
  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onToggle(postId);
  };

  const baseClasses = "inline-flex items-center gap-2 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-primary rounded-lg";
  
  const variantClasses = {
    'default': `px-4 py-2 ${isBookmarked 
      ? 'bg-primary text-primary-foreground hover:bg-primary/90' 
      : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
    }`,
    'compact': `px-3 py-1.5 text-sm ${isBookmarked 
      ? 'bg-primary text-primary-foreground hover:bg-primary/90' 
      : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
    }`,
    'icon-only': `p-2 ${isBookmarked 
      ? 'text-primary hover:bg-primary/10' 
      : 'text-muted-foreground hover:text-primary hover:bg-primary/10'
    }`
  };

  const iconSize = variant === 'compact' ? 'w-4 h-4' : 'w-5 h-5';
  const Icon = isBookmarked ? BookmarkCheck : Bookmark;

  return (
    <button
      onClick={handleClick}
      className={`${baseClasses} ${variantClasses[variant]} ${className}`}
      aria-label={isBookmarked ? 'Remove bookmark' : 'Add bookmark'}
      title={isBookmarked ? 'Remove from bookmarks' : 'Save to bookmarks'}
    >
      <Icon 
        className={iconSize} 
        fill={isBookmarked ? 'currentColor' : 'none'} 
      />
      {showLabel && variant !== 'icon-only' && (
        <span>{isBookmarked ? 'Bookmarked' : 'Bookmark'}</span>
      )}
    </button>
  );
};

export default BookmarkButton;