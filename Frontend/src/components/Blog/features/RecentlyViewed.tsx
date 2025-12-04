import React from 'react';
import { Link } from 'react-router-dom';
import { Clock, Eye, X } from 'lucide-react';

interface RecentPost {
  id: string;
  title: string;
  slug: string;
  image: string;
  readTime: string;
  viewedAt: Date;
  progress?: number; // 0-100
}

interface RecentlyViewedProps {
  posts: RecentPost[];
  maxPosts?: number;
  onRemove?: (postId: string) => void;
  onClearAll?: () => void;
  variant?: 'default' | 'compact' | 'sidebar';
}

const RecentlyViewed: React.FC<RecentlyViewedProps> = ({
  posts,
  maxPosts = 5,
  onRemove,
  onClearAll,
  variant = 'default'
}) => {
  const displayPosts = posts.slice(0, maxPosts);

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return 'Just now';
    if (diffInHours < 24) return `${diffInHours}h ago`;
    if (diffInHours < 48) return 'Yesterday';
    
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}d ago`;
    
    return date.toLocaleDateString();
  };

  const handleRemove = (e: React.MouseEvent, postId: string) => {
    e.preventDefault();
    e.stopPropagation();
    onRemove?.(postId);
  };

  if (displayPosts.length === 0) {
    return (
      <div className="bg-card rounded-lg p-6 border border-border">
        <h3 className="text-lg font-semibold text-foreground mb-4">Recently Viewed</h3>
        <div className="text-center py-8">
          <Eye className="w-12 h-12 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-muted-foreground">No recently viewed posts</p>
          <p className="text-sm text-muted-foreground mt-1">Posts you read will appear here</p>
        </div>
      </div>
    );
  }

  if (variant === 'compact') {
    return (
      <div className="space-y-2">
        {displayPosts.map((post) => (
          <Link
            key={post.id}
            to={`/blog/${post.slug}`}
            className="group flex items-center gap-3 p-2 rounded-lg hover:bg-accent transition-colors"
          >
            <img
              src={post.image}
              alt={post.title}
              className="w-10 h-10 object-cover rounded"
            />
            <div className="flex-1 min-w-0">
              <div className="font-medium text-sm text-foreground group-hover:text-primary transition-colors line-clamp-1">
                {post.title}
              </div>
              <div className="text-xs text-muted-foreground">
                {formatTimeAgo(post.viewedAt)}
              </div>
            </div>
          </Link>
        ))}
      </div>
    );
  }

  if (variant === 'sidebar') {
    return (
      <div className="bg-card rounded-lg p-4 border border-border">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-foreground flex items-center gap-2">
            <Eye className="w-4 h-4" />
            Recently Viewed
          </h3>
          {onClearAll && displayPosts.length > 0 && (
            <button
              onClick={onClearAll}
              className="text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear all
            </button>
          )}
        </div>
        
        <div className="space-y-3">
          {displayPosts.map((post) => (
            <div key={post.id} className="relative group">
              <Link
                to={`/blog/${post.slug}`}
                className="block"
              >
                <div className="flex gap-3">
                  <img
                    src={post.image}
                    alt={post.title}
                    className="w-12 h-12 object-cover rounded flex-shrink-0"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm text-foreground group-hover:text-primary transition-colors line-clamp-2 mb-1">
                      {post.title}
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span>{formatTimeAgo(post.viewedAt)}</span>
                      <span>•</span>
                      <span>{post.readTime}</span>
                    </div>
                    {post.progress && post.progress > 0 && (
                      <div className="mt-1">
                        <div className="w-full bg-secondary rounded-full h-1">
                          <div
                            className="bg-primary h-1 rounded-full"
                            style={{ width: `${post.progress}%` }}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </Link>
              
              {onRemove && (
                <button
                  onClick={(e) => handleRemove(e, post.id)}
                  className="absolute top-0 right-0 opacity-0 group-hover:opacity-100 p-1 text-muted-foreground hover:text-foreground transition-all"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg p-6 border border-border">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <Eye className="w-5 h-5" />
          Recently Viewed
        </h3>
        {onClearAll && displayPosts.length > 0 && (
          <button
            onClick={onClearAll}
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Clear all
          </button>
        )}
      </div>
      
      <div className="space-y-4">
        {displayPosts.map((post) => (
          <div key={post.id} className="relative group">
            <Link
              to={`/blog/${post.slug}`}
              className="flex gap-4 p-4 rounded-lg hover:bg-accent transition-colors"
            >
              <img
                src={post.image}
                alt={post.title}
                className="w-16 h-16 object-cover rounded-lg flex-shrink-0"
              />
              <div className="flex-1 min-w-0">
                <h4 className="font-medium text-foreground group-hover:text-primary transition-colors line-clamp-2 mb-2">
                  {post.title}
                </h4>
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <span>{formatTimeAgo(post.viewedAt)}</span>
                  <div className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {post.readTime}
                  </div>
                </div>
                {post.progress && post.progress > 0 && (
                  <div className="mt-2">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
                      <span>Progress: {Math.round(post.progress)}%</span>
                    </div>
                    <div className="w-full bg-secondary rounded-full h-2">
                      <div
                        className="bg-primary h-2 rounded-full transition-all duration-300"
                        style={{ width: `${post.progress}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            </Link>
            
            {onRemove && (
              <button
                onClick={(e) => handleRemove(e, post.id)}
                className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 p-2 text-muted-foreground hover:text-foreground transition-all"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default RecentlyViewed;