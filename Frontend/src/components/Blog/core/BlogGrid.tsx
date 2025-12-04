import React from 'react';
import BlogCard from './BlogCard';

interface BlogPost {
  id: string;
  title: string;
  excerpt: string;
  date: string;
  readTime: string;
  image: string;
  author: {
    name: string;
    avatar: string;
  };
  slug: string;
  tags: string[];
  icon: JSX.Element;
  views?: number;
  likes?: number;
  featured?: boolean;
}

interface BlogGridProps {
  posts: BlogPost[];
  layout?: 'masonry' | 'grid' | 'list';
  columns?: 1 | 2 | 3 | 4;
  showStats?: boolean;
  showActions?: boolean;
  onBookmark?: (postId: string) => void;
  onShare?: (post: BlogPost) => void;
  bookmarkedPosts?: string[];
  featuredFirst?: boolean;
}

const BlogGrid: React.FC<BlogGridProps> = ({
  posts,
  layout = 'grid',
  columns = 3,
  showStats = false,
  showActions = false,
  onBookmark,
  onShare,
  bookmarkedPosts = [],
  featuredFirst = false
}) => {
  const sortedPosts = React.useMemo(() => {
    if (!featuredFirst) return posts;
    
    const featured = posts.filter(post => post.featured);
    const regular = posts.filter(post => !post.featured);
    return [...featured, ...regular];
  }, [posts, featuredFirst]);

  const getGridClasses = () => {
    if (layout === 'list') {
      return 'flex flex-col gap-6';
    }
    
    const columnClasses = {
      1: 'grid-cols-1',
      2: 'grid-cols-1 sm:grid-cols-2',
      3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
      4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
    };
    
    return `grid ${columnClasses[columns]} gap-8`;
  };

  const getCardVariant = (post: BlogPost, index: number) => {
    if (layout === 'list') return 'compact';
    if (post.featured && index === 0 && featuredFirst) return 'featured';
    return 'default';
  };

  if (posts.length === 0) {
    return (
      <div className="text-center py-12">
        <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-muted flex items-center justify-center">
          <svg className="w-8 h-8 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z" />
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-foreground mb-2">No posts found</h3>
        <p className="text-muted-foreground">Try adjusting your search or filter criteria.</p>
      </div>
    );
  }

  return (
    <div className={getGridClasses()}>
      {sortedPosts.map((post, index) => (
        <BlogCard
          key={post.id}
          post={post}
          variant={getCardVariant(post, index)}
          showStats={showStats}
          showActions={showActions}
          onBookmark={onBookmark}
          onShare={onShare}
          isBookmarked={bookmarkedPosts.includes(post.id)}
        />
      ))}
    </div>
  );
};

export default BlogGrid;