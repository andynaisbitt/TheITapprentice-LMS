import React from 'react';
import { Link } from 'react-router-dom';
import { Clock, Eye, Heart, Bookmark, Share2 } from 'lucide-react';

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

interface BlogCardProps {
  post: BlogPost;
  variant?: 'default' | 'featured' | 'compact';
  showStats?: boolean;
  showActions?: boolean;
  onBookmark?: (postId: string) => void;
  onShare?: (post: BlogPost) => void;
  isBookmarked?: boolean;
}

const BlogCard: React.FC<BlogCardProps> = ({
  post,
  variant = 'default',
  showStats = false,
  showActions = false,
  onBookmark,
  onShare,
  isBookmarked = false
}) => {
  const handleBookmarkClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onBookmark?.(post.id);
  };

  const handleShareClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onShare?.(post);
  };

  if (variant === 'compact') {
    return (
      <Link
        to={`/blog/${post.slug}`}
        className="group block focus:outline-none focus:ring-2 focus:ring-primary rounded-lg"
      >
        <article className="flex gap-4 p-4 bg-card rounded-lg border border-border hover:shadow-md transition-all duration-300">
          <img
            src={post.image}
            alt={post.title}
            className="w-20 h-20 object-cover rounded-lg flex-shrink-0 group-hover:scale-105 transition-transform duration-300"
          />
          <div className="flex-1 min-w-0">
            <h3 className="font-semibold text-foreground group-hover:text-primary transition-colors line-clamp-2 mb-2">
              {post.title}
            </h3>
            <div className="flex items-center gap-3 text-sm text-muted-foreground mb-2">
              <span>{post.author.name}</span>
              <div className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {post.readTime}
              </div>
            </div>
            <div className="flex flex-wrap gap-1">
              {post.tags.slice(0, 2).map((tag) => (
                <span
                  key={tag}
                  className="px-2 py-1 text-xs bg-secondary text-secondary-foreground rounded-full"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </article>
      </Link>
    );
  }

  if (variant === 'featured') {
    return (
      <Link
        to={`/blog/${post.slug}`}
        className="group block focus:outline-none focus:ring-2 focus:ring-primary rounded-lg"
      >
        <article className="bg-card rounded-lg shadow-sm border border-border overflow-hidden hover:shadow-xl transition-all duration-300 relative">
          {post.featured && (
            <div className="absolute top-4 left-4 z-10 bg-primary text-primary-foreground px-3 py-1 rounded-full text-sm font-medium">
              Featured
            </div>
          )}
          
          <div className="relative h-64">
            <div className="absolute top-4 right-4 z-10 bg-background/90 backdrop-blur-sm rounded-full p-2">
              {post.icon}
            </div>
            <img
              src={post.image}
              alt={post.title}
              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent" />
            <div className="absolute bottom-4 left-4 right-4 text-white">
              <div className="flex flex-wrap gap-2 mb-2">
                {post.tags.slice(0, 3).map((tag) => (
                  <span
                    key={tag}
                    className="px-2 py-1 text-xs bg-white/20 backdrop-blur-sm rounded-full"
                  >
                    {tag}
                  </span>
                ))}
              </div>
              <h2 className="text-xl font-bold mb-2 line-clamp-2">{post.title}</h2>
            </div>
          </div>

          <div className="p-6">
            <p className="text-muted-foreground mb-4 line-clamp-3">{post.excerpt}</p>
            
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <img
                  src={post.author.avatar}
                  alt={post.author.name}
                  className="w-8 h-8 rounded-full"
                />
                <div>
                  <div className="text-sm font-medium text-foreground">{post.author.name}</div>
                  <div className="text-xs text-muted-foreground">{post.date}</div>
                </div>
              </div>
              
              <div className="flex items-center gap-4">
                {showStats && (
                  <div className="flex items-center gap-3 text-sm text-muted-foreground">
                    {post.views && (
                      <div className="flex items-center gap-1">
                        <Eye className="w-4 h-4" />
                        {post.views}
                      </div>
                    )}
                    {post.likes && (
                      <div className="flex items-center gap-1">
                        <Heart className="w-4 h-4" />
                        {post.likes}
                      </div>
                    )}
                  </div>
                )}
                
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Clock className="w-4 h-4" />
                  {post.readTime}
                </div>
              </div>
            </div>
          </div>
        </article>
      </Link>
    );
  }

  return (
    <Link
      to={`/blog/${post.slug}`}
      className="group block focus:outline-none focus:ring-2 focus:ring-primary rounded-lg"
    >
      <article className="bg-card rounded-lg shadow-sm border border-border overflow-hidden hover:shadow-lg transition-all duration-300 relative">
        <div className="relative">
          <div className="absolute top-4 left-4 bg-background/90 dark:bg-background/70 backdrop-blur-sm rounded-full p-2 shadow-sm z-10">
            {post.icon}
          </div>
          
          {showActions && (
            <div className="absolute top-4 right-4 z-10 flex gap-2">
              <button
                onClick={handleBookmarkClick}
                className={`p-2 rounded-full backdrop-blur-sm transition-colors ${
                  isBookmarked 
                    ? 'bg-primary text-primary-foreground' 
                    : 'bg-background/90 hover:bg-primary hover:text-primary-foreground'
                }`}
              >
                <Bookmark className="w-4 h-4" fill={isBookmarked ? 'currentColor' : 'none'} />
              </button>
              <button
                onClick={handleShareClick}
                className="p-2 rounded-full bg-background/90 hover:bg-primary hover:text-primary-foreground backdrop-blur-sm transition-colors"
              >
                <Share2 className="w-4 h-4" />
              </button>
            </div>
          )}
          
          <img
            src={post.image}
            alt={post.title}
            className="w-full h-48 object-cover group-hover:scale-105 transition-transform duration-500"
          />
        </div>
        
        <div className="p-6 flex flex-col">
          <div className="flex flex-wrap gap-2 mb-3">
            {post.tags.map((tag) => (
              <span
                key={tag}
                className="px-2 py-1 text-xs font-medium bg-secondary text-secondary-foreground rounded-full"
              >
                {tag}
              </span>
            ))}
          </div>
          
          <h2 className="text-xl font-bold text-foreground mb-2 group-hover:text-primary transition-colors line-clamp-2">
            {post.title}
          </h2>
          <p className="text-muted-foreground mb-4 line-clamp-2 flex-1">{post.excerpt}</p>
          
          <div className="flex items-center justify-between pt-4 border-t border-border">
            <div className="flex items-center gap-3">
              <img
                src={post.author.avatar}
                alt={post.author.name}
                className="w-8 h-8 rounded-full"
              />
              <span className="text-sm text-muted-foreground">{post.author.name}</span>
            </div>
            
            <div className="flex items-center gap-4">
              {showStats && (
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  {post.views && (
                    <div className="flex items-center gap-1">
                      <Eye className="w-4 h-4" />
                      {post.views}
                    </div>
                  )}
                  {post.likes && (
                    <div className="flex items-center gap-1">
                      <Heart className="w-4 h-4" />
                      {post.likes}
                    </div>
                  )}
                </div>
              )}
              
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Clock className="w-4 h-4" />
                {post.readTime}
              </div>
            </div>
          </div>
        </div>
      </article>
    </Link>
  );
};

export default BlogCard;