import React from 'react';
import { Search, FileText, Filter, Wifi, AlertCircle, RefreshCw } from 'lucide-react';

interface EmptyStateProps {
  type?: 'search' | 'filter' | 'posts' | 'connection' | 'error' | 'loading';
  title?: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  icon?: React.ReactNode;
  className?: string;
}

const EmptyState: React.FC<EmptyStateProps> = ({
  type = 'posts',
  title,
  description,
  action,
  icon,
  className = ''
}) => {
  const getDefaultContent = () => {
    switch (type) {
      case 'search':
        return {
          icon: <Search className="w-12 h-12 text-muted-foreground opacity-50" />,
          title: 'No search results',
          description: 'We couldn\'t find any posts matching your search. Try different keywords or check your spelling.'
        };
      case 'filter':
        return {
          icon: <Filter className="w-12 h-12 text-muted-foreground opacity-50" />,
          title: 'No posts match your filters',
          description: 'Try adjusting your filter criteria or clearing some filters to see more results.'
        };
      case 'connection':
        return {
          icon: <Wifi className="w-12 h-12 text-muted-foreground opacity-50" />,
          title: 'Connection problem',
          description: 'Unable to load posts. Please check your internet connection and try again.'
        };
      case 'error':
        return {
          icon: <AlertCircle className="w-12 h-12 text-red-500 opacity-50" />,
          title: 'Something went wrong',
          description: 'We encountered an error while loading posts. Please try refreshing the page.'
        };
      case 'loading':
        return {
          icon: <RefreshCw className="w-12 h-12 text-muted-foreground opacity-50 animate-spin" />,
          title: 'Loading posts...',
          description: 'Please wait while we fetch the latest content for you.'
        };
      default:
        return {
          icon: <FileText className="w-12 h-12 text-muted-foreground opacity-50" />,
          title: 'No posts yet',
          description: 'There are no blog posts to display at the moment. Check back later for new content.'
        };
    }
  };

  const defaultContent = getDefaultContent();
  const displayIcon = icon || defaultContent.icon;
  const displayTitle = title || defaultContent.title;
  const displayDescription = description || defaultContent.description;

  return (
    <div className={`text-center py-12 px-6 ${className}`}>
      <div className="max-w-md mx-auto">
        <div className="flex justify-center mb-4">
          {displayIcon}
        </div>
        
        <h3 className="text-lg font-semibold text-foreground mb-2">
          {displayTitle}
        </h3>
        
        <p className="text-muted-foreground mb-6 text-sm leading-relaxed">
          {displayDescription}
        </p>
        
        {action && (
          <button
            onClick={action.onClick}
            className="inline-flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
          >
            {action.label}
          </button>
        )}
      </div>
    </div>
  );
};

interface NoSearchResultsProps {
  query: string;
  onClearSearch: () => void;
  suggestions?: string[];
}

export const NoSearchResults: React.FC<NoSearchResultsProps> = ({
  query,
  onClearSearch,
  suggestions = []
}) => {
  return (
    <div className="text-center py-12 px-6">
      <Search className="w-16 h-16 text-muted-foreground opacity-50 mx-auto mb-4" />
      
      <h3 className="text-xl font-semibold text-foreground mb-2">
        No results for "{query}"
      </h3>
      
      <p className="text-muted-foreground mb-6 max-w-md mx-auto">
        We couldn't find any posts matching your search. Try different keywords or browse our categories.
      </p>
      
      <div className="space-y-4">
        <button
          onClick={onClearSearch}
          className="inline-flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
        >
          Clear search
        </button>
        
        {suggestions.length > 0 && (
          <div>
            <p className="text-sm text-muted-foreground mb-3">Try searching for:</p>
            <div className="flex flex-wrap gap-2 justify-center">
              {suggestions.map((suggestion, index) => (
                <button
                  key={index}
                  className="px-3 py-1 text-sm bg-secondary text-secondary-foreground rounded-full hover:bg-secondary/80 transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

interface NoPostsProps {
  title?: string;
  description?: string;
  showCreateButton?: boolean;
  onCreatePost?: () => void;
}

export const NoPosts: React.FC<NoPostsProps> = ({
  title = "No posts published yet",
  description = "Be the first to know when we publish new content. Subscribe to our newsletter for updates.",
  showCreateButton = false,
  onCreatePost
}) => {
  return (
    <div className="text-center py-16 px-6">
      <div className="w-24 h-24 bg-muted rounded-full flex items-center justify-center mx-auto mb-6">
        <FileText className="w-12 h-12 text-muted-foreground" />
      </div>
      
      <h2 className="text-2xl font-bold text-foreground mb-4">{title}</h2>
      <p className="text-muted-foreground mb-8 max-w-md mx-auto">{description}</p>
      
      {showCreateButton && onCreatePost && (
        <button
          onClick={onCreatePost}
          className="inline-flex items-center px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
        >
          Create your first post
        </button>
      )}
    </div>
  );
};

export default EmptyState;