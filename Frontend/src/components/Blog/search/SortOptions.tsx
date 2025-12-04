import React, { useState } from 'react';
import { ArrowUpDown, Calendar, Eye, Heart, Clock, TrendingUp, ChevronDown } from 'lucide-react';

interface SortOption {
  id: string;
  label: string;
  icon?: React.ReactNode;
  description?: string;
}

interface SortOptionsProps {
  options?: SortOption[];
  value: string;
  onChange: (sortId: string) => void;
  direction?: 'asc' | 'desc';
  onDirectionChange?: (direction: 'asc' | 'desc') => void;
  variant?: 'dropdown' | 'buttons' | 'tabs';
  showDirection?: boolean;
}

const SortOptions: React.FC<SortOptionsProps> = ({
  options,
  value,
  onChange,
  direction = 'desc',
  onDirectionChange,
  variant = 'dropdown',
  showDirection = true
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const defaultOptions: SortOption[] = [
    {
      id: 'date',
      label: 'Date Published',
      icon: <Calendar className="w-4 h-4" />,
      description: 'Sort by publication date'
    },
    {
      id: 'views',
      label: 'Most Viewed',
      icon: <Eye className="w-4 h-4" />,
      description: 'Sort by view count'
    },
    {
      id: 'likes',
      label: 'Most Liked',
      icon: <Heart className="w-4 h-4" />,
      description: 'Sort by like count'
    },
    {
      id: 'readTime',
      label: 'Reading Time',
      icon: <Clock className="w-4 h-4" />,
      description: 'Sort by estimated reading time'
    },
    {
      id: 'trending',
      label: 'Trending',
      icon: <TrendingUp className="w-4 h-4" />,
      description: 'Sort by current popularity'
    }
  ];

  const sortOptions = options || defaultOptions;
  const currentOption = sortOptions.find(option => option.id === value) || sortOptions[0];

  const handleSortChange = (sortId: string) => {
    onChange(sortId);
    setIsOpen(false);
  };

  const toggleDirection = () => {
    if (onDirectionChange) {
      onDirectionChange(direction === 'asc' ? 'desc' : 'asc');
    }
  };

  const getDirectionLabel = () => {
    if (value === 'date') {
      return direction === 'desc' ? 'Newest first' : 'Oldest first';
    }
    if (value === 'readTime') {
      return direction === 'desc' ? 'Longest first' : 'Shortest first';
    }
    return direction === 'desc' ? 'High to low' : 'Low to high';
  };

  if (variant === 'buttons') {
    return (
      <div className="flex flex-wrap gap-2">
        {sortOptions.map((option) => (
          <button
            key={option.id}
            onClick={() => handleSortChange(option.id)}
            className={`
              flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors
              ${value === option.id
                ? 'bg-primary text-primary-foreground'
                : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
              }
            `}
          >
            {option.icon}
            {option.label}
          </button>
        ))}
        
        {showDirection && onDirectionChange && (
          <button
            onClick={toggleDirection}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-accent text-accent-foreground hover:bg-accent/80 transition-colors"
            title={getDirectionLabel()}
          >
            <ArrowUpDown className="w-4 h-4" />
            {direction === 'desc' ? '↓' : '↑'}
          </button>
        )}
      </div>
    );
  }

  if (variant === 'tabs') {
    return (
      <div className="space-y-3">
        <div className="flex items-center border-b border-border">
          {sortOptions.map((option) => (
            <button
              key={option.id}
              onClick={() => handleSortChange(option.id)}
              className={`
                flex items-center gap-2 px-4 py-2 text-sm transition-colors border-b-2 
                ${value === option.id
                  ? 'border-primary text-primary font-medium'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
                }
              `}
            >
              {option.icon}
              {option.label}
            </button>
          ))}
        </div>
        
        {showDirection && onDirectionChange && (
          <button
            onClick={toggleDirection}
            className="flex items-center gap-2 px-3 py-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowUpDown className="w-4 h-4" />
            {getDirectionLabel()}
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors"
      >
        <ArrowUpDown className="w-4 h-4" />
        <span>Sort by {currentOption.label}</span>
        {showDirection && (
          <span className="text-xs opacity-75">
            ({direction === 'desc' ? '↓' : '↑'})
          </span>
        )}
        <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <>
          <div 
            className="fixed inset-0 z-40" 
            onClick={() => setIsOpen(false)}
          />
          
          <div className="absolute top-full right-0 mt-2 w-64 bg-background border border-border rounded-lg shadow-lg z-50">
            <div className="p-2">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide px-2 py-1 mb-2">
                Sort by
              </div>
              
              {sortOptions.map((option) => (
                <button
                  key={option.id}
                  onClick={() => handleSortChange(option.id)}
                  className={`
                    w-full flex items-start gap-3 p-2 rounded-lg transition-colors text-left
                    ${value === option.id
                      ? 'bg-primary/10 text-primary'
                      : 'hover:bg-accent text-foreground'
                    }
                  `}
                >
                  {option.icon}
                  <div>
                    <div className="font-medium">{option.label}</div>
                    {option.description && (
                      <div className="text-xs text-muted-foreground mt-1">
                        {option.description}
                      </div>
                    )}
                  </div>
                  {value === option.id && (
                    <div className="ml-auto text-primary">✓</div>
                  )}
                </button>
              ))}
              
              {showDirection && onDirectionChange && (
                <>
                  <div className="border-t border-border my-2" />
                  <button
                    onClick={toggleDirection}
                    className="w-full flex items-center gap-3 p-2 rounded-lg hover:bg-accent transition-colors text-left"
                  >
                    <ArrowUpDown className="w-4 h-4" />
                    <div>
                      <div className="font-medium">Direction</div>
                      <div className="text-xs text-muted-foreground">
                        {getDirectionLabel()}
                      </div>
                    </div>
                  </button>
                </>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default SortOptions;