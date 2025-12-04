import React from 'react';
import { Hash } from 'lucide-react';

interface TagData {
  name: string;
  count: number;
  color?: string;
}

interface TagCloudProps {
  tags: TagData[];
  onTagClick?: (tag: string) => void;
  maxTags?: number;
  variant?: 'cloud' | 'list' | 'compact';
  showCounts?: boolean;
}

const TagCloud: React.FC<TagCloudProps> = ({
  tags,
  onTagClick,
  maxTags = 20,
  variant = 'cloud',
  showCounts = true
}) => {
  const displayTags = tags.slice(0, maxTags);
  
  // Calculate font sizes based on tag frequency
  const maxCount = Math.max(...displayTags.map(tag => tag.count));
  const minCount = Math.min(...displayTags.map(tag => tag.count));
  const range = maxCount - minCount;

  const getFontSize = (count: number) => {
    if (range === 0) return 'text-base';
    const normalized = (count - minCount) / range;
    if (normalized > 0.8) return 'text-2xl';
    if (normalized > 0.6) return 'text-xl';
    if (normalized > 0.4) return 'text-lg';
    if (normalized > 0.2) return 'text-base';
    return 'text-sm';
  };

  const getOpacity = (count: number) => {
    if (range === 0) return 'opacity-100';
    const normalized = (count - minCount) / range;
    if (normalized > 0.8) return 'opacity-100';
    if (normalized > 0.6) return 'opacity-90';
    if (normalized > 0.4) return 'opacity-80';
    if (normalized > 0.2) return 'opacity-70';
    return 'opacity-60';
  };

  if (variant === 'list') {
    return (
      <div className="bg-card rounded-lg p-6 border border-border">
        <div className="flex items-center gap-2 mb-4">
          <Hash className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-foreground">Popular Tags</h3>
        </div>
        <div className="space-y-2">
          {displayTags.map((tag) => (
            <button
              key={tag.name}
              onClick={() => onTagClick?.(tag.name)}
              className="flex items-center justify-between w-full p-2 rounded-lg hover:bg-accent transition-colors text-left"
            >
              <span className="font-medium text-foreground">{tag.name}</span>
              {showCounts && (
                <span className="text-sm text-muted-foreground bg-secondary px-2 py-1 rounded-full">
                  {tag.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
    );
  }

  if (variant === 'compact') {
    return (
      <div className="bg-card rounded-lg p-4 border border-border">
        <h4 className="font-medium text-foreground mb-3">Tags</h4>
        <div className="flex flex-wrap gap-2">
          {displayTags.map((tag) => (
            <button
              key={tag.name}
              onClick={() => onTagClick?.(tag.name)}
              className="px-3 py-1 bg-secondary text-secondary-foreground rounded-full text-sm hover:bg-secondary/80 transition-colors"
            >
              {tag.name}
              {showCounts && ` (${tag.count})`}
            </button>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg p-6 border border-border">
      <div className="flex items-center gap-2 mb-6">
        <Hash className="w-5 h-5 text-primary" />
        <h3 className="text-lg font-semibold text-foreground">Tag Cloud</h3>
      </div>
      
      <div className="flex flex-wrap gap-4 items-center justify-center">
        {displayTags.map((tag) => (
          <button
            key={tag.name}
            onClick={() => onTagClick?.(tag.name)}
            className={`
              font-medium text-foreground hover:text-primary transition-all duration-200 
              hover:scale-110 cursor-pointer
              ${getFontSize(tag.count)} 
              ${getOpacity(tag.count)}
            `}
            style={{ color: tag.color }}
          >
            {tag.name}
            {showCounts && (
              <span className="text-xs text-muted-foreground ml-1">
                ({tag.count})
              </span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
};

export default TagCloud;