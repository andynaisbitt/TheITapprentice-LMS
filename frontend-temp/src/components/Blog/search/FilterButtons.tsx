import React from 'react';
import { Filter, X } from 'lucide-react';

interface FilterOption {
  id: string;
  label: string;
  count?: number;
  color?: string;
}

interface FilterButtonsProps {
  options: FilterOption[];
  selectedFilters: string[];
  onFilterChange: (filterId: string) => void;
  onClearAll?: () => void;
  variant?: 'default' | 'compact' | 'pills';
  showCounts?: boolean;
  multiSelect?: boolean;
  maxVisible?: number;
}

const FilterButtons: React.FC<FilterButtonsProps> = ({
  options,
  selectedFilters,
  onFilterChange,
  onClearAll,
  variant = 'default',
  showCounts = true,
  multiSelect = true,
  maxVisible
}) => {
  const [showAll, setShowAll] = React.useState(false);
  
  const visibleOptions = maxVisible && !showAll 
    ? options.slice(0, maxVisible) 
    : options;
  
  const hasHiddenOptions = maxVisible && options.length > maxVisible;
  const hasActiveFilters = selectedFilters.length > 0;

  const handleFilterClick = (filterId: string) => {
    if (!multiSelect) {
      // Single select mode
      onFilterChange(filterId);
    } else {
      // Multi select mode
      onFilterChange(filterId);
    }
  };

  const isSelected = (filterId: string) => selectedFilters.includes(filterId);

  if (variant === 'compact') {
    return (
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="w-4 h-4 text-muted-foreground" />
        <div className="flex flex-wrap gap-1">
          {visibleOptions.map((option) => (
            <button
              key={option.id}
              onClick={() => handleFilterClick(option.id)}
              className={`
                px-2 py-1 text-xs rounded transition-colors
                ${isSelected(option.id)
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
                }
              `}
            >
              {option.label}
              {showCounts && option.count && (
                <span className="ml-1 opacity-75">({option.count})</span>
              )}
            </button>
          ))}
          
          {hasHiddenOptions && (
            <button
              onClick={() => setShowAll(!showAll)}
              className="px-2 py-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {showAll ? 'Less' : `+${options.length - maxVisible!}`}
            </button>
          )}
        </div>
      </div>
    );
  }

  if (variant === 'pills') {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm font-medium text-foreground">Filters</span>
          </div>
          {hasActiveFilters && onClearAll && (
            <button
              onClick={onClearAll}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear all
            </button>
          )}
        </div>
        
        <div className="flex flex-wrap gap-2">
          {visibleOptions.map((option) => (
            <button
              key={option.id}
              onClick={() => handleFilterClick(option.id)}
              className={`
                inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm transition-colors
                ${isSelected(option.id)
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-secondary text-secondary-foreground hover:bg-secondary/80'
                }
              `}
            >
              <span>{option.label}</span>
              {showCounts && option.count && (
                <span className="text-xs opacity-75">({option.count})</span>
              )}
              {isSelected(option.id) && multiSelect && (
                <X className="w-3 h-3" />
              )}
            </button>
          ))}
          
          {hasHiddenOptions && (
            <button
              onClick={() => setShowAll(!showAll)}
              className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors border border-border rounded-full"
            >
              {showAll ? 'Show less' : `+${options.length - maxVisible!} more`}
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <Filter className="w-5 h-5" />
          Filter by Category
        </h3>
        {hasActiveFilters && onClearAll && (
          <button
            onClick={onClearAll}
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            Clear all ({selectedFilters.length})
          </button>
        )}
      </div>
      
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {visibleOptions.map((option) => (
          <button
            key={option.id}
            onClick={() => handleFilterClick(option.id)}
            className={`
              flex flex-col items-center p-4 rounded-lg border transition-all
              ${isSelected(option.id)
                ? 'bg-primary text-primary-foreground border-primary'
                : 'bg-card text-card-foreground border-border hover:bg-accent hover:text-accent-foreground'
              }
            `}
          >
            <span className="font-medium text-center">{option.label}</span>
            {showCounts && option.count && (
              <span className="text-sm opacity-75 mt-1">
                {option.count} post{option.count !== 1 ? 's' : ''}
              </span>
            )}
          </button>
        ))}
      </div>
      
      {hasHiddenOptions && (
        <div className="text-center">
          <button
            onClick={() => setShowAll(!showAll)}
            className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors border border-border rounded-lg"
          >
            {showAll 
              ? 'Show less categories' 
              : `Show ${options.length - maxVisible!} more categories`
            }
          </button>
        </div>
      )}
    </div>
  );
};

export default FilterButtons;