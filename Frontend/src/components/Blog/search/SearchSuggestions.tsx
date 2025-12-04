import React from 'react';
import { Search, TrendingUp, Clock, Hash } from 'lucide-react';

interface SearchSuggestion {
  id: string;
  text: string;
  type: 'query' | 'tag' | 'recent' | 'trending';
  count?: number;
  icon?: React.ReactNode;
}

interface SearchSuggestionsProps {
  suggestions: SearchSuggestion[];
  onSuggestionClick: (suggestion: SearchSuggestion) => void;
  onClose?: () => void;
  isVisible: boolean;
  maxSuggestions?: number;
  showTypes?: boolean;
}

const SearchSuggestions: React.FC<SearchSuggestionsProps> = ({
  suggestions,
  onSuggestionClick,
  onClose,
  isVisible,
  maxSuggestions = 8,
  showTypes = true
}) => {
  const limitedSuggestions = suggestions.slice(0, maxSuggestions);
  
  const groupedSuggestions = React.useMemo(() => {
    const groups = {
      trending: limitedSuggestions.filter(s => s.type === 'trending'),
      recent: limitedSuggestions.filter(s => s.type === 'recent'),
      tag: limitedSuggestions.filter(s => s.type === 'tag'),
      query: limitedSuggestions.filter(s => s.type === 'query')
    };
    
    return Object.entries(groups).filter(([_, items]) => items.length > 0);
  }, [limitedSuggestions]);

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'trending': return <TrendingUp className="w-4 h-4 text-orange-500" />;
      case 'recent': return <Clock className="w-4 h-4 text-blue-500" />;
      case 'tag': return <Hash className="w-4 h-4 text-green-500" />;
      case 'query': return <Search className="w-4 h-4 text-muted-foreground" />;
      default: return <Search className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'trending': return 'Trending';
      case 'recent': return 'Recent searches';
      case 'tag': return 'Popular tags';
      case 'query': return 'Suggestions';
      default: return 'Suggestions';
    }
  };

  const handleSuggestionClick = (suggestion: SearchSuggestion) => {
    onSuggestionClick(suggestion);
    if (onClose) {
      onClose();
    }
  };

  if (!isVisible || limitedSuggestions.length === 0) {
    return null;
  }

  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 z-40" 
        onClick={onClose}
      />
      
      {/* Suggestions dropdown */}
      <div className="absolute top-full left-0 right-0 mt-2 bg-background border border-border rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto">
        {showTypes ? (
          // Grouped view
          <div className="p-2">
            {groupedSuggestions.map(([type, items], groupIndex) => (
              <div key={type}>
                {groupIndex > 0 && <div className="border-t border-border my-2" />}
                
                <div className="px-2 py-1 text-xs font-medium text-muted-foreground uppercase tracking-wide flex items-center gap-2">
                  {getTypeIcon(type)}
                  {getTypeLabel(type)}
                </div>
                
                <div className="space-y-1">
                  {items.map((suggestion) => (
                    <button
                      key={suggestion.id}
                      onClick={() => handleSuggestionClick(suggestion)}
                      className="w-full flex items-center justify-between p-2 rounded-lg hover:bg-accent transition-colors text-left"
                    >
                      <div className="flex items-center gap-3">
                        {suggestion.icon || getTypeIcon(suggestion.type)}
                        <span className="text-foreground">{suggestion.text}</span>
                      </div>
                      {suggestion.count && (
                        <span className="text-xs text-muted-foreground">
                          {suggestion.count}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          // Simple list view
          <div className="p-2 space-y-1">
            {limitedSuggestions.map((suggestion) => (
              <button
                key={suggestion.id}
                onClick={() => handleSuggestionClick(suggestion)}
                className="w-full flex items-center justify-between p-2 rounded-lg hover:bg-accent transition-colors text-left"
              >
                <div className="flex items-center gap-3">
                  {suggestion.icon || getTypeIcon(suggestion.type)}
                  <span className="text-foreground">{suggestion.text}</span>
                </div>
                {suggestion.count && (
                  <span className="text-xs text-muted-foreground">
                    {suggestion.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        )}
        
        {suggestions.length > maxSuggestions && (
          <div className="border-t border-border p-3 text-center">
            <span className="text-sm text-muted-foreground">
              {suggestions.length - maxSuggestions} more suggestions available
            </span>
          </div>
        )}
      </div>
    </>
  );
};

export default SearchSuggestions;