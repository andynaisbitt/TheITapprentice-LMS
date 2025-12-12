import React, { useState, useEffect, useRef } from 'react';
import { Search, X, Command } from 'lucide-react';

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  onFocus?: () => void;
  onBlur?: () => void;
  onSubmit?: (value: string) => void;
  placeholder?: string;
  showShortcut?: boolean;
  showClear?: boolean;
  disabled?: boolean;
  autoFocus?: boolean;
  debounceMs?: number;
}

const SearchBar: React.FC<SearchBarProps> = ({
  value,
  onChange,
  onFocus,
  onBlur,
  onSubmit,
  placeholder = "Search blog posts...",
  showShortcut = true,
  showClear = true,
  disabled = false,
  autoFocus = false,
  debounceMs = 300
}) => {
  const [isFocused, setIsFocused] = useState(false);
  const [debouncedValue, setDebouncedValue] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<NodeJS.Timeout>();

  // Debounced search
  useEffect(() => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    debounceRef.current = setTimeout(() => {
      setDebouncedValue(value);
    }, debounceMs);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, [value, debounceMs]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd/Ctrl + K to focus search
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
      
      // Escape to clear and blur
      if (e.key === 'Escape' && isFocused) {
        if (value) {
          onChange('');
        } else {
          inputRef.current?.blur();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [value, onChange, isFocused]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (onSubmit) {
      onSubmit(value);
    }
  };

  const handleFocus = () => {
    setIsFocused(true);
    if (onFocus) {
      onFocus();
    }
  };

  const handleBlur = () => {
    setIsFocused(false);
    if (onBlur) {
      onBlur();
    }
  };

  const handleClear = () => {
    onChange('');
    inputRef.current?.focus();
  };

  return (
    <form onSubmit={handleSubmit} className="relative">
      <div className={`
        relative flex items-center transition-all duration-200
        ${isFocused ? 'ring-2 ring-primary' : 'ring-1 ring-border'}
        ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
        rounded-lg bg-background
      `}>
        <Search className="absolute left-3 w-4 h-4 text-muted-foreground pointer-events-none" />
        
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={handleInputChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          placeholder={placeholder}
          disabled={disabled}
          autoFocus={autoFocus}
          className={`
            w-full pl-10 pr-20 py-3 bg-transparent text-foreground 
            placeholder:text-muted-foreground rounded-lg outline-none
            ${disabled ? 'cursor-not-allowed' : ''}
          `}
        />

        <div className="absolute right-2 flex items-center gap-1">
          {showClear && value && (
            <button
              type="button"
              onClick={handleClear}
              className="p-1 text-muted-foreground hover:text-foreground rounded transition-colors"
              aria-label="Clear search"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          
          {showShortcut && !isFocused && (
            <div className="hidden sm:flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground bg-muted rounded border">
              <Command className="w-3 h-3" />
              <span>K</span>
            </div>
          )}
        </div>
      </div>
    </form>
  );
};

export default SearchBar;