// src/components/course-builder/BlockPalette.tsx
/**
 * Block Palette - Drag and Drop Block Selector
 * Shows all available content block types
 */

import React from 'react';
import { CONTENT_BLOCK_TEMPLATES, ContentBlockTemplate } from '../../types';

interface BlockPaletteProps {
  onSelectBlock: (template: ContentBlockTemplate) => void;
  className?: string;
}

export const BlockPalette: React.FC<BlockPaletteProps> = ({ onSelectBlock, className = '' }) => {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 ${className}`}>
      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
        Add Content Block
      </h3>
      
      <div className="grid grid-cols-2 gap-2">
        {CONTENT_BLOCK_TEMPLATES.map((template) => (
          <button
            key={template.type}
            onClick={() => onSelectBlock(template)}
            className="flex flex-col items-center justify-center p-3 rounded-lg border-2 border-dashed 
                     border-gray-300 dark:border-gray-600 hover:border-blue-500 dark:hover:border-blue-400
                     hover:bg-blue-50 dark:hover:bg-blue-900/20 transition group"
          >
            <span className="text-2xl mb-1 group-hover:scale-110 transition-transform">
              {template.icon}
            </span>
            <span className="text-xs font-medium text-gray-700 dark:text-gray-300 text-center">
              {template.name}
            </span>
          </button>
        ))}
      </div>
      
      <div className="mt-4 text-xs text-gray-500 dark:text-gray-400 text-center">
        Click a block to add it to your section
      </div>
    </div>
  );
};

export default BlockPalette;