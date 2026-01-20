// src/components/course-builder/SectionContentEditor.tsx
/**
 * Section Content Editor - Edit section with content blocks
 * Main editor for building section content with drag-and-drop
 */

import React, { useState } from 'react';
import { ModuleSection, ContentBlock, ContentBlockTemplate, SectionType } from '../../types';
import { BlockPalette } from './BlockPalette';
import { ContentBlockEditor } from './ContentBlockEditor';
import { DragDropProvider, Draggable } from './DragDropContext';
import { X, Save, Eye } from 'lucide-react';

interface SectionContentEditorProps {
  section: ModuleSection;
  onSave: (updates: Partial<ModuleSection>) => void;
  onClose: () => void;
}

export const SectionContentEditor: React.FC<SectionContentEditorProps> = ({
  section,
  onSave,
  onClose
}) => {
  const [editedSection, setEditedSection] = useState<ModuleSection>({ ...section });
  const [blocks, setBlocks] = useState<ContentBlock[]>(section.content_blocks || []);
  const [showPalette, setShowPalette] = useState(false);

  const handleAddBlock = (template: ContentBlockTemplate) => {
    const newBlock: ContentBlock = {
      id: `block-${Date.now()}`,
      type: template.type,
      content: template.defaultContent,
      order: blocks.length
    };
    
    const newBlocks = [...blocks, newBlock];
    setBlocks(newBlocks);
    setEditedSection({ ...editedSection, content_blocks: newBlocks });
    setShowPalette(false);
  };

  const handleUpdateBlock = (index: number, updates: Partial<ContentBlock>) => {
    const newBlocks = blocks.map((block, i) => 
      i === index ? { ...block, ...updates } : block
    );
    setBlocks(newBlocks);
    setEditedSection({ ...editedSection, content_blocks: newBlocks });
  };

  const handleDeleteBlock = (index: number) => {
    if (!confirm('Delete this block?')) return;
    const newBlocks = blocks.filter((_, i) => i !== index);
    // Reorder remaining blocks
    const reorderedBlocks = newBlocks.map((block, i) => ({ ...block, order: i }));
    setBlocks(reorderedBlocks);
    setEditedSection({ ...editedSection, content_blocks: reorderedBlocks });
  };

  const handleMoveBlock = (index: number, direction: 'up' | 'down') => {
    if (direction === 'up' && index === 0) return;
    if (direction === 'down' && index === blocks.length - 1) return;
    
    const newBlocks = [...blocks];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    
    // Swap blocks
    [newBlocks[index], newBlocks[targetIndex]] = [newBlocks[targetIndex], newBlocks[index]];
    
    // Update order
    const reorderedBlocks = newBlocks.map((block, i) => ({ ...block, order: i }));
    setBlocks(reorderedBlocks);
    setEditedSection({ ...editedSection, content_blocks: reorderedBlocks });
  };

  const handleReorderBlocks = (draggedId: string, targetId: string) => {
    const draggedIndex = blocks.findIndex(b => b.id === draggedId);
    const targetIndex = blocks.findIndex(b => b.id === targetId);
    
    if (draggedIndex === -1 || targetIndex === -1) return;
    
    const newBlocks = [...blocks];
    const [draggedBlock] = newBlocks.splice(draggedIndex, 1);
    newBlocks.splice(targetIndex, 0, draggedBlock);
    
    // Update order
    const reorderedBlocks = newBlocks.map((block, i) => ({ ...block, order: i }));
    setBlocks(reorderedBlocks);
    setEditedSection({ ...editedSection, content_blocks: reorderedBlocks });
  };

  const handleSave = () => {
    onSave(editedSection);
    onClose();
  };

  return (
    <DragDropProvider>
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                Edit Section Content
              </h2>
              <input
                type="text"
                value={editedSection.title}
                onChange={(e) => setEditedSection({ ...editedSection, title: e.target.value })}
                className="w-full max-w-2xl px-3 py-2 text-lg border border-gray-300 dark:border-gray-600 rounded-lg 
                         focus:outline-none focus:ring-2 focus:ring-blue-500 
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Section title"
              />
            </div>
            <button
              onClick={onClose}
              className="ml-4 p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          {/* Section Settings */}
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
            <div className="grid grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Section Type
                </label>
                <select
                  value={editedSection.type}
                  onChange={(e) => setEditedSection({ ...editedSection, type: e.target.value as SectionType })}
                  className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                           focus:outline-none focus:ring-1 focus:ring-blue-500 
                           bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="theory">Theory</option>
                  <option value="practice">Practice</option>
                  <option value="quiz">Quiz</option>
                  <option value="challenge">Challenge</option>
                  <option value="video">Video</option>
                  <option value="exercise">Exercise</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Time Estimate
                </label>
                <input
                  type="text"
                  value={editedSection.time_estimate || ''}
                  onChange={(e) => setEditedSection({ ...editedSection, time_estimate: e.target.value })}
                  className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                           focus:outline-none focus:ring-1 focus:ring-blue-500 
                           bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="e.g., 15 min"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Points
                </label>
                <input
                  type="number"
                  value={editedSection.points}
                  onChange={(e) => setEditedSection({ ...editedSection, points: parseInt(e.target.value) })}
                  className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                           focus:outline-none focus:ring-1 focus:ring-blue-500 
                           bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  min="0"
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={() => setShowPalette(!showPalette)}
                  className="w-full px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition"
                >
                  {showPalette ? 'Hide Blocks' : '+ Add Block'}
                </button>
              </div>
            </div>

            {/* Description */}
            <div className="mt-3">
              <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description (optional)
              </label>
              <input
                type="text"
                value={editedSection.description || ''}
                onChange={(e) => setEditedSection({ ...editedSection, description: e.target.value })}
                className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                         focus:outline-none focus:ring-1 focus:ring-blue-500 
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Brief description of this section"
              />
            </div>
          </div>

          {/* Content Area */}
          <div className="flex-1 overflow-hidden flex">
            {/* Main Content Editor */}
            <div className="flex-1 overflow-y-auto p-6">
              {blocks.length === 0 ? (
                <div className="text-center py-12">
                  <div className="text-6xl mb-4">📄</div>
                  <p className="text-gray-600 dark:text-gray-400 mb-4">
                    No content blocks yet
                  </p>
                  <button
                    onClick={() => setShowPalette(true)}
                    className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
                  >
                    Add Your First Block
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  {blocks.map((block, index) => (
                    <Draggable
                      key={block.id || index}
                      id={block.id || `block-${index}`}
                      onReorder={handleReorderBlocks}
                    >
                      <ContentBlockEditor
                        block={block}
                        index={index}
                        onUpdate={(updates) => handleUpdateBlock(index, updates)}
                        onDelete={() => handleDeleteBlock(index)}
                        onMoveUp={index > 0 ? () => handleMoveBlock(index, 'up') : undefined}
                        onMoveDown={index < blocks.length - 1 ? () => handleMoveBlock(index, 'down') : undefined}
                      />
                    </Draggable>
                  ))}
                </div>
              )}
            </div>

            {/* Block Palette Sidebar */}
            {showPalette && (
              <div className="w-80 border-l border-gray-200 dark:border-gray-700 overflow-y-auto p-4 bg-gray-50 dark:bg-gray-900">
                <BlockPalette onSelectBlock={handleAddBlock} />
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
            <div className="text-sm text-gray-600 dark:text-gray-400">
              {blocks.length} content block{blocks.length !== 1 ? 's' : ''} • Drag blocks to reorder
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition flex items-center gap-2"
              >
                <Save className="w-4 h-4" />
                Save Section
              </button>
            </div>
          </div>
        </div>
      </div>
    </DragDropProvider>
  );
};

export default SectionContentEditor;