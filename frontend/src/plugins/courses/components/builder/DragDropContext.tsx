// src/components/course-builder/DragDropContext.tsx
/**
 * Drag and Drop Context - HTML5 Drag API wrapper
 * Enables drag-and-drop reordering of blocks
 */

import React, { createContext, useContext, useState, DragEvent } from 'react';

interface DragDropContextValue {
  draggedItem: string | null;
  draggedOverItem: string | null;
  onDragStart: (id: string) => void;
  onDragEnd: () => void;
  onDragOver: (id: string) => void;
  onDrop: (id: string, onReorder: (draggedId: string, targetId: string) => void) => void;
}

const DragDropContext = createContext<DragDropContextValue | undefined>(undefined);

export const useDragDrop = () => {
  const context = useContext(DragDropContext);
  if (!context) {
    throw new Error('useDragDrop must be used within DragDropProvider');
  }
  return context;
};

interface DragDropProviderProps {
  children: React.ReactNode;
}

export const DragDropProvider: React.FC<DragDropProviderProps> = ({ children }) => {
  const [draggedItem, setDraggedItem] = useState<string | null>(null);
  const [draggedOverItem, setDraggedOverItem] = useState<string | null>(null);

  const onDragStart = (id: string) => {
    setDraggedItem(id);
  };

  const onDragEnd = () => {
    setDraggedItem(null);
    setDraggedOverItem(null);
  };

  const onDragOver = (id: string) => {
    if (id !== draggedItem) {
      setDraggedOverItem(id);
    }
  };

  const onDrop = (id: string, onReorder: (draggedId: string, targetId: string) => void) => {
    if (draggedItem && draggedItem !== id) {
      onReorder(draggedItem, id);
    }
    onDragEnd();
  };

  const value: DragDropContextValue = {
    draggedItem,
    draggedOverItem,
    onDragStart,
    onDragEnd,
    onDragOver,
    onDrop,
  };

  return (
    <DragDropContext.Provider value={value}>
      {children}
    </DragDropContext.Provider>
  );
};

// Draggable wrapper component
interface DraggableProps {
  id: string;
  onReorder: (draggedId: string, targetId: string) => void;
  children: React.ReactNode;
  className?: string;
}

export const Draggable: React.FC<DraggableProps> = ({ 
  id, 
  onReorder, 
  children, 
  className = '' 
}) => {
  const { draggedItem, draggedOverItem, onDragStart, onDragEnd, onDragOver, onDrop } = useDragDrop();

  const handleDragStart = (e: DragEvent) => {
    e.dataTransfer.effectAllowed = 'move';
    onDragStart(id);
  };

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    onDragOver(id);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    onDrop(id, onReorder);
  };

  const isDragging = draggedItem === id;
  const isDraggedOver = draggedOverItem === id && !isDragging;

  return (
    <div
      draggable
      onDragStart={handleDragStart}
      onDragEnd={onDragEnd}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      className={`
        ${className}
        ${isDragging ? 'opacity-50 cursor-grabbing' : 'cursor-grab'}
        ${isDraggedOver ? 'border-t-4 border-blue-500' : ''}
        transition-all duration-200
      `}
    >
      {children}
    </div>
  );
};

export default DragDropProvider;