// src/components/course-builder/RichTextEditor.tsx
/**
 * Rich Text Editor - Advanced text editing with formatting
 * Markdown-based with visual toolbar
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Bold,
  Italic,
  Underline,
  List,
  ListOrdered,
  Link,
  Code,
  Quote,
  Heading1,
  Heading2,
  Heading3,
  AlignLeft,
  AlignCenter,
  AlignRight,
  Image,
  Eye,
  Type
} from 'lucide-react';

interface RichTextEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  minHeight?: string;
  maxHeight?: string;
  showPreview?: boolean;
}

export const RichTextEditor: React.FC<RichTextEditorProps> = ({
  value,
  onChange,
  placeholder = 'Enter your text here...',
  minHeight = '200px',
  maxHeight = '500px',
  showPreview: initialShowPreview = false
}) => {
  const [showPreview, setShowPreview] = useState(initialShowPreview);
  const [selectedText, setSelectedText] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Handle text selection
  const handleSelect = () => {
    if (textareaRef.current) {
      const start = textareaRef.current.selectionStart;
      const end = textareaRef.current.selectionEnd;
      setSelectedText(value.substring(start, end));
    }
  };

  // Insert text at cursor position
  const insertText = (before: string, after: string = '', defaultText: string = '') => {
    if (!textareaRef.current) return;

    const start = textareaRef.current.selectionStart;
    const end = textareaRef.current.selectionEnd;
    const selectedText = value.substring(start, end);
    const textToInsert = selectedText || defaultText;
    
    const newText = 
      value.substring(0, start) +
      before +
      textToInsert +
      after +
      value.substring(end);
    
    onChange(newText);
    
    // Set cursor position
    setTimeout(() => {
      if (textareaRef.current) {
        const newCursorPos = start + before.length + textToInsert.length;
        textareaRef.current.focus();
        textareaRef.current.setSelectionRange(newCursorPos, newCursorPos);
      }
    }, 0);
  };

  // Toolbar actions
  const actions = {
    bold: () => insertText('**', '**', 'bold text'),
    italic: () => insertText('*', '*', 'italic text'),
    underline: () => insertText('<u>', '</u>', 'underlined text'),
    h1: () => insertText('# ', '', 'Heading 1'),
    h2: () => insertText('## ', '', 'Heading 2'),
    h3: () => insertText('### ', '', 'Heading 3'),
    link: () => {
      const url = prompt('Enter URL:');
      if (url) insertText('[', `](${url})`, 'link text');
    },
    image: () => {
      const url = prompt('Enter image URL:');
      if (url) insertText('![', `](${url})`, 'alt text');
    },
    code: () => insertText('`', '`', 'code'),
    codeBlock: () => insertText('```\n', '\n```', 'code block'),
    quote: () => insertText('> ', '', 'quote'),
    bulletList: () => insertText('- ', '', 'list item'),
    numberedList: () => insertText('1. ', '', 'list item'),
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey) {
        switch (e.key.toLowerCase()) {
          case 'b':
            e.preventDefault();
            actions.bold();
            break;
          case 'i':
            e.preventDefault();
            actions.italic();
            break;
          case 'k':
            e.preventDefault();
            actions.link();
            break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [value]);

  // Simple markdown to HTML converter for preview
  const renderMarkdown = (text: string) => {
    return text
      .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold mt-4 mb-2">$1</h3>')
      .replace(/^## (.*$)/gim, '<h2 class="text-xl font-semibold mt-4 mb-2">$1</h2>')
      .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold mt-4 mb-2">$1</h1>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code class="bg-gray-100 dark:bg-gray-800 px-1 py-0.5 rounded text-sm font-mono">$1</code>')
      .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" class="text-blue-600 hover:underline">$1</a>')
      .replace(/!\[(.*?)\]\((.*?)\)/g, '<img src="$2" alt="$1" class="max-w-full h-auto rounded my-2" />')
      .replace(/^> (.*$)/gim, '<blockquote class="border-l-4 border-gray-300 pl-4 italic my-2">$1</blockquote>')
      .replace(/^- (.*$)/gim, '<li class="ml-4">$1</li>')
      .replace(/^\d+\. (.*$)/gim, '<li class="ml-4">$1</li>')
      .replace(/\n/g, '<br />');
  };

  return (
    <div className="border border-gray-300 dark:border-gray-600 rounded-lg overflow-hidden bg-white dark:bg-gray-800">
      {/* Toolbar */}
      <div className="flex items-center gap-1 p-2 border-b border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 flex-wrap">
        {/* Text Style */}
        <div className="flex items-center gap-1 pr-2 border-r border-gray-300 dark:border-gray-600">
          <button
            onClick={actions.bold}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Bold (Ctrl+B)"
          >
            <Bold className="w-4 h-4" />
          </button>
          <button
            onClick={actions.italic}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Italic (Ctrl+I)"
          >
            <Italic className="w-4 h-4" />
          </button>
          <button
            onClick={actions.underline}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Underline"
          >
            <Underline className="w-4 h-4" />
          </button>
        </div>

        {/* Headings */}
        <div className="flex items-center gap-1 pr-2 border-r border-gray-300 dark:border-gray-600">
          <button
            onClick={actions.h1}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Heading 1"
          >
            <Heading1 className="w-4 h-4" />
          </button>
          <button
            onClick={actions.h2}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Heading 2"
          >
            <Heading2 className="w-4 h-4" />
          </button>
          <button
            onClick={actions.h3}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Heading 3"
          >
            <Heading3 className="w-4 h-4" />
          </button>
        </div>

        {/* Lists */}
        <div className="flex items-center gap-1 pr-2 border-r border-gray-300 dark:border-gray-600">
          <button
            onClick={actions.bulletList}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Bullet List"
          >
            <List className="w-4 h-4" />
          </button>
          <button
            onClick={actions.numberedList}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Numbered List"
          >
            <ListOrdered className="w-4 h-4" />
          </button>
        </div>

        {/* Insert */}
        <div className="flex items-center gap-1 pr-2 border-r border-gray-300 dark:border-gray-600">
          <button
            onClick={actions.link}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Insert Link (Ctrl+K)"
          >
            <Link className="w-4 h-4" />
          </button>
          <button
            onClick={actions.image}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Insert Image"
          >
            <Image className="w-4 h-4" />
          </button>
          <button
            onClick={actions.code}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Inline Code"
          >
            <Code className="w-4 h-4" />
          </button>
          <button
            onClick={actions.quote}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
            title="Quote"
          >
            <Quote className="w-4 h-4" />
          </button>
        </div>

        {/* Preview Toggle */}
        <button
          onClick={() => setShowPreview(!showPreview)}
          className={`p-1.5 rounded transition ml-auto ${
            showPreview 
              ? 'bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400' 
              : 'hover:bg-gray-200 dark:hover:bg-gray-600'
          }`}
          title="Toggle Preview"
        >
          <Eye className="w-4 h-4" />
        </button>
      </div>

      {/* Editor / Preview */}
      <div className="flex">
        {/* Editor */}
        {!showPreview && (
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onSelect={handleSelect}
            placeholder={placeholder}
            style={{ minHeight, maxHeight }}
            className="w-full p-4 font-mono text-sm resize-y focus:outline-none 
                     bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          />
        )}

        {/* Preview */}
        {showPreview && (
          <div
            style={{ minHeight, maxHeight }}
            className="w-full p-4 prose dark:prose-invert max-w-none overflow-y-auto"
            dangerouslySetInnerHTML={{ __html: renderMarkdown(value) }}
          />
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between px-3 py-2 border-t border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-xs text-gray-600 dark:text-gray-400">
        <div>
          Markdown supported: **bold**, *italic*, `code`, [link](url), # heading
        </div>
        <div>
          {value.length} characters
        </div>
      </div>
    </div>
  );
};

export default RichTextEditor;