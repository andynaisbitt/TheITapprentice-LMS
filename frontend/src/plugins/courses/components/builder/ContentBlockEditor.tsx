// src/components/course-builder/ContentBlockEditor.tsx
/**
 * Content Block Editor - Renders appropriate editor for each block type
 */

import React, { useState } from 'react';
import {
  ContentBlock,
  TextBlockContent,
  HeadingBlockContent,
  QuizBlockContent,
  VideoBlockContent,
  CodeBlockContent,
  ImageBlockContent,
  CalloutBlockContent,
  TimelineBlockContent,
  InteractiveBlockContent,
  DividerBlockContent,
  QuizQuestion
} from '../../types';
import { 
  Trash2, 
  GripVertical, 
  ChevronDown, 
  ChevronUp,
  Plus,
  X
} from 'lucide-react';
import { RichTextEditor } from './RichTextEditor';

interface ContentBlockEditorProps {
  block: ContentBlock;
  index: number;
  onUpdate: (updates: Partial<ContentBlock>) => void;
  onDelete: () => void;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
}

export const ContentBlockEditor: React.FC<ContentBlockEditorProps> = ({
  block,
  index,
  onUpdate,
  onDelete,
  onMoveUp,
  onMoveDown
}) => {
  const [isExpanded, setIsExpanded] = useState(true);

  const renderBlockEditor = () => {
    switch (block.type) {
      case 'text':
        return <TextBlockEditor content={block.content as TextBlockContent} onUpdate={onUpdate} />;
      case 'heading':
        return <HeadingBlockEditor content={block.content as HeadingBlockContent} onUpdate={onUpdate} />;
      case 'quiz':
        return <QuizBlockEditor content={block.content as QuizBlockContent} onUpdate={onUpdate} />;
      case 'video':
        return <VideoBlockEditor content={block.content as VideoBlockContent} onUpdate={onUpdate} />;
      case 'code':
        return <CodeBlockEditor content={block.content as CodeBlockContent} onUpdate={onUpdate} />;
      case 'image':
        return <ImageBlockEditor content={block.content as ImageBlockContent} onUpdate={onUpdate} />;
      case 'callout':
        return <CalloutBlockEditor content={block.content as CalloutBlockContent} onUpdate={onUpdate} />;
      case 'timeline':
        return <TimelineBlockEditor content={block.content as TimelineBlockContent} onUpdate={onUpdate} />;
      case 'interactive':
        return <InteractiveBlockEditor content={block.content as InteractiveBlockContent} onUpdate={onUpdate} />;
      case 'divider':
        return <DividerBlockEditor content={block.content as DividerBlockContent} onUpdate={onUpdate} />;
      default:
        return <div>Unknown block type</div>;
    }
  };

  const getBlockIcon = () => {
    const icons: Record<string, string> = {
      text: '📝',
      heading: '📌',
      quiz: '❓',
      video: '🎥',
      code: '💻',
      image: '🖼️',
      callout: '💡',
      timeline: '📅',
      interactive: '🎮',
      divider: '➖'
    };
    return icons[block.type] || '📦';
  };

  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      {/* Block Header */}
      <div className="flex items-center gap-2 p-3 bg-gray-50 dark:bg-gray-700/50 border-b border-gray-200 dark:border-gray-700">
        <button className="cursor-move text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
          <GripVertical className="w-4 h-4" />
        </button>
        
        <span className="text-lg">{getBlockIcon()}</span>
        
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize flex-1">
          {block.type} Block
        </span>
        
        {/* Move buttons */}
        <div className="flex items-center gap-1">
          {onMoveUp && (
            <button
              onClick={onMoveUp}
              className="p-1 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 rounded"
              title="Move up"
            >
              <ChevronUp className="w-4 h-4" />
            </button>
          )}
          {onMoveDown && (
            <button
              onClick={onMoveDown}
              className="p-1 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 rounded"
              title="Move down"
            >
              <ChevronDown className="w-4 h-4" />
            </button>
          )}
        </div>
        
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="p-1 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
        >
          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        
        <button
          onClick={onDelete}
          className="p-1 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>

      {/* Block Content */}
      {isExpanded && (
        <div className="p-4">
          {renderBlockEditor()}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// INDIVIDUAL BLOCK EDITORS
// ============================================================================

// TEXT BLOCK
const TextBlockEditor: React.FC<{
  content: TextBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => {
  const [useRichEditor, setUseRichEditor] = useState(content.format === 'markdown');

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Format
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={useRichEditor}
            onChange={(e) => {
              setUseRichEditor(e.target.checked);
              onUpdate({ content: { ...content, format: e.target.checked ? 'markdown' : 'plain' } });
            }}
            className="rounded"
          />
          <span className="text-sm text-gray-700 dark:text-gray-300">Use Rich Editor</span>
        </label>
      </div>

      {useRichEditor ? (
        <RichTextEditor
          value={content.text}
          onChange={(text) => onUpdate({ content: { ...content, text } })}
          placeholder="Start typing your content..."
          minHeight="300px"
          showPreview={true}
        />
      ) : (
        <>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Format
            </label>
            <select
              value={content.format || 'plain'}
              onChange={(e) => onUpdate({ content: { ...content, format: e.target.value } })}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                       focus:outline-none focus:ring-2 focus:ring-blue-500 
                       bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="plain">Plain Text</option>
              <option value="markdown">Markdown</option>
              <option value="html">HTML</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Content
            </label>
            <textarea
              value={content.text}
              onChange={(e) => onUpdate({ content: { ...content, text: e.target.value } })}
              rows={8}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                       focus:outline-none focus:ring-2 focus:ring-blue-500 
                       bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
              placeholder="Enter your content here..."
            />
          </div>
          {content.format === 'markdown' && (
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Supports: **bold**, *italic*, `code`, [links](url), # headers, - lists
            </div>
          )}
        </>
      )}
    </div>
  );
};

// HEADING BLOCK
const HeadingBlockEditor: React.FC<{
  content: HeadingBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Heading Level
      </label>
      <select
        value={content.level}
        onChange={(e) => onUpdate({ content: { ...content, level: parseInt(e.target.value) } })}
        className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
      >
        <option value="1">H1 - Main Title</option>
        <option value="2">H2 - Section</option>
        <option value="3">H3 - Subsection</option>
        <option value="4">H4 - Small Heading</option>
        <option value="5">H5 - Tiny Heading</option>
        <option value="6">H6 - Micro Heading</option>
      </select>
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Heading Text
      </label>
      <input
        type="text"
        value={content.text}
        onChange={(e) => onUpdate({ content: { ...content, text: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="Enter heading text"
      />
    </div>
    {/* Preview */}
    <div className="mt-4 p-3 bg-gray-50 dark:bg-gray-700 rounded border border-gray-200 dark:border-gray-600">
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Preview:</p>
      {React.createElement(
        `h${content.level}`,
        { className: 'text-gray-900 dark:text-white' },
        content.text || 'Heading Preview'
      )}
    </div>
  </div>
);

// QUIZ BLOCK
const QuizBlockEditor: React.FC<{
  content: QuizBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => {
  const [questions, setQuestions] = useState<QuizQuestion[]>(content.questions || []);

  const addQuestion = () => {
    const newQuestion: QuizQuestion = {
      id: `q-${Date.now()}`,
      type: 'multiple_choice',
      question: 'New question',
      options: ['Option 1', 'Option 2', 'Option 3', 'Option 4'],
      correct_answer: 'Option 1',
      explanation: '',
      points: 10
    };
    const newQuestions = [...questions, newQuestion];
    setQuestions(newQuestions);
    onUpdate({ content: { ...content, questions: newQuestions } });
  };

  const updateQuestion = (index: number, updates: Partial<QuizQuestion>) => {
    const newQuestions = questions.map((q, i) => i === index ? { ...q, ...updates } : q);
    setQuestions(newQuestions);
    onUpdate({ content: { ...content, questions: newQuestions } });
  };

  const deleteQuestion = (index: number) => {
    const newQuestions = questions.filter((_, i) => i !== index);
    setQuestions(newQuestions);
    onUpdate({ content: { ...content, questions: newQuestions } });
  };

  return (
    <div className="space-y-4">
      {/* Quiz Settings */}
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
            Passing Score (%)
          </label>
          <input
            type="number"
            value={content.passing_score || 70}
            onChange={(e) => onUpdate({ content: { ...content, passing_score: parseInt(e.target.value) } })}
            className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                     focus:outline-none focus:ring-1 focus:ring-blue-500 
                     bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            min="0"
            max="100"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
            Max Attempts
          </label>
          <input
            type="number"
            value={content.max_attempts || 3}
            onChange={(e) => onUpdate({ content: { ...content, max_attempts: parseInt(e.target.value) } })}
            className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                     focus:outline-none focus:ring-1 focus:ring-blue-500 
                     bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            min="1"
          />
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={content.shuffle_questions || false}
              onChange={(e) => onUpdate({ content: { ...content, shuffle_questions: e.target.checked } })}
              className="rounded"
            />
            <span className="text-xs text-gray-700 dark:text-gray-300">Shuffle</span>
          </label>
        </div>
      </div>

      {/* Questions */}
      <div className="space-y-3">
        {questions.map((question, index) => (
          <div key={question.id} className="border border-gray-300 dark:border-gray-600 rounded p-3 space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1">
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Question {index + 1}
                </label>
                <input
                  type="text"
                  value={question.question}
                  onChange={(e) => updateQuestion(index, { question: e.target.value })}
                  className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                           focus:outline-none focus:ring-1 focus:ring-blue-500 
                           bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="Enter question"
                />
              </div>
              <button
                onClick={() => deleteQuestion(index)}
                className="p-1 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Options for multiple choice */}
            {question.type === 'multiple_choice' && question.options && (
              <div className="space-y-1">
                {question.options.map((option, optIndex) => (
                  <div key={optIndex} className="flex items-center gap-2">
                    <input
                      type="radio"
                      checked={question.correct_answer === option}
                      onChange={() => updateQuestion(index, { correct_answer: option })}
                      className="text-blue-600"
                    />
                    <input
                      type="text"
                      value={option}
                      onChange={(e) => {
                        const newOptions = [...question.options!];
                        newOptions[optIndex] = e.target.value;
                        updateQuestion(index, { options: newOptions });
                      }}
                      className="flex-1 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                               focus:outline-none focus:ring-1 focus:ring-blue-500 
                               bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      placeholder={`Option ${optIndex + 1}`}
                    />
                  </div>
                ))}
              </div>
            )}

            {/* Explanation */}
            <div>
              <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                Explanation (optional)
              </label>
              <input
                type="text"
                value={question.explanation || ''}
                onChange={(e) => updateQuestion(index, { explanation: e.target.value })}
                className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded 
                         focus:outline-none focus:ring-1 focus:ring-blue-500 
                         bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Explain the correct answer"
              />
            </div>
          </div>
        ))}
      </div>

      <button
        onClick={addQuestion}
        className="w-full py-2 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded 
                 hover:border-blue-500 dark:hover:border-blue-400 transition
                 text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400
                 flex items-center justify-center gap-2 text-sm"
      >
        <Plus className="w-4 h-4" />
        Add Question
      </button>
    </div>
  );
};

// VIDEO BLOCK
const VideoBlockEditor: React.FC<{
  content: VideoBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Video Provider
      </label>
      <select
        value={content.provider}
        onChange={(e) => onUpdate({ content: { ...content, provider: e.target.value } })}
        className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
      >
        <option value="youtube">YouTube</option>
        <option value="vimeo">Vimeo</option>
        <option value="direct">Direct URL</option>
      </select>
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Video URL
      </label>
      <input
        type="text"
        value={content.url}
        onChange={(e) => onUpdate({ content: { ...content, url: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="https://youtube.com/watch?v=..."
      />
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Caption (optional)
      </label>
      <input
        type="text"
        value={content.caption || ''}
        onChange={(e) => onUpdate({ content: { ...content, caption: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="Video description"
      />
    </div>
  </div>
);

// CODE BLOCK
const CodeBlockEditor: React.FC<{
  content: CodeBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Language
        </label>
        <select
          value={content.language}
          onChange={(e) => onUpdate({ content: { ...content, language: e.target.value } })}
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                   focus:outline-none focus:ring-2 focus:ring-blue-500 
                   bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        >
          <option value="javascript">JavaScript</option>
          <option value="python">Python</option>
          <option value="typescript">TypeScript</option>
          <option value="java">Java</option>
          <option value="csharp">C#</option>
          <option value="cpp">C++</option>
          <option value="html">HTML</option>
          <option value="css">CSS</option>
          <option value="sql">SQL</option>
          <option value="bash">Bash</option>
        </select>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Filename (optional)
        </label>
        <input
          type="text"
          value={content.filename || ''}
          onChange={(e) => onUpdate({ content: { ...content, filename: e.target.value } })}
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                   focus:outline-none focus:ring-2 focus:ring-blue-500 
                   bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          placeholder="example.js"
        />
      </div>
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Code
      </label>
      <textarea
        value={content.code}
        onChange={(e) => onUpdate({ content: { ...content, code: e.target.value } })}
        rows={10}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
        placeholder="// Your code here"
      />
    </div>
    <div className="flex items-center gap-4">
      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={content.runnable || false}
          onChange={(e) => onUpdate({ content: { ...content, runnable: e.target.checked } })}
          className="rounded"
        />
        <span className="text-sm text-gray-700 dark:text-gray-300">Runnable</span>
      </label>
      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={content.editable || false}
          onChange={(e) => onUpdate({ content: { ...content, editable: e.target.checked } })}
          className="rounded"
        />
        <span className="text-sm text-gray-700 dark:text-gray-300">Editable</span>
      </label>
    </div>
  </div>
);

// IMAGE BLOCK
const ImageBlockEditor: React.FC<{
  content: ImageBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Image URL
      </label>
      <input
        type="text"
        value={content.url}
        onChange={(e) => onUpdate({ content: { ...content, url: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="https://example.com/image.jpg"
      />
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Alt Text (for accessibility)
      </label>
      <input
        type="text"
        value={content.alt}
        onChange={(e) => onUpdate({ content: { ...content, alt: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="Describe the image"
      />
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Caption (optional)
      </label>
      <input
        type="text"
        value={content.caption || ''}
        onChange={(e) => onUpdate({ content: { ...content, caption: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="Image caption"
      />
    </div>
    {content.url && (
      <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-700 rounded border border-gray-200 dark:border-gray-600">
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Preview:</p>
        <img src={content.url} alt={content.alt} className="max-w-full h-auto rounded" />
      </div>
    )}
  </div>
);

// CALLOUT BLOCK
const CalloutBlockEditor: React.FC<{
  content: CalloutBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Callout Type
      </label>
      <select
        value={content.type}
        onChange={(e) => onUpdate({ content: { ...content, type: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
      >
        <option value="info">ℹ️ Info</option>
        <option value="warning">⚠️ Warning</option>
        <option value="success">✅ Success</option>
        <option value="error">❌ Error</option>
        <option value="tip">💡 Tip</option>
      </select>
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Title (optional)
      </label>
      <input
        type="text"
        value={content.title || ''}
        onChange={(e) => onUpdate({ content: { ...content, title: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="Callout title"
      />
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Content
      </label>
      <textarea
        value={content.content}
        onChange={(e) => onUpdate({ content: { ...content, content: e.target.value } })}
        rows={4}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="Callout content"
      />
    </div>
  </div>
);

// TIMELINE BLOCK (Simplified)
const TimelineBlockEditor: React.FC<{
  content: TimelineBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div className="text-sm text-gray-600 dark:text-gray-400">
      Timeline editor - Advanced feature coming soon
    </div>
    <textarea
      value={JSON.stringify(content, null, 2)}
      onChange={(e) => {
        try {
          const parsed = JSON.parse(e.target.value);
          onUpdate({ content: parsed });
        } catch (e) {
          // Invalid JSON, ignore
        }
      }}
      rows={6}
      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
               focus:outline-none focus:ring-2 focus:ring-blue-500 
               bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-xs"
    />
  </div>
);

// INTERACTIVE BLOCK (Simplified)
const InteractiveBlockEditor: React.FC<{
  content: InteractiveBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Component Name
      </label>
      <input
        type="text"
        value={content.component_name}
        onChange={(e) => onUpdate({ content: { ...content, component_name: e.target.value } })}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        placeholder="ComponentName"
      />
    </div>
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Props (JSON)
      </label>
      <textarea
        value={JSON.stringify(content.props || {}, null, 2)}
        onChange={(e) => {
          try {
            const parsed = JSON.parse(e.target.value);
            onUpdate({ content: { ...content, props: parsed } });
          } catch (e) {
            // Invalid JSON, ignore
          }
        }}
        rows={4}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                 focus:outline-none focus:ring-2 focus:ring-blue-500 
                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
      />
    </div>
  </div>
);

// DIVIDER BLOCK
const DividerBlockEditor: React.FC<{
  content: DividerBlockContent;
  onUpdate: (updates: any) => void;
}> = ({ content, onUpdate }) => (
  <div className="space-y-3">
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Style
        </label>
        <select
          value={content.style || 'solid'}
          onChange={(e) => onUpdate({ content: { ...content, style: e.target.value } })}
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                   focus:outline-none focus:ring-2 focus:ring-blue-500 
                   bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        >
          <option value="solid">Solid</option>
          <option value="dashed">Dashed</option>
          <option value="dotted">Dotted</option>
        </select>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Spacing
        </label>
        <select
          value={content.spacing || 'medium'}
          onChange={(e) => onUpdate({ content: { ...content, spacing: e.target.value } })}
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg 
                   focus:outline-none focus:ring-2 focus:ring-blue-500 
                   bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        >
          <option value="small">Small</option>
          <option value="medium">Medium</option>
          <option value="large">Large</option>
        </select>
      </div>
    </div>
  </div>
);

export default ContentBlockEditor;