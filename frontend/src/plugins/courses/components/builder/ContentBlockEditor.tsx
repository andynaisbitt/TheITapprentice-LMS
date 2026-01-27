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
  QuizQuestion,
  QuestionType
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

  const addQuestion = (type: QuestionType = 'multiple_choice') => {
    const baseQuestion = {
      id: `q-${Date.now()}`,
      type,
      question: 'New question',
      explanation: '',
      points: 10
    };

    // Set default options and correct_answer based on type
    let newQuestion: QuizQuestion;
    switch (type) {
      case 'multiple_choice':
        newQuestion = {
          ...baseQuestion,
          options: ['Option 1', 'Option 2', 'Option 3', 'Option 4'],
          correct_answer: 'Option 1'
        };
        break;
      case 'multiple_select':
        newQuestion = {
          ...baseQuestion,
          options: ['Option 1', 'Option 2', 'Option 3', 'Option 4'],
          correct_answer: ['Option 1'] // Array for multiple correct
        };
        break;
      case 'true_false':
        newQuestion = {
          ...baseQuestion,
          options: ['True', 'False'],
          correct_answer: 'True'
        };
        break;
      case 'short_answer':
      case 'fill_blank':
        newQuestion = {
          ...baseQuestion,
          correct_answer: ''
        };
        break;
      case 'code_challenge':
        newQuestion = {
          ...baseQuestion,
          correct_answer: '',
          code_snippet: '// Starter code here',
          language: 'javascript'
        };
        break;
      default:
        newQuestion = {
          ...baseQuestion,
          options: ['Option 1', 'Option 2'],
          correct_answer: 'Option 1'
        };
    }

    const newQuestions = [...questions, newQuestion];
    setQuestions(newQuestions);
    onUpdate({ content: { ...content, questions: newQuestions } });
  };

  const changeQuestionType = (index: number, newType: QuestionType) => {
    // Reset correct_answer and options based on new type
    const updates: Partial<QuizQuestion> = { type: newType };

    switch (newType) {
      case 'multiple_choice':
        updates.options = ['Option 1', 'Option 2', 'Option 3', 'Option 4'];
        updates.correct_answer = 'Option 1';
        break;
      case 'multiple_select':
        updates.options = ['Option 1', 'Option 2', 'Option 3', 'Option 4'];
        updates.correct_answer = [];
        break;
      case 'true_false':
        updates.options = ['True', 'False'];
        updates.correct_answer = 'True';
        break;
      case 'short_answer':
      case 'fill_blank':
        updates.options = undefined;
        updates.correct_answer = '';
        break;
      case 'code_challenge':
        updates.options = undefined;
        updates.correct_answer = '';
        updates.code_snippet = '// Starter code';
        updates.language = 'javascript';
        break;
    }

    updateQuestion(index, updates);
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
              <div className="flex-1 space-y-2">
                <div className="flex items-center gap-2">
                  <label className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                    Q{index + 1}
                  </label>
                  <select
                    value={question.type}
                    onChange={(e) => changeQuestionType(index, e.target.value as QuestionType)}
                    className="px-2 py-1 text-xs border border-gray-300 dark:border-gray-600 rounded
                             bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="multiple_choice">Multiple Choice</option>
                    <option value="multiple_select">Multiple Select</option>
                    <option value="true_false">True/False</option>
                    <option value="short_answer">Short Answer</option>
                    <option value="fill_blank">Fill in Blank</option>
                    <option value="code_challenge">Code Challenge</option>
                  </select>
                  <input
                    type="number"
                    value={question.points}
                    onChange={(e) => updateQuestion(index, { points: parseInt(e.target.value) || 1 })}
                    className="w-16 px-2 py-1 text-xs border border-gray-300 dark:border-gray-600 rounded
                             bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    min="1"
                    title="Points"
                  />
                  <span className="text-xs text-gray-500">pts</span>
                </div>
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

            {/* Multiple Choice - radio buttons to select ONE correct answer */}
            {question.type === 'multiple_choice' && question.options && (
              <div className="space-y-1">
                <p className="text-xs text-gray-500 dark:text-gray-400">Select the correct answer:</p>
                {question.options.map((option, optIndex) => (
                  <div key={optIndex} className="flex items-center gap-2">
                    <input
                      type="radio"
                      checked={question.correct_answer === option}
                      onChange={() => updateQuestion(index, { correct_answer: option })}
                      className="text-blue-600"
                      title="Mark as correct"
                    />
                    <input
                      type="text"
                      value={option}
                      onChange={(e) => {
                        const newOptions = [...question.options!];
                        const oldOption = newOptions[optIndex];
                        newOptions[optIndex] = e.target.value;
                        // Update correct_answer if this was the correct option
                        const updates: Partial<QuizQuestion> = { options: newOptions };
                        if (question.correct_answer === oldOption) {
                          updates.correct_answer = e.target.value;
                        }
                        updateQuestion(index, updates);
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

            {/* Multiple Select - checkboxes to select MULTIPLE correct answers */}
            {question.type === 'multiple_select' && question.options && (
              <div className="space-y-1">
                <p className="text-xs text-gray-500 dark:text-gray-400">Check all correct answers:</p>
                {question.options.map((option, optIndex) => {
                  const correctAnswers = Array.isArray(question.correct_answer) ? question.correct_answer : [];
                  const isCorrect = correctAnswers.includes(option);
                  return (
                    <div key={optIndex} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={isCorrect}
                        onChange={() => {
                          const newCorrect = isCorrect
                            ? correctAnswers.filter(a => a !== option)
                            : [...correctAnswers, option];
                          updateQuestion(index, { correct_answer: newCorrect });
                        }}
                        className="text-blue-600 rounded"
                        title="Mark as correct"
                      />
                      <input
                        type="text"
                        value={option}
                        onChange={(e) => {
                          const newOptions = [...question.options!];
                          const oldOption = newOptions[optIndex];
                          newOptions[optIndex] = e.target.value;
                          // Update correct_answer array if this was a correct option
                          let newCorrect = [...correctAnswers];
                          const wasCorrect = newCorrect.includes(oldOption);
                          if (wasCorrect) {
                            newCorrect = newCorrect.map(a => a === oldOption ? e.target.value : a);
                          }
                          updateQuestion(index, { options: newOptions, correct_answer: newCorrect });
                        }}
                        className="flex-1 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded
                                 focus:outline-none focus:ring-1 focus:ring-blue-500
                                 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                        placeholder={`Option ${optIndex + 1}`}
                      />
                    </div>
                  );
                })}
              </div>
            )}

            {/* True/False - radio buttons */}
            {question.type === 'true_false' && (
              <div className="space-y-1">
                <p className="text-xs text-gray-500 dark:text-gray-400">Select the correct answer:</p>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      checked={question.correct_answer === 'True'}
                      onChange={() => updateQuestion(index, { correct_answer: 'True' })}
                      className="text-blue-600"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">True</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      checked={question.correct_answer === 'False'}
                      onChange={() => updateQuestion(index, { correct_answer: 'False' })}
                      className="text-blue-600"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">False</span>
                  </label>
                </div>
              </div>
            )}

            {/* Short Answer / Fill in Blank - text input for correct answer */}
            {(question.type === 'short_answer' || question.type === 'fill_blank') && (
              <div className="space-y-1">
                <label className="block text-xs text-gray-500 dark:text-gray-400">
                  Correct answer(s) - separate multiple accepted answers with commas:
                </label>
                <input
                  type="text"
                  value={Array.isArray(question.correct_answer)
                    ? question.correct_answer.join(', ')
                    : question.correct_answer || ''}
                  onChange={(e) => {
                    const value = e.target.value;
                    // If contains comma, store as array
                    const answers = value.includes(',')
                      ? value.split(',').map(a => a.trim()).filter(a => a)
                      : value;
                    updateQuestion(index, { correct_answer: answers });
                  }}
                  className="w-full px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded
                           focus:outline-none focus:ring-1 focus:ring-blue-500
                           bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder={question.type === 'fill_blank' ? 'e.g., answer, Answer, ANSWER' : 'Enter the expected answer'}
                />
              </div>
            )}

            {/* Code Challenge - code snippet and expected output */}
            {question.type === 'code_challenge' && (
              <div className="space-y-2">
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                    Language:
                  </label>
                  <select
                    value={question.language || 'javascript'}
                    onChange={(e) => updateQuestion(index, { language: e.target.value })}
                    className="px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded
                             bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="javascript">JavaScript</option>
                    <option value="python">Python</option>
                    <option value="typescript">TypeScript</option>
                    <option value="html">HTML</option>
                    <option value="css">CSS</option>
                    <option value="sql">SQL</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                    Starter code (optional):
                  </label>
                  <textarea
                    value={question.code_snippet || ''}
                    onChange={(e) => updateQuestion(index, { code_snippet: e.target.value })}
                    className="w-full px-2 py-1 text-sm font-mono border border-gray-300 dark:border-gray-600 rounded
                             focus:outline-none focus:ring-1 focus:ring-blue-500
                             bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    rows={3}
                    placeholder="// Starter code for the student"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                    Expected output/answer:
                  </label>
                  <textarea
                    value={question.correct_answer as string || ''}
                    onChange={(e) => updateQuestion(index, { correct_answer: e.target.value })}
                    className="w-full px-2 py-1 text-sm font-mono border border-gray-300 dark:border-gray-600 rounded
                             focus:outline-none focus:ring-1 focus:ring-blue-500
                             bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    rows={2}
                    placeholder="Expected output or code solution"
                  />
                </div>
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

      {/* Add Question Buttons */}
      <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded p-3">
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-2 text-center">Add Question:</p>
        <div className="flex flex-wrap gap-2 justify-center">
          <button
            onClick={() => addQuestion('multiple_choice')}
            className="px-3 py-1.5 text-xs bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400
                     hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded transition"
          >
            Multiple Choice
          </button>
          <button
            onClick={() => addQuestion('multiple_select')}
            className="px-3 py-1.5 text-xs bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400
                     hover:bg-purple-100 dark:hover:bg-purple-900/50 rounded transition"
          >
            Multiple Select
          </button>
          <button
            onClick={() => addQuestion('true_false')}
            className="px-3 py-1.5 text-xs bg-green-50 dark:bg-green-900/30 text-green-600 dark:text-green-400
                     hover:bg-green-100 dark:hover:bg-green-900/50 rounded transition"
          >
            True/False
          </button>
          <button
            onClick={() => addQuestion('short_answer')}
            className="px-3 py-1.5 text-xs bg-yellow-50 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400
                     hover:bg-yellow-100 dark:hover:bg-yellow-900/50 rounded transition"
          >
            Short Answer
          </button>
          <button
            onClick={() => addQuestion('fill_blank')}
            className="px-3 py-1.5 text-xs bg-orange-50 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400
                     hover:bg-orange-100 dark:hover:bg-orange-900/50 rounded transition"
          >
            Fill in Blank
          </button>
          <button
            onClick={() => addQuestion('code_challenge')}
            className="px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400
                     hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition"
          >
            Code Challenge
          </button>
        </div>
      </div>
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