// frontend/src/plugins/quizzes/components/QuizImportModal.tsx
/**
 * Quiz Import Modal - Bulk import questions from JSON/CSV
 */
import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, Download, FileJson, FileSpreadsheet, X, CheckCircle, AlertTriangle, HelpCircle } from 'lucide-react';
import type { QuestionCreateInput, QuestionType } from '../types';

interface QuizImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImport: (questions: QuestionCreateInput[]) => Promise<void>;
  quizId: string;
}

interface ParsedQuestion {
  question_type: QuestionType;
  question_text: string;
  options?: { id: string; text: string; is_correct: boolean }[];
  correct_answer: string;
  explanation?: string;
  points?: number;
  valid: boolean;
  error?: string;
}

const VALID_QUESTION_TYPES: QuestionType[] = [
  'multiple_choice',
  'multiple_select',
  'true_false',
  'short_answer',
  'code',
  'fill_blank',
];

// JSON Template
const JSON_TEMPLATE = {
  questions: [
    {
      question_type: 'multiple_choice',
      question_text: 'What is the capital of France?',
      options: [
        { id: 'a', text: 'London', is_correct: false },
        { id: 'b', text: 'Paris', is_correct: true },
        { id: 'c', text: 'Berlin', is_correct: false },
        { id: 'd', text: 'Madrid', is_correct: false },
      ],
      explanation: 'Paris is the capital and largest city of France.',
      points: 1,
    },
    {
      question_type: 'true_false',
      question_text: 'The Earth is flat.',
      correct_answer: 'false',
      explanation: 'The Earth is an oblate spheroid.',
      points: 1,
    },
    {
      question_type: 'short_answer',
      question_text: 'What programming language is React written in?',
      correct_answer: 'JavaScript',
      explanation: 'React is a JavaScript library.',
      points: 2,
    },
  ],
};

// CSV Template
const CSV_TEMPLATE = `question_type,question_text,option_a,option_b,option_c,option_d,correct_answer,explanation,points
multiple_choice,What is 2+2?,3,4,5,6,b,Basic addition,1
true_false,The sky is blue,,,,,true,Due to Rayleigh scattering,1
short_answer,What is the chemical symbol for water?,,,,,H2O,Water molecule,1`;

export const QuizImportModal: React.FC<QuizImportModalProps> = ({
  isOpen,
  onClose,
  onImport,
  quizId,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importType, setImportType] = useState<'json' | 'csv'>('json');
  const [rawInput, setRawInput] = useState('');
  const [parsedQuestions, setParsedQuestions] = useState<ParsedQuestion[]>([]);
  const [parseError, setParseError] = useState('');
  const [importing, setImporting] = useState(false);
  const [step, setStep] = useState<'input' | 'preview'>('input');

  const resetState = () => {
    setRawInput('');
    setParsedQuestions([]);
    setParseError('');
    setStep('input');
  };

  const handleClose = () => {
    resetState();
    onClose();
  };

  const downloadTemplate = (type: 'json' | 'csv') => {
    let content: string;
    let filename: string;
    let mimeType: string;

    if (type === 'json') {
      content = JSON.stringify(JSON_TEMPLATE, null, 2);
      filename = 'quiz_questions_template.json';
      mimeType = 'application/json';
    } else {
      content = CSV_TEMPLATE;
      filename = 'quiz_questions_template.csv';
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawInput(content);

      // Auto-detect type
      if (file.name.endsWith('.json')) {
        setImportType('json');
      } else if (file.name.endsWith('.csv')) {
        setImportType('csv');
      }
    };
    reader.readAsText(file);

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const parseJSON = (content: string): ParsedQuestion[] => {
    try {
      const data = JSON.parse(content);
      const questions = data.questions || data;

      if (!Array.isArray(questions)) {
        throw new Error('JSON must contain a "questions" array or be an array of questions');
      }

      return questions.map((q: any, idx: number): ParsedQuestion => {
        const errors: string[] = [];

        // Validate question_type
        if (!q.question_type || !VALID_QUESTION_TYPES.includes(q.question_type)) {
          errors.push(`Invalid question_type: ${q.question_type || 'missing'}`);
        }

        // Validate question_text
        if (!q.question_text?.trim()) {
          errors.push('Missing question_text');
        }

        // Validate correct_answer for non-multiple-choice
        if (['true_false', 'short_answer', 'fill_blank'].includes(q.question_type)) {
          if (!q.correct_answer) {
            errors.push('Missing correct_answer');
          }
        }

        // Validate options for multiple choice
        if (['multiple_choice', 'multiple_select'].includes(q.question_type)) {
          if (!q.options || !Array.isArray(q.options) || q.options.length < 2) {
            errors.push('Multiple choice needs at least 2 options');
          } else {
            const hasCorrect = q.options.some((opt: any) => opt.is_correct);
            if (!hasCorrect) {
              errors.push('At least one option must be marked correct');
            }
          }
        }

        return {
          question_type: q.question_type || 'multiple_choice',
          question_text: q.question_text || '',
          options: q.options,
          correct_answer: q.correct_answer || (q.options?.find((o: any) => o.is_correct)?.id || ''),
          explanation: q.explanation,
          points: q.points || 1,
          valid: errors.length === 0,
          error: errors.length > 0 ? errors.join(', ') : undefined,
        };
      });
    } catch (e: any) {
      throw new Error(`JSON Parse Error: ${e.message}`);
    }
  };

  const parseCSV = (content: string): ParsedQuestion[] => {
    const lines = content.trim().split('\n');
    if (lines.length < 2) {
      throw new Error('CSV must have at least a header row and one data row');
    }

    const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
    const requiredHeaders = ['question_type', 'question_text', 'correct_answer'];
    const missingHeaders = requiredHeaders.filter((h) => !headers.includes(h));
    if (missingHeaders.length > 0) {
      throw new Error(`Missing required CSV columns: ${missingHeaders.join(', ')}`);
    }

    return lines.slice(1).map((line, idx): ParsedQuestion => {
      // Handle quoted fields (basic CSV parsing)
      const values: string[] = [];
      let current = '';
      let inQuotes = false;

      for (const char of line) {
        if (char === '"') {
          inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
          values.push(current.trim());
          current = '';
        } else {
          current += char;
        }
      }
      values.push(current.trim());

      const row: Record<string, string> = {};
      headers.forEach((h, i) => {
        row[h] = values[i] || '';
      });

      const errors: string[] = [];
      const questionType = row.question_type as QuestionType;

      if (!VALID_QUESTION_TYPES.includes(questionType)) {
        errors.push(`Invalid question_type: ${questionType}`);
      }
      if (!row.question_text) {
        errors.push('Missing question_text');
      }
      if (!row.correct_answer) {
        errors.push('Missing correct_answer');
      }

      // Build options for multiple choice
      let options: { id: string; text: string; is_correct: boolean }[] | undefined;
      if (['multiple_choice', 'multiple_select'].includes(questionType)) {
        const optionLetters = ['a', 'b', 'c', 'd'];
        options = optionLetters
          .filter((letter) => row[`option_${letter}`])
          .map((letter) => ({
            id: letter,
            text: row[`option_${letter}`],
            is_correct: row.correct_answer?.toLowerCase() === letter,
          }));

        if (options.length < 2) {
          errors.push('Multiple choice needs at least 2 options');
        }
      }

      return {
        question_type: questionType,
        question_text: row.question_text,
        options,
        correct_answer: row.correct_answer,
        explanation: row.explanation,
        points: parseInt(row.points) || 1,
        valid: errors.length === 0,
        error: errors.length > 0 ? errors.join(', ') : undefined,
      };
    });
  };

  const handleParse = () => {
    setParseError('');
    setParsedQuestions([]);

    if (!rawInput.trim()) {
      setParseError('Please paste or upload content first');
      return;
    }

    try {
      const questions = importType === 'json' ? parseJSON(rawInput) : parseCSV(rawInput);
      setParsedQuestions(questions);
      setStep('preview');
    } catch (e: any) {
      setParseError(e.message);
    }
  };

  const handleImport = async () => {
    const validQuestions = parsedQuestions.filter((q) => q.valid);
    if (validQuestions.length === 0) {
      setParseError('No valid questions to import');
      return;
    }

    setImporting(true);
    try {
      const questionsToImport: QuestionCreateInput[] = validQuestions.map((q, idx) => ({
        question_type: q.question_type,
        question_text: q.question_text,
        options: q.options,
        correct_answer: q.correct_answer,
        explanation: q.explanation,
        points: q.points,
        order_index: idx,
      }));

      await onImport(questionsToImport);
      handleClose();
    } catch (e: any) {
      setParseError(e.message || 'Failed to import questions');
    } finally {
      setImporting(false);
    }
  };

  const validCount = parsedQuestions.filter((q) => q.valid).length;
  const invalidCount = parsedQuestions.filter((q) => !q.valid).length;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
        >
          {/* Backdrop */}
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={handleClose} />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="relative bg-white dark:bg-gray-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                  <Upload className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                    Import Questions
                  </h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Bulk import questions from JSON or CSV
                  </p>
                </div>
              </div>
              <button
                onClick={handleClose}
                className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              {step === 'input' && (
                <div className="space-y-6">
                  {/* Template Downloads */}
                  <div className="flex flex-wrap gap-3">
                    <button
                      onClick={() => downloadTemplate('json')}
                      className="flex items-center gap-2 px-4 py-2 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50 transition"
                    >
                      <Download className="w-4 h-4" />
                      <FileJson className="w-4 h-4" />
                      Download JSON Template
                    </button>
                    <button
                      onClick={() => downloadTemplate('csv')}
                      className="flex items-center gap-2 px-4 py-2 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/50 transition"
                    >
                      <Download className="w-4 h-4" />
                      <FileSpreadsheet className="w-4 h-4" />
                      Download CSV Template
                    </button>
                  </div>

                  {/* Format Toggle */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Import Format
                    </label>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setImportType('json')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition ${
                          importType === 'json'
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                        }`}
                      >
                        <FileJson className="w-4 h-4" />
                        JSON
                      </button>
                      <button
                        onClick={() => setImportType('csv')}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition ${
                          importType === 'csv'
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                        }`}
                      >
                        <FileSpreadsheet className="w-4 h-4" />
                        CSV
                      </button>
                    </div>
                  </div>

                  {/* File Upload */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Upload File
                    </label>
                    <div
                      className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center cursor-pointer hover:border-purple-500 dark:hover:border-purple-500 transition"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <Upload className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Click to upload or drag and drop
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                        {importType === 'json' ? '.json files' : '.csv files'}
                      </p>
                    </div>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept={importType === 'json' ? '.json' : '.csv'}
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                  </div>

                  {/* Or paste */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Or Paste Content
                    </label>
                    <textarea
                      value={rawInput}
                      onChange={(e) => setRawInput(e.target.value)}
                      rows={10}
                      placeholder={importType === 'json' ? '{\n  "questions": [...]\n}' : 'question_type,question_text,...'}
                      className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>

                  {/* Error */}
                  {parseError && (
                    <div className="flex items-start gap-3 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                      <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                      <p className="text-sm text-red-700 dark:text-red-300">{parseError}</p>
                    </div>
                  )}
                </div>
              )}

              {step === 'preview' && (
                <div className="space-y-6">
                  {/* Stats */}
                  <div className="flex gap-4">
                    <div className="flex items-center gap-2 px-4 py-2 bg-green-50 dark:bg-green-900/30 rounded-lg">
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                      <span className="font-medium text-green-700 dark:text-green-400">
                        {validCount} valid
                      </span>
                    </div>
                    {invalidCount > 0 && (
                      <div className="flex items-center gap-2 px-4 py-2 bg-red-50 dark:bg-red-900/30 rounded-lg">
                        <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
                        <span className="font-medium text-red-700 dark:text-red-400">
                          {invalidCount} invalid
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Questions Preview */}
                  <div className="space-y-3 max-h-[400px] overflow-y-auto">
                    {parsedQuestions.map((q, idx) => (
                      <div
                        key={idx}
                        className={`p-4 rounded-lg border ${
                          q.valid
                            ? 'bg-white dark:bg-gray-700 border-gray-200 dark:border-gray-600'
                            : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-xs font-medium px-2 py-0.5 bg-gray-100 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded">
                                {q.question_type.replace('_', ' ')}
                              </span>
                              <span className="text-xs text-gray-500 dark:text-gray-400">
                                {q.points} pt{q.points !== 1 ? 's' : ''}
                              </span>
                            </div>
                            <p className="text-gray-900 dark:text-white text-sm">
                              {q.question_text || '(empty question)'}
                            </p>
                            {q.options && q.options.length > 0 && (
                              <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                                Options: {q.options.map((o) => o.text).join(' | ')}
                              </div>
                            )}
                            {q.error && (
                              <p className="mt-2 text-xs text-red-600 dark:text-red-400">
                                {q.error}
                              </p>
                            )}
                          </div>
                          <div className="flex-shrink-0">
                            {q.valid ? (
                              <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                            ) : (
                              <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Error */}
                  {parseError && (
                    <div className="flex items-start gap-3 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                      <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                      <p className="text-sm text-red-700 dark:text-red-300">{parseError}</p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900">
              <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                <HelpCircle className="w-4 h-4" />
                <span>Download a template to see the expected format</span>
              </div>
              <div className="flex gap-3">
                {step === 'preview' && (
                  <button
                    onClick={() => setStep('input')}
                    className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition"
                  >
                    Back
                  </button>
                )}
                <button
                  onClick={handleClose}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                {step === 'input' ? (
                  <button
                    onClick={handleParse}
                    disabled={!rawInput.trim()}
                    className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
                  >
                    Parse & Preview
                  </button>
                ) : (
                  <button
                    onClick={handleImport}
                    disabled={importing || validCount === 0}
                    className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center gap-2"
                  >
                    {importing ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Importing...
                      </>
                    ) : (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        Import {validCount} Question{validCount !== 1 ? 's' : ''}
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default QuizImportModal;
