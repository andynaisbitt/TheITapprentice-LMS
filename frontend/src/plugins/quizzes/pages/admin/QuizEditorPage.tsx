// frontend/src/plugins/quizzes/pages/admin/QuizEditorPage.tsx
/**
 * Quiz Editor Admin Page
 * Create and edit quizzes with question management
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  useAdminQuiz,
  createQuiz,
  updateQuiz,
  addQuestion,
  updateQuestion,
  deleteQuestion,
} from '../../hooks/useQuizzes';
import type {
  QuizCreateInput,
  QuestionCreateInput,
  QuestionType,
  QuizDifficulty,
  QuizStatus,
  QuizQuestion,
  QuestionOption,
} from '../../types';

const questionTypes: { value: QuestionType; label: string }[] = [
  { value: 'multiple_choice', label: 'Multiple Choice' },
  { value: 'multiple_select', label: 'Multiple Select' },
  { value: 'true_false', label: 'True/False' },
  { value: 'short_answer', label: 'Short Answer' },
  { value: 'code', label: 'Code' },
  { value: 'fill_blank', label: 'Fill in the Blank' },
];

const difficulties: QuizDifficulty[] = ['easy', 'medium', 'hard', 'expert'];

const QuizEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isEditing = Boolean(id);

  const { quiz: existingQuiz, loading: loadingQuiz, refetch } = useAdminQuiz(id);

  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'details' | 'questions'>('details');

  // Quiz form state
  const [formData, setFormData] = useState<QuizCreateInput>({
    id: '',
    title: '',
    description: '',
    instructions: '',
    category: '',
    tags: [],
    difficulty: 'medium',
    time_limit_minutes: undefined,
    passing_score: 70,
    max_attempts: 0,
    question_order: 'sequential',
    show_answers_after: true,
    allow_review: true,
    xp_reward: 50,
    xp_perfect: 100,
    status: 'draft',
    is_featured: false,
    questions: [],
  });

  // Question editor state
  const [editingQuestion, setEditingQuestion] = useState<Partial<QuestionCreateInput> & { id?: number } | null>(null);
  const [questionModalOpen, setQuestionModalOpen] = useState(false);

  // Load existing quiz data
  useEffect(() => {
    if (existingQuiz) {
      setFormData({
        id: existingQuiz.id,
        title: existingQuiz.title,
        description: existingQuiz.description || '',
        instructions: existingQuiz.instructions || '',
        category: existingQuiz.category || '',
        tags: existingQuiz.tags || [],
        difficulty: existingQuiz.difficulty,
        time_limit_minutes: existingQuiz.time_limit_minutes || undefined,
        passing_score: existingQuiz.passing_score,
        max_attempts: existingQuiz.max_attempts,
        question_order: existingQuiz.question_order as 'sequential' | 'random',
        show_answers_after: existingQuiz.show_answers_after,
        allow_review: existingQuiz.allow_review,
        xp_reward: existingQuiz.xp_reward,
        xp_perfect: existingQuiz.xp_perfect,
        status: existingQuiz.status,
        is_featured: existingQuiz.is_featured,
      });
    }
  }, [existingQuiz]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'number' ? (value ? parseInt(value) : undefined) : value,
    }));
  };

  const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = e.target;
    setFormData(prev => ({ ...prev, [name]: checked }));
  };

  const handleSaveQuiz = async () => {
    if (!formData.title.trim()) {
      alert('Please enter a quiz title');
      return;
    }

    if (!isEditing && !formData.id.trim()) {
      alert('Please enter a quiz ID');
      return;
    }

    setSaving(true);
    try {
      if (isEditing) {
        await updateQuiz(id!, formData);
      } else {
        await createQuiz(formData);
      }
      navigate('/admin/quizzes');
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to save quiz');
    } finally {
      setSaving(false);
    }
  };

  const openQuestionModal = (question?: QuizQuestion) => {
    if (question) {
      setEditingQuestion({
        id: question.id,
        question_type: question.question_type,
        question_text: question.question_text,
        question_html: question.question_html,
        options: question.options,
        correct_answer: question.correct_answer,
        explanation: question.explanation,
        code_language: question.code_language,
        code_template: question.code_template,
        points: question.points,
        image_url: question.image_url,
      });
    } else {
      setEditingQuestion({
        question_type: 'multiple_choice',
        question_text: '',
        options: [
          { id: 'a', text: '', is_correct: false },
          { id: 'b', text: '', is_correct: false },
          { id: 'c', text: '', is_correct: false },
          { id: 'd', text: '', is_correct: false },
        ],
        correct_answer: '',
        points: 1,
      });
    }
    setQuestionModalOpen(true);
  };

  const handleSaveQuestion = async () => {
    if (!editingQuestion || !id) return;

    // Validate required fields
    if (!editingQuestion.question_text?.trim()) {
      alert('Please enter a question text');
      return;
    }

    // Validate correct answer for multiple choice
    if (editingQuestion.question_type === 'multiple_choice' || editingQuestion.question_type === 'multiple_select') {
      const hasCorrectAnswer = editingQuestion.options?.some(opt => opt.is_correct);
      if (!hasCorrectAnswer) {
        alert('Please select at least one correct answer');
        return;
      }
      const hasEmptyOption = editingQuestion.options?.some(opt => !opt.text?.trim());
      if (hasEmptyOption) {
        alert('Please fill in all answer options');
        return;
      }
    }

    // Validate correct answer for true/false
    if (editingQuestion.question_type === 'true_false' && !editingQuestion.correct_answer) {
      alert('Please select the correct answer (True or False)');
      return;
    }

    // Validate correct answer for short answer/fill blank
    if ((editingQuestion.question_type === 'short_answer' || editingQuestion.question_type === 'fill_blank') && !editingQuestion.correct_answer) {
      alert('Please enter the correct answer');
      return;
    }

    try {
      if (editingQuestion.id) {
        await updateQuestion(editingQuestion.id, editingQuestion);
      } else {
        await addQuestion(id, editingQuestion);
      }
      setQuestionModalOpen(false);
      setEditingQuestion(null);
      refetch();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to save question');
    }
  };

  const handleDeleteQuestion = async (questionId: number) => {
    if (!confirm('Are you sure you want to delete this question?')) return;

    try {
      await deleteQuestion(questionId);
      refetch();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete question');
    }
  };

  if (isEditing && loadingQuiz) {
    return (
      <div className="p-6 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <Link
            to="/admin/quizzes"
            className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              {isEditing ? 'Edit Quiz' : 'Create Quiz'}
            </h1>
            {isEditing && (
              <p className="text-sm text-gray-600 dark:text-gray-400">ID: {id}</p>
            )}
          </div>
        </div>
        <button
          onClick={handleSaveQuiz}
          disabled={saving}
          className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2"
        >
          {saving ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              Saving...
            </>
          ) : (
            <>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              Save Quiz
            </>
          )}
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700 mb-6">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('details')}
            className={`pb-3 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'details'
                ? 'border-purple-600 text-purple-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            }`}
          >
            Quiz Details
          </button>
          {isEditing && (
            <button
              onClick={() => setActiveTab('questions')}
              className={`pb-3 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'questions'
                  ? 'border-purple-600 text-purple-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
              }`}
            >
              Questions ({existingQuiz?.question_count || 0})
            </button>
          )}
        </nav>
      </div>

      {/* Details Tab */}
      {activeTab === 'details' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column - Basic Info */}
          <div className="space-y-6">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h2 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Basic Information</h2>

              {!isEditing && (
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Quiz ID *
                  </label>
                  <input
                    type="text"
                    name="id"
                    value={formData.id}
                    onChange={handleInputChange}
                    placeholder="e.g., python-basics-quiz"
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                  <p className="text-xs text-gray-500 mt-1">URL-friendly identifier (no spaces)</p>
                </div>
              )}

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Title *
                </label>
                <input
                  type="text"
                  name="title"
                  value={formData.title}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Description
                </label>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Instructions
                </label>
                <textarea
                  name="instructions"
                  value={formData.instructions}
                  onChange={handleInputChange}
                  rows={2}
                  placeholder="Instructions shown before starting the quiz"
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Category
                  </label>
                  <input
                    type="text"
                    name="category"
                    value={formData.category}
                    onChange={handleInputChange}
                    placeholder="e.g., Programming"
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Difficulty
                  </label>
                  <select
                    name="difficulty"
                    value={formData.difficulty}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    {difficulties.map(d => (
                      <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Settings */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h2 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Quiz Settings</h2>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Time Limit (minutes)
                  </label>
                  <input
                    type="number"
                    name="time_limit_minutes"
                    value={formData.time_limit_minutes || ''}
                    onChange={handleInputChange}
                    placeholder="No limit"
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Passing Score (%)
                  </label>
                  <input
                    type="number"
                    name="passing_score"
                    value={formData.passing_score}
                    onChange={handleInputChange}
                    min={0}
                    max={100}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Max Attempts (0 = unlimited)
                  </label>
                  <input
                    type="number"
                    name="max_attempts"
                    value={formData.max_attempts}
                    onChange={handleInputChange}
                    min={0}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Question Order
                  </label>
                  <select
                    name="question_order"
                    value={formData.question_order}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="sequential">Sequential</option>
                    <option value="random">Random</option>
                  </select>
                </div>
              </div>

              <div className="space-y-3">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    name="show_answers_after"
                    checked={formData.show_answers_after}
                    onChange={handleCheckboxChange}
                    className="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Show correct answers after completion</span>
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    name="allow_review"
                    checked={formData.allow_review}
                    onChange={handleCheckboxChange}
                    className="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Allow reviewing answers</span>
                </label>
              </div>
            </div>
          </div>

          {/* Right Column - XP & Status */}
          <div className="space-y-6">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h2 className="text-lg font-bold text-gray-900 dark:text-white mb-4">XP Rewards</h2>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    XP for Passing
                  </label>
                  <input
                    type="number"
                    name="xp_reward"
                    value={formData.xp_reward}
                    onChange={handleInputChange}
                    min={0}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    XP for Perfect Score
                  </label>
                  <input
                    type="number"
                    name="xp_perfect"
                    value={formData.xp_perfect}
                    onChange={handleInputChange}
                    min={0}
                    className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h2 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Publishing</h2>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Status
                </label>
                <select
                  name="status"
                  value={formData.status}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="draft">Draft</option>
                  <option value="published">Published</option>
                  <option value="archived">Archived</option>
                </select>
              </div>

              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  name="is_featured"
                  checked={formData.is_featured}
                  onChange={handleCheckboxChange}
                  className="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Featured quiz</span>
              </label>
            </div>

            {!isEditing && (
              <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">
                  <strong>Note:</strong> Save the quiz first, then you can add questions.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Questions Tab */}
      {activeTab === 'questions' && isEditing && existingQuiz && (
        <div>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-bold text-gray-900 dark:text-white">
              Questions ({existingQuiz.questions.length})
            </h2>
            <button
              onClick={() => openQuestionModal()}
              className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add Question
            </button>
          </div>

          {existingQuiz.questions.length === 0 ? (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-12 text-center">
              <p className="text-gray-500 dark:text-gray-400 mb-4">No questions yet. Add your first question!</p>
              <button
                onClick={() => openQuestionModal()}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
              >
                Add Question
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {existingQuiz.questions.map((question, idx) => (
                <div
                  key={question.id}
                  className="bg-white dark:bg-gray-800 rounded-lg shadow p-4"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-4 flex-1">
                      <span className="flex-shrink-0 w-8 h-8 bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded-full flex items-center justify-center font-bold">
                        {idx + 1}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded capitalize">
                            {question.question_type.replace('_', ' ')}
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            {question.points} point{question.points !== 1 ? 's' : ''}
                          </span>
                        </div>
                        <p className="text-gray-900 dark:text-white">{question.question_text}</p>
                        {question.options.length > 0 && (
                          <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                            {question.options.map(opt => opt.text).join(' | ')}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => openQuestionModal(question)}
                        className="p-2 text-blue-600 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg"
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button
                        onClick={() => handleDeleteQuestion(question.id)}
                        className="p-2 text-red-600 hover:bg-red-100 dark:hover:bg-red-900/30 rounded-lg"
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Question Modal */}
      {questionModalOpen && editingQuestion && (
        <QuestionModal
          question={editingQuestion}
          onChange={setEditingQuestion}
          onSave={handleSaveQuestion}
          onClose={() => {
            setQuestionModalOpen(false);
            setEditingQuestion(null);
          }}
        />
      )}
    </div>
  );
};

// Question Edit Modal Component
interface QuestionModalProps {
  question: Partial<QuestionCreateInput> & { id?: number };
  onChange: (question: Partial<QuestionCreateInput> & { id?: number }) => void;
  onSave: () => void;
  onClose: () => void;
}

const QuestionModal: React.FC<QuestionModalProps> = ({ question, onChange, onSave, onClose }) => {
  const handleChange = (field: string, value: any) => {
    onChange({ ...question, [field]: value });
  };

  const handleOptionChange = (idx: number, field: string, value: any) => {
    const newOptions = [...(question.options || [])];
    newOptions[idx] = { ...newOptions[idx], [field]: value };

    // For multiple choice, if setting is_correct, update correct_answer
    if (field === 'is_correct' && value && question.question_type === 'multiple_choice') {
      newOptions.forEach((opt, i) => {
        if (i !== idx) opt.is_correct = false;
      });
      onChange({
        ...question,
        options: newOptions,
        correct_answer: newOptions[idx].id,
      });
    } else {
      onChange({ ...question, options: newOptions });
    }
  };

  const addOption = () => {
    // Find the next available letter that's not already used
    const existingIds = new Set(question.options?.map(opt => opt.id) || []);
    let newId = 'a';
    for (let i = 0; i < 26; i++) {
      const letter = String.fromCharCode(97 + i); // a, b, c, d...
      if (!existingIds.has(letter)) {
        newId = letter;
        break;
      }
    }
    onChange({
      ...question,
      options: [...(question.options || []), { id: newId, text: '', is_correct: false }],
    });
  };

  const removeOption = (idx: number) => {
    onChange({
      ...question,
      options: question.options?.filter((_, i) => i !== idx),
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              {question.id ? 'Edit Question' : 'Add Question'}
            </h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div className="space-y-4">
            {/* Question Type */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Question Type
              </label>
              <select
                value={question.question_type}
                onChange={(e) => handleChange('question_type', e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                {questionTypes.map(qt => (
                  <option key={qt.value} value={qt.value}>{qt.label}</option>
                ))}
              </select>
            </div>

            {/* Question Text */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Question Text *
              </label>
              <textarea
                value={question.question_text || ''}
                onChange={(e) => handleChange('question_text', e.target.value)}
                rows={3}
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>

            {/* Options (for multiple choice / multiple select) */}
            {(question.question_type === 'multiple_choice' || question.question_type === 'multiple_select') && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Answer Options
                </label>
                <div className="space-y-2">
                  {question.options?.map((opt, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <input
                        type={question.question_type === 'multiple_choice' ? 'radio' : 'checkbox'}
                        checked={opt.is_correct}
                        onChange={(e) => handleOptionChange(idx, 'is_correct', e.target.checked)}
                        className="text-purple-600"
                      />
                      <input
                        type="text"
                        value={opt.text}
                        onChange={(e) => handleOptionChange(idx, 'text', e.target.value)}
                        placeholder={`Option ${opt.id.toUpperCase()}`}
                        className="flex-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                      <button
                        onClick={() => removeOption(idx)}
                        className="p-2 text-red-600 hover:bg-red-100 rounded"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
                <button
                  onClick={addOption}
                  className="mt-2 text-sm text-purple-600 hover:text-purple-700"
                >
                  + Add Option
                </button>
              </div>
            )}

            {/* True/False correct answer */}
            {question.question_type === 'true_false' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Correct Answer
                </label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="radio"
                      checked={question.correct_answer === 'true'}
                      onChange={() => handleChange('correct_answer', 'true')}
                      className="text-purple-600"
                    />
                    <span>True</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="radio"
                      checked={question.correct_answer === 'false'}
                      onChange={() => handleChange('correct_answer', 'false')}
                      className="text-purple-600"
                    />
                    <span>False</span>
                  </label>
                </div>
              </div>
            )}

            {/* Short answer / fill blank correct answer */}
            {(question.question_type === 'short_answer' || question.question_type === 'fill_blank') && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Correct Answer(s)
                </label>
                <input
                  type="text"
                  value={Array.isArray(question.correct_answer) ? question.correct_answer.join(', ') : question.correct_answer || ''}
                  onChange={(e) => handleChange('correct_answer', e.target.value)}
                  placeholder="Separate multiple acceptable answers with commas"
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
            )}

            {/* Explanation */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Explanation (shown after answering)
              </label>
              <textarea
                value={question.explanation || ''}
                onChange={(e) => handleChange('explanation', e.target.value)}
                rows={2}
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>

            {/* Points */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Points
              </label>
              <input
                type="number"
                value={question.points || 1}
                onChange={(e) => handleChange('points', parseInt(e.target.value) || 1)}
                min={1}
                className="w-32 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
            <button
              onClick={onClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              Cancel
            </button>
            <button
              onClick={onSave}
              className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
            >
              Save Question
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuizEditorPage;
