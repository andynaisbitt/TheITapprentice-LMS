// frontend/src/plugins/tutorials/pages/admin/TutorialEditorPage.tsx
/**
 * Admin Tutorial Builder/Editor - ENHANCED
 * Create or edit tutorials with steps that support multiple content types:
 * - Text/markdown content
 * - Code examples with syntax highlighting
 * - Images, videos, diagrams
 * - Inline quizzes
 * - Different step types (theory, practice, quiz, demonstration, exercise)
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useTutorialCategories } from '../../hooks/useTutorials';
import * as tutorialApi from '../../services/tutorialApi';
import type { TutorialCreate, TutorialDifficulty } from '../../types';
import {
  BookOpen,
  Code,
  Image,
  Video,
  HelpCircle,
  Terminal,
  PenTool,
  Lightbulb,
  Play,
  FileText,
  Plus,
  Trash2,
  ChevronDown,
  ChevronUp,
  GripVertical,
  Clock,
  Zap,
} from 'lucide-react';
import { SkillSelector } from '../../../../components/admin/SkillSelector';

// Step type options
const STEP_TYPES = [
  { value: 'theory', label: 'Theory', icon: BookOpen, color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' },
  { value: 'practice', label: 'Practice', icon: PenTool, color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' },
  { value: 'quiz', label: 'Quiz', icon: HelpCircle, color: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' },
  { value: 'demonstration', label: 'Demo', icon: Play, color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' },
  { value: 'exercise', label: 'Exercise', icon: Lightbulb, color: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' },
];

// Media type options
const MEDIA_TYPES = [
  { value: 'none', label: 'No Media', icon: FileText },
  { value: 'code', label: 'Code', icon: Code },
  { value: 'image', label: 'Image', icon: Image },
  { value: 'video', label: 'Video', icon: Video },
  { value: 'diagram', label: 'Diagram', icon: Image },
  { value: 'terminal', label: 'Terminal', icon: Terminal },
];

// Code language options
const CODE_LANGUAGES = [
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'python', label: 'Python' },
  { value: 'java', label: 'Java' },
  { value: 'csharp', label: 'C#' },
  { value: 'cpp', label: 'C++' },
  { value: 'go', label: 'Go' },
  { value: 'rust', label: 'Rust' },
  { value: 'html', label: 'HTML' },
  { value: 'css', label: 'CSS' },
  { value: 'bash', label: 'Bash/Shell' },
  { value: 'sql', label: 'SQL' },
  { value: 'json', label: 'JSON' },
  { value: 'yaml', label: 'YAML' },
  { value: 'markdown', label: 'Markdown' },
  { value: 'powershell', label: 'PowerShell' },
  { value: 'dockerfile', label: 'Dockerfile' },
];

interface StepForm {
  step_order: number;
  title: string;
  step_type: string;
  content: string;
  media_type: string;
  media_content: string;
  media_language: string;
  media_caption: string;
  code_example: string;
  code_language: string;
  hints: string[];
  quiz_question: any | null;
  expected_action: string;
  estimated_minutes: number;
  xp_reward: number;
}

const defaultStep: StepForm = {
  step_order: 1,
  title: '',
  step_type: 'theory',
  content: '',
  media_type: 'none',
  media_content: '',
  media_language: 'javascript',
  media_caption: '',
  code_example: '',
  code_language: 'javascript',
  hints: [],
  quiz_question: null,
  expected_action: '',
  estimated_minutes: 5,
  xp_reward: 0,
};

// Step Editor Component
const StepEditor: React.FC<{
  step: StepForm;
  index: number;
  totalSteps: number;
  onUpdate: (index: number, field: keyof StepForm, value: any) => void;
  onRemove: (index: number) => void;
  onMoveUp: (index: number) => void;
  onMoveDown: (index: number) => void;
}> = ({ step, index, totalSteps, onUpdate, onRemove, onMoveUp, onMoveDown }) => {
  const [expanded, setExpanded] = useState(true);
  const [showQuizEditor, setShowQuizEditor] = useState(!!step.quiz_question);

  const selectedStepType = STEP_TYPES.find(t => t.value === step.step_type) || STEP_TYPES[0];
  const StepIcon = selectedStepType.icon;

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      {/* Step Header */}
      <div
        className={`flex items-center justify-between p-4 cursor-pointer ${selectedStepType.color}`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <GripVertical className="w-4 h-4 opacity-50" />
          <StepIcon className="w-5 h-5" />
          <span className="font-semibold">
            Step {index + 1}: {step.title || '(Untitled)'}
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-white/50 dark:bg-black/20">
            {selectedStepType.label}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs flex items-center gap-1">
            <Clock className="w-3 h-3" /> {step.estimated_minutes}m
          </span>
          {step.xp_reward > 0 && (
            <span className="text-xs flex items-center gap-1">
              <Zap className="w-3 h-3" /> {step.xp_reward} XP
            </span>
          )}
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </div>

      {/* Step Content */}
      {expanded && (
        <div className="p-4 bg-white dark:bg-gray-800 space-y-4">
          {/* Title & Step Type Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                Step Title *
              </label>
              <input
                type="text"
                value={step.title}
                onChange={(e) => onUpdate(index, 'title', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500"
                placeholder="What is this step about?"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                Step Type
              </label>
              <select
                value={step.step_type}
                onChange={(e) => onUpdate(index, 'step_type', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500"
              >
                {STEP_TYPES.map(type => (
                  <option key={type.value} value={type.value}>{type.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Main Content */}
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Content (Markdown supported)
            </label>
            <textarea
              value={step.content}
              onChange={(e) => onUpdate(index, 'content', e.target.value)}
              rows={6}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:ring-2 focus:ring-blue-500"
              placeholder="Explain the concept, provide instructions, or describe what the learner needs to do...

Use Markdown:
- **bold** for emphasis
- `code` for inline code
- Lists with - or 1. 2. 3.
- [Links](url)"
            />
          </div>

          {/* Media Type Selector */}
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
              Media Type
            </label>
            <div className="flex flex-wrap gap-2">
              {MEDIA_TYPES.map(media => {
                const MediaIcon = media.icon;
                return (
                  <button
                    key={media.value}
                    type="button"
                    onClick={() => onUpdate(index, 'media_type', media.value)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      step.media_type === media.value
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                    }`}
                  >
                    <MediaIcon className="w-4 h-4" />
                    {media.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Media Content - Conditional based on type */}
          {step.media_type === 'code' && (
            <div className="space-y-3 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Code Example</span>
                <select
                  value={step.media_language || step.code_language}
                  onChange={(e) => {
                    onUpdate(index, 'media_language', e.target.value);
                    onUpdate(index, 'code_language', e.target.value);
                  }}
                  className="px-2 py-1 text-xs border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  {CODE_LANGUAGES.map(lang => (
                    <option key={lang.value} value={lang.value}>{lang.label}</option>
                  ))}
                </select>
              </div>
              <textarea
                value={step.media_content || step.code_example}
                onChange={(e) => {
                  onUpdate(index, 'media_content', e.target.value);
                  onUpdate(index, 'code_example', e.target.value);
                }}
                rows={8}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-900 text-green-400 text-sm font-mono focus:ring-2 focus:ring-blue-500"
                placeholder="// Enter your code here..."
              />
            </div>
          )}

          {step.media_type === 'image' && (
            <div className="space-y-3 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Image</span>
              <input
                type="text"
                value={step.media_content}
                onChange={(e) => onUpdate(index, 'media_content', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                placeholder="https://example.com/image.png"
              />
              <input
                type="text"
                value={step.media_caption}
                onChange={(e) => onUpdate(index, 'media_caption', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                placeholder="Image caption (optional)"
              />
              {step.media_content && (
                <img
                  src={step.media_content}
                  alt={step.media_caption || 'Preview'}
                  className="max-w-md rounded-lg border border-gray-200 dark:border-gray-700"
                  onError={(e) => (e.target as HTMLImageElement).style.display = 'none'}
                />
              )}
            </div>
          )}

          {step.media_type === 'video' && (
            <div className="space-y-3 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Video URL</span>
              <input
                type="text"
                value={step.media_content}
                onChange={(e) => onUpdate(index, 'media_content', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                placeholder="YouTube, Vimeo, or direct video URL"
              />
              <input
                type="text"
                value={step.media_caption}
                onChange={(e) => onUpdate(index, 'media_caption', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                placeholder="Video description (optional)"
              />
            </div>
          )}

          {step.media_type === 'terminal' && (
            <div className="space-y-3 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Terminal Output</span>
              <textarea
                value={step.media_content}
                onChange={(e) => onUpdate(index, 'media_content', e.target.value)}
                rows={6}
                className="w-full px-3 py-2 border border-gray-700 rounded-lg bg-black text-green-400 text-sm font-mono focus:ring-2 focus:ring-blue-500"
                placeholder="$ command&#10;output..."
              />
            </div>
          )}

          {step.media_type === 'diagram' && (
            <div className="space-y-3 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Diagram URL</span>
              <input
                type="text"
                value={step.media_content}
                onChange={(e) => onUpdate(index, 'media_content', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                placeholder="URL to diagram image (draw.io, Mermaid, etc.)"
              />
              <input
                type="text"
                value={step.media_caption}
                onChange={(e) => onUpdate(index, 'media_caption', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                placeholder="Diagram description"
              />
            </div>
          )}

          {/* Expected Action */}
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Expected Action (What should the learner do?)
            </label>
            <input
              type="text"
              value={step.expected_action}
              onChange={(e) => onUpdate(index, 'expected_action', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              placeholder="e.g., 'Run the command in your terminal' or 'Answer the quiz question'"
            />
          </div>

          {/* Hints */}
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Hints (comma-separated, revealed progressively if learner is stuck)
            </label>
            <input
              type="text"
              value={step.hints.join(', ')}
              onChange={(e) => onUpdate(index, 'hints', e.target.value.split(',').map(h => h.trim()).filter(Boolean))}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              placeholder="First hint, Second hint, Third hint"
            />
          </div>

          {/* Quiz Question (Optional) */}
          <div>
            <button
              type="button"
              onClick={() => setShowQuizEditor(!showQuizEditor)}
              className="text-sm text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
            >
              <HelpCircle className="w-4 h-4" />
              {showQuizEditor ? 'Hide Quiz Question' : 'Add Quiz Question (Optional)'}
            </button>

            {showQuizEditor && (
              <div className="mt-3 p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg space-y-3">
                <input
                  type="text"
                  value={step.quiz_question?.question || ''}
                  onChange={(e) => onUpdate(index, 'quiz_question', {
                    ...step.quiz_question,
                    question: e.target.value,
                    type: step.quiz_question?.type || 'multiple_choice'
                  })}
                  className="w-full px-3 py-2 border border-purple-300 dark:border-purple-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                  placeholder="Quiz question..."
                />
                <select
                  value={step.quiz_question?.type || 'multiple_choice'}
                  onChange={(e) => onUpdate(index, 'quiz_question', {
                    ...step.quiz_question,
                    type: e.target.value
                  })}
                  className="px-3 py-2 border border-purple-300 dark:border-purple-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="multiple_choice">Multiple Choice</option>
                  <option value="true_false">True/False</option>
                  <option value="short_answer">Short Answer</option>
                </select>
                <input
                  type="text"
                  value={step.quiz_question?.options?.join(', ') || ''}
                  onChange={(e) => onUpdate(index, 'quiz_question', {
                    ...step.quiz_question,
                    options: e.target.value.split(',').map(o => o.trim()).filter(Boolean)
                  })}
                  className="w-full px-3 py-2 border border-purple-300 dark:border-purple-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                  placeholder="Options (comma-separated for multiple choice)"
                />
                <input
                  type="text"
                  value={step.quiz_question?.correct_answer || ''}
                  onChange={(e) => onUpdate(index, 'quiz_question', {
                    ...step.quiz_question,
                    correct_answer: e.target.value
                  })}
                  className="w-full px-3 py-2 border border-purple-300 dark:border-purple-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                  placeholder="Correct answer"
                />
              </div>
            )}
          </div>

          {/* Time & XP Row */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                Estimated Time (minutes)
              </label>
              <input
                type="number"
                min="1"
                max="60"
                value={step.estimated_minutes}
                onChange={(e) => onUpdate(index, 'estimated_minutes', parseInt(e.target.value) || 5)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                XP Reward (0 = default 10 XP)
              </label>
              <input
                type="number"
                min="0"
                max="100"
                value={step.xp_reward}
                onChange={(e) => onUpdate(index, 'xp_reward', parseInt(e.target.value) || 0)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
            </div>
          </div>

          {/* Step Actions */}
          <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => onMoveUp(index)}
                disabled={index === 0}
                className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-30"
              >
                ↑ Move Up
              </button>
              <button
                type="button"
                onClick={() => onMoveDown(index)}
                disabled={index === totalSteps - 1}
                className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-30"
              >
                ↓ Move Down
              </button>
            </div>
            {totalSteps > 1 && (
              <button
                type="button"
                onClick={() => onRemove(index)}
                className="flex items-center gap-1 px-3 py-1 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
              >
                <Trash2 className="w-4 h-4" />
                Remove Step
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const TutorialEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { categories } = useTutorialCategories();

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  // Tutorial fields
  const [title, setTitle] = useState('');
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');
  const [difficulty, setDifficulty] = useState<TutorialDifficulty>('beginner');
  const [estimatedTime, setEstimatedTime] = useState(30);
  const [categoryId, setCategoryId] = useState<number | null>(null);
  const [thumbnailUrl, setThumbnailUrl] = useState('');
  const [xpReward, setXpReward] = useState(50);
  const [relatedSkills, setRelatedSkills] = useState<string[]>([]);
  const [isPublished, setIsPublished] = useState(false);
  const [isFeatured, setIsFeatured] = useState(false);

  // Steps
  const [steps, setSteps] = useState<StepForm[]>([{ ...defaultStep }]);

  // Auto-generate slug from title
  useEffect(() => {
    if (!id) {
      const generatedSlug = title
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
      setSlug(generatedSlug);
    }
  }, [title, id]);

  // Load tutorial for editing
  useEffect(() => {
    if (id && id !== 'new') {
      loadTutorial(parseInt(id));
    }
  }, [id]);

  const loadTutorial = async (tutorialId: number) => {
    try {
      setLoading(true);
      const tutorial = await tutorialApi.getTutorialBySlug(tutorialId.toString());

      setTitle(tutorial.title);
      setSlug(tutorial.slug);
      setDescription(tutorial.description || '');
      setDifficulty(tutorial.difficulty);
      setEstimatedTime(tutorial.estimated_time_minutes || 30);
      setCategoryId(tutorial.category_id);
      setThumbnailUrl(tutorial.thumbnail_url || '');
      setXpReward(tutorial.xp_reward);
      setRelatedSkills(tutorial.related_skills || []);
      setIsPublished(tutorial.is_published);
      setIsFeatured(tutorial.is_featured);

      if (tutorial.steps.length > 0) {
        setSteps(tutorial.steps.map((step: any) => ({
          step_order: step.step_order,
          title: step.title,
          step_type: step.step_type || 'theory',
          content: step.content || '',
          media_type: step.media_type || 'none',
          media_content: step.media_content || '',
          media_language: step.media_language || step.code_language || 'javascript',
          media_caption: step.media_caption || '',
          code_example: step.code_example || '',
          code_language: step.code_language || 'javascript',
          hints: step.hints || [],
          quiz_question: step.quiz_question || null,
          expected_action: step.expected_action || '',
          estimated_minutes: step.estimated_minutes || 5,
          xp_reward: step.xp_reward || 0,
        })));
      }
    } catch (err: any) {
      alert(`Failed to load tutorial: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const addStep = () => {
    setSteps([
      ...steps,
      {
        ...defaultStep,
        step_order: steps.length + 1,
      },
    ]);
  };

  const removeStep = (index: number) => {
    const newSteps = steps.filter((_, i) => i !== index);
    newSteps.forEach((step, i) => {
      step.step_order = i + 1;
    });
    setSteps(newSteps);
  };

  const updateStep = (index: number, field: keyof StepForm, value: any) => {
    const newSteps = [...steps];
    newSteps[index] = { ...newSteps[index], [field]: value };
    setSteps(newSteps);
  };

  const moveStep = (index: number, direction: 'up' | 'down') => {
    const newSteps = [...steps];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= newSteps.length) return;

    [newSteps[index], newSteps[targetIndex]] = [newSteps[targetIndex], newSteps[index]];
    newSteps.forEach((step, i) => {
      step.step_order = i + 1;
    });
    setSteps(newSteps);
  };

  // Calculate total estimated time from steps
  const totalStepTime = steps.reduce((sum, step) => sum + step.estimated_minutes, 0);

  const handleSave = async (publish: boolean = false) => {
    if (!title.trim()) {
      alert('Please enter a title');
      return;
    }

    if (!slug.trim()) {
      alert('Please enter a slug');
      return;
    }

    if (steps.length === 0 || !steps[0].title.trim()) {
      alert('Please add at least one step');
      return;
    }

    const tutorialData: TutorialCreate = {
      title: title.trim(),
      slug: slug.trim(),
      description: description.trim() || null,
      difficulty,
      estimated_time_minutes: totalStepTime || estimatedTime,
      category_id: categoryId,
      thumbnail_url: thumbnailUrl.trim() || null,
      xp_reward: xpReward,
      related_skills: relatedSkills,
      is_published: publish,
      is_featured: isFeatured,
      steps: steps.map(step => ({
        step_order: step.step_order,
        title: step.title.trim(),
        step_type: step.step_type,
        content: step.content.trim() || null,
        content_blocks: [],
        media_type: step.media_type,
        media_content: step.media_content.trim() || null,
        media_language: step.media_language,
        media_caption: step.media_caption.trim() || null,
        code_example: step.code_example.trim() || null,
        code_language: step.code_language,
        hints: step.hints.filter(h => h.trim()),
        quiz_question: step.quiz_question,
        expected_action: step.expected_action.trim() || null,
        estimated_minutes: step.estimated_minutes,
        xp_reward: step.xp_reward,
      })),
    };

    try {
      setSaving(true);

      if (id && id !== 'new') {
        const { steps, ...updateData } = tutorialData;
        await tutorialApi.updateTutorial(parseInt(id), updateData);
        alert('Tutorial updated successfully!');
      } else {
        await tutorialApi.createTutorial(tutorialData);
        alert('Tutorial created successfully!');
      }

      navigate('/admin/tutorials');
    } catch (err: any) {
      alert(`Failed to save tutorial: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                {id && id !== 'new' ? 'Edit Tutorial' : 'Create Tutorial'}
              </h1>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Build interactive tutorials with multiple content types
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => handleSave(false)}
                disabled={saving}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-medium disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save Draft'}
              </button>
              <button
                onClick={() => handleSave(true)}
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium disabled:opacity-50"
              >
                {saving ? 'Publishing...' : 'Publish'}
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Form */}
          <div className="lg:col-span-2 space-y-6">
            {/* Basic Info */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Basic Information
              </h2>

              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Title *
                    </label>
                    <input
                      type="text"
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                      placeholder="Getting Started with Docker"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Slug *
                    </label>
                    <input
                      type="text"
                      value={slug}
                      onChange={(e) => setSlug(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                      placeholder="getting-started-with-docker"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    placeholder="A brief description of what learners will achieve..."
                  />
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Difficulty
                    </label>
                    <select
                      value={difficulty}
                      onChange={(e) => setDifficulty(e.target.value as TutorialDifficulty)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="beginner">Beginner</option>
                      <option value="intermediate">Intermediate</option>
                      <option value="advanced">Advanced</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Category
                    </label>
                    <select
                      value={categoryId || ''}
                      onChange={(e) => setCategoryId(e.target.value ? parseInt(e.target.value) : null)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="">None</option>
                      {categories.map(cat => (
                        <option key={cat.id} value={cat.id}>{cat.name}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      XP Reward
                    </label>
                    <input
                      type="number"
                      value={xpReward}
                      onChange={(e) => setXpReward(parseInt(e.target.value) || 0)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Est. Time
                    </label>
                    <div className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                      {totalStepTime} min
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Thumbnail URL
                    </label>
                    <input
                      type="text"
                      value={thumbnailUrl}
                      onChange={(e) => setThumbnailUrl(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                      placeholder="https://..."
                    />
                  </div>
                  <div>
                    <SkillSelector
                      selectedSlugs={relatedSkills}
                      onChange={setRelatedSkills}
                      helpText="Skills that will receive XP when this tutorial is completed"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Steps */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Tutorial Steps ({steps.length})
                  </h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Add steps with different content types: theory, practice, quizzes, and more
                  </p>
                </div>
                <button
                  onClick={addStep}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium"
                >
                  <Plus className="w-4 h-4" />
                  Add Step
                </button>
              </div>

              <div className="space-y-4">
                {steps.map((step, index) => (
                  <StepEditor
                    key={index}
                    step={step}
                    index={index}
                    totalSteps={steps.length}
                    onUpdate={updateStep}
                    onRemove={removeStep}
                    onMoveUp={() => moveStep(index, 'up')}
                    onMoveDown={() => moveStep(index, 'down')}
                  />
                ))}
              </div>

              <button
                onClick={addStep}
                className="w-full mt-4 py-3 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg text-gray-500 dark:text-gray-400 hover:border-blue-500 hover:text-blue-500 transition-colors"
              >
                + Add Another Step
              </button>
            </div>
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6 sticky top-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Publish Settings
              </h3>

              <div className="space-y-4 mb-6">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={isFeatured}
                    onChange={(e) => setIsFeatured(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Featured Tutorial
                  </span>
                </label>
              </div>

              {/* Summary Stats */}
              <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 mb-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Summary</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Total Steps:</span>
                    <span className="font-medium text-gray-900 dark:text-white">{steps.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Est. Time:</span>
                    <span className="font-medium text-gray-900 dark:text-white">{totalStepTime} min</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Total XP:</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {xpReward + steps.reduce((sum, s) => sum + (s.xp_reward || 10), 0)} XP
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Step Types:</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {[...new Set(steps.map(s => s.step_type))].length}
                    </span>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <button
                  onClick={() => handleSave(false)}
                  disabled={saving}
                  className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-medium disabled:opacity-50"
                >
                  {saving ? 'Saving...' : 'Save Draft'}
                </button>

                <button
                  onClick={() => handleSave(true)}
                  disabled={saving}
                  className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium disabled:opacity-50"
                >
                  {saving ? 'Publishing...' : 'Publish Tutorial'}
                </button>

                <button
                  onClick={() => navigate('/admin/tutorials')}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 font-medium"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TutorialEditorPage;
