// frontend/src/plugins/tutorials/pages/admin/TutorialEditorPage.tsx
/**
 * Admin Tutorial Builder/Editor
 * Create or edit tutorials with steps
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useTutorialCategories } from '../../hooks/useTutorials';
import * as tutorialApi from '../../services/tutorialApi';
import type { TutorialCreate, TutorialDifficulty } from '../../types';

interface StepForm {
  step_order: number;
  title: string;
  content: string;
  code_example: string;
  code_language: string;
  hints: string[];
}

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
  const [relatedSkills, setRelatedSkills] = useState('');
  const [isPublished, setIsPublished] = useState(false);
  const [isFeatured, setIsFeatured] = useState(false);

  // Steps
  const [steps, setSteps] = useState<StepForm[]>([
    {
      step_order: 1,
      title: '',
      content: '',
      code_example: '',
      code_language: 'javascript',
      hints: [],
    },
  ]);

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
      setRelatedSkills(tutorial.related_skills.join(', '));
      setIsPublished(tutorial.is_published);
      setIsFeatured(tutorial.is_featured);

      if (tutorial.steps.length > 0) {
        setSteps(tutorial.steps.map(step => ({
          step_order: step.step_order,
          title: step.title,
          content: step.content || '',
          code_example: step.code_example || '',
          code_language: step.code_language || 'javascript',
          hints: step.hints || [],
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
        step_order: steps.length + 1,
        title: '',
        content: '',
        code_example: '',
        code_language: 'javascript',
        hints: [],
      },
    ]);
  };

  const removeStep = (index: number) => {
    const newSteps = steps.filter((_, i) => i !== index);
    // Reorder
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
      estimated_time_minutes: estimatedTime,
      category_id: categoryId,
      thumbnail_url: thumbnailUrl.trim() || null,
      xp_reward: xpReward,
      related_skills: relatedSkills.split(',').map(s => s.trim()).filter(Boolean),
      is_published: publish,
      is_featured: isFeatured,
      steps: steps.map(step => ({
        step_order: step.step_order,
        title: step.title.trim(),
        content: step.content.trim() || null,
        code_example: step.code_example.trim() || null,
        code_language: step.code_language || 'javascript',
        hints: step.hints.filter(h => h.trim()),
      })),
    };

    try {
      setSaving(true);

      if (id && id !== 'new') {
        // For updates, exclude steps (managed separately)
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
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            {id && id !== 'new' ? 'Edit Tutorial' : 'Create Tutorial'}
          </h1>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Form */}
          <div className="lg:col-span-2 space-y-6">
            {/* Basic Info */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
                Basic Information
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Title *
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    placeholder="Getting Started with React Hooks"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Slug *
                  </label>
                  <input
                    type="text"
                    value={slug}
                    onChange={(e) => setSlug(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    placeholder="getting-started-with-react-hooks"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={3}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    placeholder="Brief description of the tutorial..."
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Difficulty
                    </label>
                    <select
                      value={difficulty}
                      onChange={(e) => setDifficulty(e.target.value as TutorialDifficulty)}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="beginner">Beginner</option>
                      <option value="intermediate">Intermediate</option>
                      <option value="advanced">Advanced</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Estimated Time (minutes)
                    </label>
                    <input
                      type="number"
                      value={estimatedTime}
                      onChange={(e) => setEstimatedTime(parseInt(e.target.value) || 0)}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Category
                  </label>
                  <select
                    value={categoryId || ''}
                    onChange={(e) => setCategoryId(e.target.value ? parseInt(e.target.value) : null)}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="">No Category</option>
                    {categories.map(cat => (
                      <option key={cat.id} value={cat.id}>
                        {cat.icon} {cat.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Thumbnail URL
                  </label>
                  <input
                    type="text"
                    value={thumbnailUrl}
                    onChange={(e) => setThumbnailUrl(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    placeholder="https://example.com/image.jpg"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      XP Reward
                    </label>
                    <input
                      type="number"
                      value={xpReward}
                      onChange={(e) => setXpReward(parseInt(e.target.value) || 0)}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Related Skills (comma-separated)
                    </label>
                    <input
                      type="text"
                      value={relatedSkills}
                      onChange={(e) => setRelatedSkills(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                      placeholder="React, JavaScript, CSS"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Steps */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                  Tutorial Steps ({steps.length})
                </h2>
                <button
                  onClick={addStep}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium"
                >
                  + Add Step
                </button>
              </div>

              <div className="space-y-6">
                {steps.map((step, index) => (
                  <div
                    key={index}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Step {index + 1}
                      </h3>
                      {steps.length > 1 && (
                        <button
                          onClick={() => removeStep(index)}
                          className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      )}
                    </div>

                    <div className="space-y-3">
                      <div>
                        <input
                          type="text"
                          value={step.title}
                          onChange={(e) => updateStep(index, 'title', e.target.value)}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                          placeholder="Step title..."
                        />
                      </div>

                      <div>
                        <textarea
                          value={step.content}
                          onChange={(e) => updateStep(index, 'content', e.target.value)}
                          rows={4}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                          placeholder="Step content (Markdown supported)..."
                        />
                      </div>

                      <div>
                        <textarea
                          value={step.code_example}
                          onChange={(e) => updateStep(index, 'code_example', e.target.value)}
                          rows={3}
                          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono"
                          placeholder="Code example (optional)..."
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <select
                          value={step.code_language}
                          onChange={(e) => updateStep(index, 'code_language', e.target.value)}
                          className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                        >
                          <option value="javascript">JavaScript</option>
                          <option value="typescript">TypeScript</option>
                          <option value="python">Python</option>
                          <option value="java">Java</option>
                          <option value="csharp">C#</option>
                          <option value="cpp">C++</option>
                          <option value="html">HTML</option>
                          <option value="css">CSS</option>
                          <option value="bash">Bash</option>
                          <option value="sql">SQL</option>
                        </select>

                        <input
                          type="text"
                          value={step.hints.join(', ')}
                          onChange={(e) => updateStep(index, 'hints', e.target.value.split(',').map(h => h.trim()))}
                          className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                          placeholder="Hints (comma-separated)..."
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 sticky top-4">
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
