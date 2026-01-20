// frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx
/**
 * Course Editor Page - Create/Edit Courses with Content Blocks
 * Uses the ContentBlockEditor for building course content
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Plus, Trash2, ChevronUp, ChevronDown, GripVertical, BookOpen, FileText } from 'lucide-react';
import { adminCoursesApi } from '../../services/coursesApi';
import type { Course, CreateCourseRequest, UpdateCourseRequest, CourseLevel, CourseModule, ModuleSection, CreateModuleRequest, CreateSectionRequest, SectionType } from '../../types';

const CourseEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isEditMode = !!id;

  const [activeTab, setActiveTab] = useState<'info' | 'modules'>('info');
  const [course, setCourse] = useState<Partial<CreateCourseRequest>>({
    id: '',
    title: '',
    description: '',
    short_description: '',
    level: 'beginner' as CourseLevel,
    skills: [],
    tags: [],
    requirements: [],
    objectives: [],
    is_premium: false,
    price: 0,
  });
  const [fullCourse, setFullCourse] = useState<Course | null>(null);
  const [modules, setModules] = useState<CourseModule[]>([]);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (isEditMode && id) {
      fetchCourse();
    }
  }, [id]);

  const fetchCourse = async () => {
    try {
      setLoading(true);
      const data = await adminCoursesApi.getCourse(id!);
      setCourse(data);
      setFullCourse(data);
      setModules(data.modules || []);
    } catch (err: any) {
      alert(`Failed to load course: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Module Management
  const handleAddModule = async () => {
    if (!id) return;

    const newModuleId = `module-${Date.now()}`;
    const newModule: CreateModuleRequest = {
      id: newModuleId,
      title: `Module ${modules.length + 1}`,
      description: '',
      order_index: modules.length,
      estimated_minutes: 30,
    };

    try {
      await adminCoursesApi.addModule(id, newModule);
      await fetchCourse();
      setExpandedModules(prev => new Set([...prev, newModuleId]));
    } catch (err: any) {
      alert(`Failed to add module: ${err.message}`);
    }
  };

  const handleDeleteModule = async (moduleId: string) => {
    if (!id || !confirm('Delete this module and all its sections?')) return;

    try {
      await adminCoursesApi.deleteModule(id, moduleId);
      await fetchCourse();
    } catch (err: any) {
      alert(`Failed to delete module: ${err.message}`);
    }
  };

  const handleUpdateModule = async (moduleId: string, updates: Partial<CreateModuleRequest>) => {
    if (!id) return;

    try {
      await adminCoursesApi.updateModule(id, moduleId, updates);
      setModules(prev => prev.map(m =>
        m.id === moduleId ? { ...m, ...updates } : m
      ));
    } catch (err: any) {
      alert(`Failed to update module: ${err.message}`);
    }
  };

  // Section Management
  const handleAddSection = async (moduleId: string) => {
    if (!id) return;

    const module = modules.find(m => m.id === moduleId);
    const sectionCount = module?.sections?.length || 0;

    const newSection: CreateSectionRequest = {
      id: `section-${Date.now()}`,
      title: `Section ${sectionCount + 1}`,
      description: '',
      type: 'theory' as SectionType,
      content_blocks: [],
      order_index: sectionCount,
      points: 10,
    };

    try {
      await adminCoursesApi.addSection(id, moduleId, newSection);
      await fetchCourse();
    } catch (err: any) {
      alert(`Failed to add section: ${err.message}`);
    }
  };

  const handleDeleteSection = async (moduleId: string, sectionId: string) => {
    if (!id || !confirm('Delete this section?')) return;

    try {
      await adminCoursesApi.deleteSection(id, moduleId, sectionId);
      await fetchCourse();
    } catch (err: any) {
      alert(`Failed to delete section: ${err.message}`);
    }
  };

  const toggleModuleExpand = (moduleId: string) => {
    setExpandedModules(prev => {
      const next = new Set(prev);
      if (next.has(moduleId)) {
        next.delete(moduleId);
      } else {
        next.add(moduleId);
      }
      return next;
    });
  };

  const handleSave = async () => {
    try {
      setSaving(true);

      if (isEditMode) {
        await adminCoursesApi.updateCourse(id!, course as UpdateCourseRequest);
      } else {
        await adminCoursesApi.createCourse(course as CreateCourseRequest);
      }

      navigate('/admin/courses');
    } catch (err: any) {
      alert(`Failed to save course: ${err.message}`);
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
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            {isEditMode ? 'Edit Course' : 'Create New Course'}
          </h1>
          <p className="mt-2 text-gray-600 dark:text-gray-400">
            {isEditMode ? 'Update course details and manage content' : 'Create a new course with content blocks'}
          </p>
        </div>

        {/* Tabs - Only show in edit mode */}
        {isEditMode && (
          <div className="mb-6 border-b border-gray-200 dark:border-gray-700">
            <nav className="-mb-px flex space-x-8">
              <button
                onClick={() => setActiveTab('info')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'info'
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                Course Info
              </button>
              <button
                onClick={() => setActiveTab('modules')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'modules'
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                Modules & Content ({modules.length})
              </button>
            </nav>
          </div>
        )}

        {/* Modules Tab Content */}
        {isEditMode && activeTab === 'modules' && (
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Course Modules
              </h2>
              <button
                onClick={handleAddModule}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                <Plus className="w-4 h-4" />
                Add Module
              </button>
            </div>

            {modules.length === 0 ? (
              <div className="text-center py-12 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg">
                <BookOpen className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500 dark:text-gray-400 mb-4">No modules yet</p>
                <button
                  onClick={handleAddModule}
                  className="text-blue-600 hover:text-blue-700 font-medium"
                >
                  + Add your first module
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                {modules.sort((a, b) => a.order_index - b.order_index).map((module, idx) => (
                  <div
                    key={module.id}
                    className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden"
                  >
                    {/* Module Header */}
                    <div
                      className="flex items-center gap-4 p-4 bg-gray-50 dark:bg-gray-700 cursor-pointer"
                      onClick={() => toggleModuleExpand(module.id)}
                    >
                      <GripVertical className="w-5 h-5 text-gray-400 cursor-grab" />
                      <div className="flex-1">
                        <input
                          type="text"
                          value={module.title}
                          onChange={(e) => handleUpdateModule(module.id, { title: e.target.value })}
                          onClick={(e) => e.stopPropagation()}
                          className="font-medium text-gray-900 dark:text-white bg-transparent border-none focus:outline-none focus:ring-2 focus:ring-blue-500 rounded px-2 -ml-2"
                        />
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {module.sections?.length || 0} sections • {module.estimated_minutes || 0} min
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); handleAddSection(module.id); }}
                          className="p-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded"
                          title="Add Section"
                        >
                          <Plus className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleDeleteModule(module.id); }}
                          className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30 rounded"
                          title="Delete Module"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                        {expandedModules.has(module.id) ? (
                          <ChevronUp className="w-5 h-5 text-gray-400" />
                        ) : (
                          <ChevronDown className="w-5 h-5 text-gray-400" />
                        )}
                      </div>
                    </div>

                    {/* Module Sections (Expandable) */}
                    {expandedModules.has(module.id) && (
                      <div className="p-4 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
                        {(!module.sections || module.sections.length === 0) ? (
                          <div className="text-center py-6 text-gray-500 dark:text-gray-400">
                            <FileText className="w-8 h-8 mx-auto mb-2 text-gray-300" />
                            <p className="text-sm">No sections yet</p>
                            <button
                              onClick={() => handleAddSection(module.id)}
                              className="text-blue-600 text-sm hover:underline mt-2"
                            >
                              + Add section
                            </button>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {module.sections.sort((a, b) => a.order_index - b.order_index).map((section) => (
                              <div
                                key={section.id}
                                className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
                              >
                                <GripVertical className="w-4 h-4 text-gray-400" />
                                <span className={`px-2 py-0.5 text-xs rounded ${
                                  section.type === 'theory' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' :
                                  section.type === 'practice' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                                  section.type === 'quiz' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' :
                                  'bg-gray-100 text-gray-700 dark:bg-gray-600 dark:text-gray-300'
                                }`}>
                                  {section.type}
                                </span>
                                <span className="flex-1 text-sm text-gray-700 dark:text-gray-300">
                                  {section.title}
                                </span>
                                <span className="text-xs text-gray-500">
                                  {section.content_blocks?.length || 0} blocks
                                </span>
                                <button
                                  onClick={() => handleDeleteSection(module.id, section.id)}
                                  className="p-1 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/30 rounded"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            ))}
                            <button
                              onClick={() => handleAddSection(module.id)}
                              className="w-full py-2 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg text-gray-500 dark:text-gray-400 hover:border-blue-400 hover:text-blue-500 text-sm"
                            >
                              + Add Section
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div className="mt-6 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
              <p className="text-sm text-amber-700 dark:text-amber-400">
                <strong>Coming Soon:</strong> Full content block editor for sections. Currently you can manage course structure - content editing will be available in the next update.
              </p>
            </div>
          </div>
        )}

        {/* Info Tab Content */}
        {(!isEditMode || activeTab === 'info') && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-6">
          {/* Course ID (only for new courses) */}
          {!isEditMode && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Course ID
              </label>
              <input
                type="text"
                value={course.id}
                onChange={(e) => setCourse({ ...course, id: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="e.g., python-fundamentals"
              />
            </div>
          )}

          {/* Title */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Title
            </label>
            <input
              type="text"
              value={course.title}
              onChange={(e) => setCourse({ ...course, title: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Description
            </label>
            <textarea
              value={course.description}
              onChange={(e) => setCourse({ ...course, description: e.target.value })}
              rows={4}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>

          {/* Short Description */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Short Description
            </label>
            <input
              type="text"
              value={course.short_description}
              onChange={(e) => setCourse({ ...course, short_description: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>

          {/* Level */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Difficulty Level
            </label>
            <select
              value={course.level}
              onChange={(e) => setCourse({ ...course, level: e.target.value as CourseLevel })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="advanced">Advanced</option>
            </select>
          </div>

          {/* Category */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Category
            </label>
            <input
              type="text"
              value={course.category || ''}
              onChange={(e) => setCourse({ ...course, category: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="e.g., Programming"
            />
          </div>

          {/* Premium & Price */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={course.is_premium}
                  onChange={(e) => setCourse({ ...course, is_premium: e.target.checked })}
                  className="mr-2"
                />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Premium Course
                </span>
              </label>
            </div>
            {course.is_premium && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Price (USD)
                </label>
                <input
                  type="number"
                  value={course.price}
                  onChange={(e) => setCourse({ ...course, price: parseFloat(e.target.value) })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-4 pt-6 border-t border-gray-200 dark:border-gray-700">
            <button
              onClick={() => navigate('/admin/courses')}
              className="px-6 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {saving ? 'Saving...' : isEditMode ? 'Update Course' : 'Create Course'}
            </button>
          </div>
        </div>
        )}
        {/* End of Info Tab Content */}
      </div>
    </div>
  );
};

export default CourseEditorPage;
