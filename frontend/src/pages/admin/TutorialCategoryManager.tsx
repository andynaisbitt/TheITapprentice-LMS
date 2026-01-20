// src/pages/admin/TutorialCategoryManager.tsx
/**
 * Tutorial Categories Management
 * CRUD interface for tutorial categories
 */

import { useState, useEffect } from 'react';
import {
  Plus,
  Edit2,
  Trash2,
  GripVertical,
  FolderTree,
  Loader2,
  X,
  Code,
  Server,
  Shield,
  Database,
  Globe,
  Smartphone,
  Cloud,
  Terminal,
  Cpu,
  Lock,
  Palette,
  Layers,
  GitBranch,
  Box,
  Zap,
} from 'lucide-react';

// Icon map for category icons
const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  Code, Server, Shield, Database, Globe, Smartphone, Cloud, Terminal,
  Cpu, Lock, Palette, Layers, GitBranch, Box, Zap, FolderTree,
};

const availableIcons = Object.keys(iconMap);

// Predefined colors for categories
const availableColors = [
  { name: 'Blue', value: '#3B82F6' },
  { name: 'Green', value: '#10B981' },
  { name: 'Red', value: '#EF4444' },
  { name: 'Purple', value: '#8B5CF6' },
  { name: 'Orange', value: '#F97316' },
  { name: 'Cyan', value: '#06B6D4' },
  { name: 'Pink', value: '#EC4899' },
  { name: 'Yellow', value: '#EAB308' },
  { name: 'Indigo', value: '#6366F1' },
  { name: 'Teal', value: '#14B8A6' },
];

interface TutorialCategory {
  id: number;
  name: string;
  slug: string;
  description?: string;
  icon?: string;
  color?: string;
  display_order: number;
  tutorial_count?: number;
}

export const TutorialCategoryManager: React.FC = () => {
  const [categories, setCategories] = useState<TutorialCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingCategory, setEditingCategory] = useState<TutorialCategory | null>(null);

  useEffect(() => {
    loadCategories();
  }, []);

  const loadCategories = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/tutorials/categories');
      // const data = await response.json();
      // setCategories(data);

      // Mock data for now
      setCategories([
        { id: 1, name: 'Programming', slug: 'programming', description: 'Learn to code', icon: 'Code', color: '#3B82F6', display_order: 1, tutorial_count: 5 },
        { id: 2, name: 'DevOps', slug: 'devops', description: 'Infrastructure and deployment', icon: 'Server', color: '#10B981', display_order: 2, tutorial_count: 3 },
        { id: 3, name: 'Security', slug: 'security', description: 'Cybersecurity fundamentals', icon: 'Shield', color: '#EF4444', display_order: 3, tutorial_count: 2 },
      ]);
    } catch (error) {
      console.error('Failed to load categories:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this category?')) return;

    // TODO: Implement delete API call
    setCategories(categories.filter(c => c.id !== id));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Tutorial Categories
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Organize your tutorials into categories
          </p>
        </div>
        <button
          onClick={() => {
            setEditingCategory(null);
            setShowForm(true);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Category
        </button>
      </div>

      {/* Categories List */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm">
        {categories.length === 0 ? (
          <div className="text-center py-12">
            <FolderTree className="w-12 h-12 mx-auto mb-4 text-gray-400" />
            <p className="text-gray-600 dark:text-gray-400">No categories yet</p>
            <button
              onClick={() => setShowForm(true)}
              className="mt-4 text-primary hover:underline"
            >
              Create your first category
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {categories.map((category) => (
              <div
                key={category.id}
                className="flex items-center gap-4 p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
              >
                {/* Drag Handle */}
                <button className="cursor-grab text-gray-400 hover:text-gray-600">
                  <GripVertical className="w-5 h-5" />
                </button>

                {/* Color Indicator */}
                <div
                  className="w-4 h-4 rounded-full flex-shrink-0"
                  style={{ backgroundColor: category.color || '#6B7280' }}
                />

                {/* Category Info */}
                <div className="flex-1 min-w-0">
                  <h3 className="font-medium text-gray-900 dark:text-white">
                    {category.name}
                  </h3>
                  {category.description && (
                    <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                      {category.description}
                    </p>
                  )}
                </div>

                {/* Tutorial Count */}
                <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                  {category.tutorial_count || 0} tutorials
                </span>

                {/* Actions */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setEditingCategory(category);
                      setShowForm(true);
                    }}
                    className="p-2 text-gray-400 hover:text-primary transition-colors"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(category.id)}
                    className="p-2 text-gray-400 hover:text-red-500 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Category Form Modal */}
      {showForm && (
        <CategoryFormModal
          category={editingCategory}
          nextOrder={categories.length + 1}
          onClose={() => setShowForm(false)}
          onSave={(data) => {
            if (editingCategory) {
              setCategories(categories.map(c =>
                c.id === editingCategory.id ? { ...c, ...data } : c
              ));
            } else {
              const newCategory: TutorialCategory = {
                ...data,
                id: Date.now(),
                tutorial_count: 0,
              };
              setCategories([...categories, newCategory]);
            }
            setShowForm(false);
          }}
        />
      )}
    </div>
  );
};

// Category Form Modal Component
interface CategoryFormData {
  name: string;
  slug: string;
  description: string;
  icon: string;
  color: string;
  display_order: number;
}

interface CategoryFormModalProps {
  category: TutorialCategory | null;
  nextOrder: number;
  onClose: () => void;
  onSave: (data: CategoryFormData) => void;
}

const CategoryFormModal: React.FC<CategoryFormModalProps> = ({
  category,
  nextOrder,
  onClose,
  onSave,
}) => {
  const [formData, setFormData] = useState<CategoryFormData>({
    name: category?.name || '',
    slug: category?.slug || '',
    description: category?.description || '',
    icon: category?.icon || 'Code',
    color: category?.color || '#3B82F6',
    display_order: category?.display_order || nextOrder,
  });

  const [autoSlug, setAutoSlug] = useState(!category);

  // Generate slug from name
  const generateSlug = (name: string) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '');
  };

  const handleNameChange = (name: string) => {
    setFormData(prev => ({
      ...prev,
      name,
      ...(autoSlug ? { slug: generateSlug(name) } : {}),
    }));
  };

  const handleSlugChange = (slug: string) => {
    setAutoSlug(false);
    setFormData(prev => ({ ...prev, slug }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  const IconComponent = iconMap[formData.icon] || Code;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            {category ? 'Edit Category' : 'New Category'}
          </h2>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Name *
            </label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => handleNameChange(e.target.value)}
              className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              placeholder="Programming"
            />
          </div>

          {/* Slug */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Slug *
            </label>
            <input
              type="text"
              required
              value={formData.slug}
              onChange={(e) => handleSlugChange(e.target.value)}
              className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-sm"
              placeholder="programming"
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              URL-friendly identifier (auto-generated from name)
            </p>
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Description
            </label>
            <textarea
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
              placeholder="Learn to code with practical examples"
            />
          </div>

          {/* Icon Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Icon
            </label>
            <div className="grid grid-cols-8 gap-2">
              {availableIcons.map((iconName) => {
                const Icon = iconMap[iconName];
                return (
                  <button
                    key={iconName}
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, icon: iconName }))}
                    className={`p-2 rounded-lg border-2 transition-colors ${
                      formData.icon === iconName
                        ? 'border-primary bg-primary/10'
                        : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'
                    }`}
                    title={iconName}
                  >
                    <Icon className="w-5 h-5 text-gray-600 dark:text-gray-300" />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Color Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Color
            </label>
            <div className="flex flex-wrap gap-2">
              {availableColors.map((color) => (
                <button
                  key={color.value}
                  type="button"
                  onClick={() => setFormData(prev => ({ ...prev, color: color.value }))}
                  className={`w-8 h-8 rounded-full border-2 transition-all ${
                    formData.color === color.value
                      ? 'border-gray-900 dark:border-white scale-110'
                      : 'border-transparent hover:scale-105'
                  }`}
                  style={{ backgroundColor: color.value }}
                  title={color.name}
                />
              ))}
            </div>
          </div>

          {/* Preview */}
          <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-2">Preview</label>
            <div className="flex items-center gap-3">
              <div
                className="w-10 h-10 rounded-lg flex items-center justify-center"
                style={{ backgroundColor: formData.color + '20' }}
              >
                <IconComponent className="w-5 h-5" style={{ color: formData.color }} />
              </div>
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  {formData.name || 'Category Name'}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  /{formData.slug || 'category-slug'}
                </p>
              </div>
            </div>
          </div>
        </form>

        {/* Footer */}
        <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-700">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
          >
            {category ? 'Save Changes' : 'Create Category'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default TutorialCategoryManager;
