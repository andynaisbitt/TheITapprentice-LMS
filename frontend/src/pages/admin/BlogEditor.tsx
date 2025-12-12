// src/pages/admin/BlogEditor.tsx
/**
 * Enhanced Blog Post Editor
 * Full-featured editor with rich text, categories, media upload, and more
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { CheckCircle, Eye, ArrowLeft, Edit, ExternalLink } from 'lucide-react';
import {
  adminBlogApi,
  adminCategoryApi,
  blogApi,
  BlogPostCreate,
  BlogPostUpdate,
  Category,
  Tag,
} from '../../services/api';

export const BlogEditor: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;

  // Dark mode (synced with localStorage, no toggle button)
  const [darkMode] = useState(() => localStorage.getItem('darkMode') === 'true');

  // Form state
  const [formData, setFormData] = useState({
    title: '',
    slug: '',
    content: '',
    excerpt: '',
    meta_title: '',
    meta_description: '',
    meta_keywords: '',
    canonical_url: '',
    featured_image: '',
    featured_image_alt: '',
    featured_image_caption: '',
    published: false,
    scheduled_for: '',
    is_featured: false,
    allow_comments: true,
    category_ids: [] as number[],
    tag_ids: [] as number[],
  });

  // UI state
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [error, setError] = useState('');
  const [showMediaLibrary, setShowMediaLibrary] = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  // Data
  const [categories, setCategories] = useState<Category[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);

  // New tag creation
  const [newTagName, setNewTagName] = useState('');
  const [isCreatingTag, setIsCreatingTag] = useState(false);

  // Auto-save
  const [lastSaved, setLastSaved] = useState<Date | null>(null);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  // Load initial data
  useEffect(() => {
    loadCategories();
    loadTags();
    if (isEditMode && id) {
      loadPost(parseInt(id));
    }
  }, [id, isEditMode]);

  // Auto-save every 30 seconds
  useEffect(() => {
    if (hasUnsavedChanges && formData.title) {
      const timer = setTimeout(() => {
        handleAutoSave();
      }, 30000); // 30 seconds

      return () => clearTimeout(timer);
    }
  }, [formData, hasUnsavedChanges]);

  // Auto-generate slug from title
  useEffect(() => {
    if (!isEditMode && formData.title && !formData.slug) {
      const slug = generateSlug(formData.title);
      setFormData(prev => ({ ...prev, slug }));
    }
  }, [formData.title, isEditMode]);

  const generateSlug = (title: string): string => {
    return title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/--+/g, '-')
      .trim();
  };

  const loadCategories = async () => {
    try {
      const data = await adminCategoryApi.getAll();
      setCategories(data);
    } catch (err) {
      console.error('Failed to load categories:', err);
    }
  };

  const loadTags = async () => {
    try {
      const data = await blogApi.getTags();
      setTags(data);
    } catch (err) {
      console.error('Failed to load tags:', err);
    }
  };

  const loadPost = async (postId: number) => {
    try {
      setIsLoading(true);
      const post = await adminBlogApi.getPostById(postId);
      setFormData({
        title: post.title,
        slug: post.slug,
        content: post.content,
        excerpt: post.excerpt,
        meta_title: post.meta_title,
        meta_description: post.meta_description,
        meta_keywords: post.meta_keywords,
        canonical_url: post.canonical_url || '',
        featured_image: post.featured_image || '',
        featured_image_alt: post.featured_image_alt || '',
        featured_image_caption: post.featured_image_caption || '',
        published: post.published,
        scheduled_for: post.scheduled_for || '',
        is_featured: post.is_featured,
        allow_comments: post.allow_comments,
        category_ids: post.categories.map(c => c.id),
        tag_ids: post.tags.map(t => t.id),
      });
    } catch (err) {
      setError('Failed to load post');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;
    
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value,
    });

    setHasUnsavedChanges(true);

    // Auto-generate meta_title from title if empty
    if (name === 'title' && !formData.meta_title) {
      setFormData(prev => ({
        ...prev,
        title: value,
        meta_title: value.substring(0, 60),
      }));
    }

    // Auto-generate excerpt from content if empty
    if (name === 'content' && !formData.excerpt) {
      const plainText = value.replace(/<[^>]*>/g, '');
      setFormData(prev => ({
        ...prev,
        content: value,
        excerpt: plainText.substring(0, 160) + '...',
      }));
    }
  };

  const handleCategoryToggle = (categoryId: number) => {
    setFormData(prev => ({
      ...prev,
      category_ids: prev.category_ids.includes(categoryId)
        ? prev.category_ids.filter(id => id !== categoryId)
        : [...prev.category_ids, categoryId],
    }));
    setHasUnsavedChanges(true);
  };

  const handleTagToggle = (tagId: number) => {
    setFormData(prev => ({
      ...prev,
      tag_ids: prev.tag_ids.includes(tagId)
        ? prev.tag_ids.filter(id => id !== tagId)
        : [...prev.tag_ids, tagId],
    }));
    setHasUnsavedChanges(true);
  };

  const handleCreateTag = async () => {
    if (!newTagName.trim()) return;

    try {
      setIsCreatingTag(true);
      const newTag = await adminBlogApi.createTag({
        name: newTagName.trim(),
        color: '#3B82F6', // Default blue
      });
      
      setTags([...tags, newTag]);
      setFormData(prev => ({
        ...prev,
        tag_ids: [...prev.tag_ids, newTag.id],
      }));
      setNewTagName('');
    } catch (err) {
      console.error('Failed to create tag:', err);
    } finally {
      setIsCreatingTag(false);
    }
  };

  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file type
    const validTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      alert('Invalid file type. Please upload JPEG, PNG, GIF, or WebP images.');
      return;
    }

    // Validate file size (10MB max)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      alert('File too large. Maximum size is 10MB.');
      return;
    }

    try {
      setIsUploading(true);
      setUploadProgress(0);

      // Upload the image
      const result = await adminBlogApi.uploadImage(file);

      // Set the uploaded image URL
      setFormData(prev => ({
        ...prev,
        featured_image: result.url,
      }));

      setUploadProgress(100);
      alert(`Image uploaded successfully! URL: ${result.url}`);
    } catch (err: any) {
      console.error('Image upload failed:', err);
      alert(`Upload failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
      // Reset the file input
      e.target.value = '';
    }
  };

  const handleAutoSave = async () => {
    if (!formData.title || !hasUnsavedChanges) return;

    try {
      if (isEditMode && id) {
        // Clean up formData: convert empty strings to null for optional fields
        const cleanedData = {
          ...formData,
          scheduled_for: formData.scheduled_for || null,
          meta_title: formData.meta_title || null,
          meta_description: formData.meta_description || null,
          meta_keywords: formData.meta_keywords || null,
          canonical_url: formData.canonical_url || null,
          featured_image: formData.featured_image || null,
          featured_image_alt: formData.featured_image_alt || null,
          featured_image_caption: formData.featured_image_caption || null,
          excerpt: formData.excerpt || null,
          slug: formData.slug || null,
        };

        await adminBlogApi.updatePost(parseInt(id), cleanedData as BlogPostUpdate);
        setLastSaved(new Date());
        setHasUnsavedChanges(false);
      }
    } catch (err) {
      console.error('Auto-save failed:', err);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSaving(true);

    try {
      // Clean up formData: convert empty strings to null for optional fields
      const cleanedData = {
        ...formData,
        scheduled_for: formData.scheduled_for || null,
        meta_title: formData.meta_title || null,
        meta_description: formData.meta_description || null,
        meta_keywords: formData.meta_keywords || null,
        canonical_url: formData.canonical_url || null,
        featured_image: formData.featured_image || null,
        featured_image_alt: formData.featured_image_alt || null,
        featured_image_caption: formData.featured_image_caption || null,
        excerpt: formData.excerpt || null,
        slug: formData.slug || null,
      };

      if (isEditMode && id) {
        await adminBlogApi.updatePost(parseInt(id), cleanedData as BlogPostUpdate);
      } else {
        await adminBlogApi.createPost(cleanedData as BlogPostCreate);
      }

      setHasUnsavedChanges(false);
      setShowSuccessModal(true);
    } catch (err: any) {
      console.error('Blog post save error:', err);

      // Handle Pydantic validation errors (422)
      if (err.response?.status === 422) {
        const validationErrors = err.response?.data?.detail;

        if (Array.isArray(validationErrors)) {
          // Format validation errors
          const errorMessages = validationErrors.map((e: any) =>
            `${e.loc?.join('.') || 'Field'}: ${e.msg}`
          ).join(', ');
          setError(`Validation errors: ${errorMessages}`);
        } else if (typeof validationErrors === 'string') {
          setError(validationErrors);
        } else {
          setError('Validation error - please check all required fields');
        }
      } else {
        setError(err.response?.data?.detail || err.message || 'Failed to save post');
      }
    } finally {
      setIsSaving(false);
    }
  };

  const handleCancel = () => {
    if (hasUnsavedChanges) {
      if (!confirm('You have unsaved changes. Are you sure you want to leave?')) {
        return;
      }
    }
    navigate('/admin');
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center transition-colors">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading post...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 transition-colors sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                {isEditMode ? 'Edit Post' : 'Create New Post'}
              </h1>
              {lastSaved && (
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Last saved: {lastSaved.toLocaleTimeString()}
                </p>
              )}
              {hasUnsavedChanges && (
                <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-1">
                  ● Unsaved changes
                </p>
              )}
            </div>
            <button
              onClick={() => navigate('/admin')}
              className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white text-sm transition"
            >
              ← Back to Dashboard
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Content - Left 2/3 */}
          <div className="lg:col-span-2 space-y-6">
            {/* Title & Slug */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-4">
              <div>
                <label htmlFor="title" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Title *
                </label>
                <input
                  type="text"
                  id="title"
                  name="title"
                  required
                  value={formData.title}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter post title"
                />
              </div>

              <div>
                <label htmlFor="slug" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  URL Slug *
                </label>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-500 dark:text-gray-400">/blog/</span>
                  <input
                    type="text"
                    id="slug"
                    name="slug"
                    required
                    value={formData.slug}
                    onChange={handleChange}
                    className="flex-1 px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="post-url-slug"
                  />
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  💡 This will be your post's URL
                </p>
              </div>
            </div>

            {/* Content Editor */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <label htmlFor="content" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Content *
              </label>
              <textarea
                id="content"
                name="content"
                required
                rows={20}
                value={formData.content}
                onChange={handleChange}
                className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                placeholder="Write your post content here... (HTML supported)"
              />
              <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                💡 HTML is supported. Rich text editor coming soon!
              </p>
            </div>

            {/* Excerpt */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <label htmlFor="excerpt" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Excerpt
              </label>
              <textarea
                id="excerpt"
                name="excerpt"
                rows={3}
                value={formData.excerpt}
                onChange={handleChange}
                className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Short summary (auto-generated if left empty)"
              />
            </div>

            {/* SEO Settings */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">
                SEO Settings
              </h3>

              <div>
                <label htmlFor="meta_title" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Meta Title ({formData.meta_title.length}/60)
                </label>
                <input
                  type="text"
                  id="meta_title"
                  name="meta_title"
                  maxLength={60}
                  value={formData.meta_title}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="SEO title (max 60 characters)"
                />
                <div className="mt-1 h-1 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all ${
                      formData.meta_title.length > 55 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${(formData.meta_title.length / 60) * 100}%` }}
                  />
                </div>
              </div>

              <div>
                <label htmlFor="meta_description" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Meta Description ({formData.meta_description.length}/160)
                </label>
                <textarea
                  id="meta_description"
                  name="meta_description"
                  rows={3}
                  maxLength={160}
                  value={formData.meta_description}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="SEO description (max 160 characters)"
                />
                <div className="mt-1 h-1 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all ${
                      formData.meta_description.length > 150 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${(formData.meta_description.length / 160) * 100}%` }}
                  />
                </div>
              </div>

              <div>
                <label htmlFor="meta_keywords" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Keywords (comma-separated)
                </label>
                <input
                  type="text"
                  id="meta_keywords"
                  name="meta_keywords"
                  value={formData.meta_keywords}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="keyword1, keyword2, keyword3"
                />
              </div>

              <div>
                <label htmlFor="canonical_url" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Canonical URL (optional)
                </label>
                <input
                  type="url"
                  id="canonical_url"
                  name="canonical_url"
                  value={formData.canonical_url}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="https://example.com/original-post"
                />
              </div>
            </div>
          </div>

          {/* Sidebar - Right 1/3 */}
          <div className="space-y-6">
            {/* Publish Settings */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">
                Publish Settings
              </h3>

              <label className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  name="published"
                  checked={formData.published}
                  onChange={handleChange}
                  className="w-5 h-5 text-blue-600 bg-gray-100 dark:bg-gray-700 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500 checked:bg-blue-600 checked:border-blue-600"
                />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Publish immediately
                </span>
              </label>

              <div>
                <label htmlFor="scheduled_for" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Schedule for later
                </label>
                <input
                  type="datetime-local"
                  id="scheduled_for"
                  name="scheduled_for"
                  value={formData.scheduled_for}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <label className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  name="is_featured"
                  checked={formData.is_featured}
                  onChange={handleChange}
                  className="w-5 h-5 text-blue-600 bg-gray-100 dark:bg-gray-700 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500 checked:bg-blue-600 checked:border-blue-600"
                />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Featured post
                </span>
              </label>

              <label className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  name="allow_comments"
                  checked={formData.allow_comments}
                  onChange={handleChange}
                  className="w-5 h-5 text-blue-600 bg-gray-100 dark:bg-gray-700 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500 checked:bg-blue-600 checked:border-blue-600"
                />
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Allow comments
                </span>
              </label>
            </div>

            {/* Featured Image */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">
                Featured Image
              </h3>

              {formData.featured_image ? (
                <div className="space-y-2">
                  <img 
                    src={formData.featured_image} 
                    alt="Featured" 
                    className="w-full rounded-lg border border-gray-300 dark:border-gray-600"
                  />
                  <button
                    type="button"
                    onClick={() => setFormData(prev => ({ ...prev, featured_image: '' }))}
                    className="text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
                  >
                    Remove image
                  </button>
                </div>
              ) : (
                <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center">
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleImageUpload}
                    className="hidden"
                    id="image-upload"
                    disabled={isUploading}
                  />
                  <label
                    htmlFor="image-upload"
                    className={`cursor-pointer text-sm ${
                      isUploading
                        ? 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                        : 'text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300'
                    }`}
                  >
                    {isUploading ? '⏳ Uploading...' : '📤 Upload image'}
                  </label>
                </div>
              )}

              <div>
                <label htmlFor="featured_image_alt" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Alt Text <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  id="featured_image_alt"
                  name="featured_image_alt"
                  value={formData.featured_image_alt}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                  placeholder="Describe the image for accessibility and SEO"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Improves SEO and accessibility. Describe what the image shows.
                </p>
              </div>

              <div>
                <label htmlFor="featured_image_caption" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Caption (Optional)
                </label>
                <input
                  type="text"
                  id="featured_image_caption"
                  name="featured_image_caption"
                  value={formData.featured_image_caption}
                  onChange={handleChange}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                  placeholder="Optional caption displayed under the image"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Text displayed below the image (optional).
                </p>
              </div>
            </div>

            {/* Categories */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">
                Categories
              </h3>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {categories.map(category => (
                  <label key={category.id} className="flex items-center space-x-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700 p-2 rounded">
                    <input
                      type="checkbox"
                      checked={formData.category_ids.includes(category.id)}
                      onChange={() => handleCategoryToggle(category.id)}
                      className="w-4 h-4 text-blue-600 bg-gray-100 dark:bg-gray-700 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500 checked:bg-blue-600 checked:border-blue-600"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">
                      {category.name}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {/* Tags */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 space-y-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2">
                Tags
              </h3>
              
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={newTagName}
                  onChange={(e) => setNewTagName(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), handleCreateTag())}
                  placeholder="New tag name"
                  className="flex-1 px-3 py-2 text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <button
                  type="button"
                  onClick={handleCreateTag}
                  disabled={isCreatingTag || !newTagName.trim()}
                  className="px-4 py-2 text-sm bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Add
                </button>
              </div>

              <div className="flex flex-wrap gap-2">
                {tags.map(tag => (
                  <button
                    key={tag.id}
                    type="button"
                    onClick={() => handleTagToggle(tag.id)}
                    className={`px-3 py-1 text-sm rounded-full transition ${
                      formData.tag_ids.includes(tag.id)
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
                    }`}
                    style={formData.tag_ids.includes(tag.id) ? { backgroundColor: tag.color } : {}}
                  >
                    {tag.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="space-y-3">
              <button
                type="submit"
                disabled={isSaving}
                className="w-full px-6 py-3 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                {isSaving ? 'Saving...' : isEditMode ? 'Update Post' : 'Create Post'}
              </button>
              <button
                type="button"
                onClick={handleCancel}
                className="w-full px-6 py-3 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition"
              >
                Cancel
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Success Modal */}
      {showSuccessModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full p-8 text-center">
            <div className="mb-6">
              <div className="w-16 h-16 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="text-green-600 dark:text-green-400" size={32} />
              </div>
              <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                Success!
              </h3>
              <p className="text-gray-600 dark:text-gray-400">
                Your post has been {isEditMode ? 'updated' : 'created'} successfully.
              </p>
            </div>

            <div className="space-y-3">
              {/* Continue Editing - Primary Action */}
              <button
                onClick={() => {
                  setShowSuccessModal(false);
                }}
                className="w-full px-6 py-3 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition font-medium flex items-center justify-center gap-2"
              >
                <Edit size={20} />
                Continue Editing
              </button>

              {/* Preview in New Tab - Only if published */}
              {formData.slug && formData.published && (
                <button
                  onClick={() => {
                    window.open(`/blog/${formData.slug}`, '_blank');
                  }}
                  className="w-full px-6 py-3 bg-green-600 dark:bg-green-500 text-white rounded-lg hover:bg-green-700 dark:hover:bg-green-600 transition font-medium flex items-center justify-center gap-2"
                >
                  <ExternalLink size={20} />
                  Preview in New Tab
                </button>
              )}

              {/* Back to Admin */}
              <button
                onClick={() => {
                  setShowSuccessModal(false);
                  navigate('/admin');
                }}
                className="w-full px-6 py-3 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition font-medium flex items-center justify-center gap-2"
              >
                <ArrowLeft size={20} />
                Back to Admin
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlogEditor;