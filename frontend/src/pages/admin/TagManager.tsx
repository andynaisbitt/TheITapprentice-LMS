// src/pages/admin/TagManager.tsx
/**
 * Tag Manager - Modern admin interface
 * Styled like CategoryManager with stats cards, search, grid display
 */
import React, { useState, useEffect } from 'react';
import { adminBlogApi, blogApi, Tag } from '../../services/api';
import { ConfirmDialog, useToast } from '../../components/ui';

export const TagManager: React.FC = () => {
  const { toast } = useToast();
  const [tags, setTags] = useState<Tag[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingTag, setEditingTag] = useState<Tag | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState<{ show: boolean; tag?: Tag }>({ show: false });
  const [deleting, setDeleting] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    color: '#6B7280',
  });

  useEffect(() => {
    loadTags();
  }, []);

  const loadTags = async () => {
    try {
      setIsLoading(true);
      setError('');
      const data = await blogApi.getTags();
      setTags(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load tags');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingTag(null);
    setFormData({
      name: '',
      color: '#6B7280',
    });
    setIsModalOpen(true);
  };

  const handleEdit = (tag: Tag) => {
    setEditingTag(tag);
    setFormData({
      name: tag.name,
      color: tag.color || '#6B7280',
    });
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      if (editingTag) {
        await adminBlogApi.updateTag(editingTag.id, formData);
        toast.success('Tag updated successfully');
      } else {
        await adminBlogApi.createTag(formData);
        toast.success('Tag created successfully');
      }
      setIsModalOpen(false);
      loadTags();
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || 'Failed to save tag';
      setError(errorMsg);
      toast.error(errorMsg);
    }
  };

  const handleDeleteClick = (tag: Tag) => {
    setDeleteConfirm({ show: true, tag });
  };

  const confirmDelete = async () => {
    if (!deleteConfirm.tag) return;

    setDeleting(true);
    try {
      await adminBlogApi.deleteTag(deleteConfirm.tag.id);
      toast.success('Tag deleted successfully');
      loadTags();
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || 'Failed to delete tag';
      toast.error(errorMsg);
    } finally {
      setDeleting(false);
      setDeleteConfirm({ show: false });
    }
  };

  const filteredTags = tags.filter((tag) =>
    tag.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Stats
  const tagsWithPosts = tags.filter(t => (t.post_count || 0) > 0).length;
  const emptyTags = tags.filter(t => (t.post_count || 0) === 0).length;

  const predefinedColors = [
    { name: 'Gray', value: '#6B7280' },
    { name: 'Blue', value: '#3B82F6' },
    { name: 'Purple', value: '#8B5CF6' },
    { name: 'Green', value: '#10B981' },
    { name: 'Red', value: '#EF4444' },
    { name: 'Orange', value: '#F59E0B' },
    { name: 'Cyan', value: '#06B6D4' },
    { name: 'Pink', value: '#EC4899' },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-2">
            Tag Manager
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Organize your blog posts with tags
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Tags</p>
                <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">
                  {tags.length}
                </p>
              </div>
              <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                <svg className="w-8 h-8 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">With Posts</p>
                <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">
                  {tagsWithPosts}
                </p>
              </div>
              <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
                <svg className="w-8 h-8 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Empty Tags</p>
                <p className="text-3xl font-bold text-gray-900 dark:text-gray-100">
                  {emptyTags}
                </p>
              </div>
              <div className="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
                <svg className="w-8 h-8 text-orange-600 dark:text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 mb-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="flex-1">
              <div className="relative">
                <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search tags..."
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                />
              </div>
            </div>
            <button
              onClick={handleCreate}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              New Tag
            </button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-200 px-4 py-3 rounded-lg mb-6">
            {error}
          </div>
        )}

        {/* Tags Grid */}
        {isLoading ? (
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <p className="mt-2 text-gray-600 dark:text-gray-400">Loading tags...</p>
          </div>
        ) : filteredTags.length === 0 ? (
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-12 text-center">
            <svg className="mx-auto w-16 h-16 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
            </svg>
            <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-gray-100">No tags found</h3>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              {searchTerm ? 'Try a different search term' : 'Get started by creating your first tag'}
            </p>
            {!searchTerm && (
              <button
                onClick={handleCreate}
                className="mt-6 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
              >
                Create Tag
              </button>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filteredTags.map((tag) => (
              <div
                key={tag.id}
                className="bg-white dark:bg-slate-800 rounded-lg shadow hover:shadow-lg transition p-4 border-l-4"
                style={{ borderLeftColor: tag.color || '#6B7280' }}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center text-white text-sm font-bold"
                      style={{ backgroundColor: tag.color || '#6B7280' }}
                    >
                      {tag.name.charAt(0).toUpperCase()}
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-gray-100">
                        {tag.name}
                      </h3>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {tag.post_count || 0} posts
                      </p>
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3 border-t border-gray-200 dark:border-slate-700">
                  <div
                    className="w-6 h-6 rounded-full border-2 border-gray-200 dark:border-slate-600"
                    style={{ backgroundColor: tag.color || '#6B7280' }}
                    title={tag.color}
                  />
                  <div className="flex gap-1">
                    <button
                      onClick={() => handleEdit(tag)}
                      className="p-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded-lg transition"
                      title="Edit"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => handleDeleteClick(tag)}
                      className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg transition"
                      title="Delete"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Create/Edit Modal */}
        {isModalOpen && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl max-w-md w-full">
              <div className="p-6">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">
                  {editingTag ? 'Edit Tag' : 'Create Tag'}
                </h2>

                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Name */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Tag Name *
                    </label>
                    <input
                      type="text"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      required
                      className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100"
                      placeholder="e.g., JavaScript"
                    />
                  </div>

                  {/* Color */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Color
                    </label>
                    <div className="flex gap-2 mb-3 flex-wrap">
                      {predefinedColors.map((color) => (
                        <button
                          key={color.value}
                          type="button"
                          onClick={() => setFormData({ ...formData, color: color.value })}
                          className={`w-8 h-8 rounded-lg border-2 transition ${
                            formData.color === color.value
                              ? 'border-gray-900 dark:border-gray-100 scale-110 ring-2 ring-offset-2 ring-blue-500'
                              : 'border-gray-300 dark:border-slate-600 hover:scale-105'
                          }`}
                          style={{ backgroundColor: color.value }}
                          title={color.name}
                        />
                      ))}
                    </div>
                    <div className="flex items-center gap-3">
                      <input
                        type="color"
                        value={formData.color}
                        onChange={(e) => setFormData({ ...formData, color: e.target.value })}
                        className="w-12 h-10 rounded-lg border border-gray-300 dark:border-slate-600 cursor-pointer"
                      />
                      <span className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                        {formData.color}
                      </span>
                    </div>
                  </div>

                  {/* Preview */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Preview
                    </label>
                    <div className="flex items-center gap-2">
                      <span
                        className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium text-white"
                        style={{ backgroundColor: formData.color }}
                      >
                        {formData.name || 'Tag Name'}
                      </span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-slate-700">
                    <button
                      type="button"
                      onClick={() => setIsModalOpen(false)}
                      className="px-6 py-2 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 transition"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
                    >
                      {editingTag ? 'Save Changes' : 'Create Tag'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* Delete Confirmation Dialog */}
        <ConfirmDialog
          isOpen={deleteConfirm.show}
          title="Delete Tag?"
          message={`Are you sure you want to delete "${deleteConfirm.tag?.name}"? This action cannot be undone.`}
          confirmLabel="Delete"
          cancelLabel="Cancel"
          variant="danger"
          onConfirm={confirmDelete}
          onCancel={() => setDeleteConfirm({ show: false })}
          loading={deleting}
        />
      </div>
    </div>
  );
};

export default TagManager;
