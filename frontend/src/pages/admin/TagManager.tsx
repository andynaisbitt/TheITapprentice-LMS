// src/pages/admin/TagManager.tsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminBlogApi, blogApi, Tag } from '../../services/api';

export const TagManager: React.FC = () => {
  const navigate = useNavigate();
  const [tags, setTags] = useState<Tag[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingTag, setEditingTag] = useState<Tag | null>(null);
  const [formData, setFormData] = useState({ name: '', color: '#6B7280' });

  useEffect(() => { loadTags(); }, []);

  const loadTags = async () => {
    try {
      setIsLoading(true);
      const data = await blogApi.getTags();
      setTags(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editingTag) {
        await adminBlogApi.updateTag(editingTag.id, formData);
      } else {
        await adminBlogApi.createTag(formData);
      }
      setShowModal(false);
      loadTags();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this tag?')) return;
    try {
      await adminBlogApi.deleteTag(id);
      loadTags();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Tag Manager</h1>
          <button onClick={() => { setEditingTag(null); setFormData({ name: '', color: '#6B7280' }); setShowModal(true); }} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">+ New Tag</button>
        </div>

        {isLoading ? (
          <div className="text-center py-12"><div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div></div>
        ) : (
          <div className="flex flex-wrap gap-3">
            {tags.map(tag => (
              <div key={tag.id} className="group relative">
                <div className="inline-flex items-center space-x-2 px-4 py-2 rounded-full text-white font-medium" style={{ backgroundColor: tag.color }}>
                  <span>{tag.name}</span>
                  <span className="text-xs opacity-75">({tag.post_count || 0})</span>
                </div>
                <div className="hidden group-hover:flex absolute top-full left-1/2 transform -translate-x-1/2 mt-2 space-x-2 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-2">
                  <button onClick={() => { setEditingTag(tag); setFormData({ name: tag.name, color: tag.color }); setShowModal(true); }} className="p-2 text-blue-600 hover:bg-blue-50 rounded">Edit</button>
                  <button onClick={() => handleDelete(tag.id)} className="p-2 text-red-600 hover:bg-red-50 rounded">Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}

        {showModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
              <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-white">{editingTag ? 'Edit' : 'Create'} Tag</h2>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Name *</label>
                  <input type="text" required value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="w-full px-4 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Color</label>
                  <input type="color" value={formData.color} onChange={(e) => setFormData({ ...formData, color: e.target.value })} className="w-full h-12 rounded-lg cursor-pointer" />
                </div>
                <div className="flex space-x-3">
                  <button type="submit" className="flex-1 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700">Save</button>
                  <button type="button" onClick={() => setShowModal(false)} className="px-6 py-2 border rounded-lg dark:border-gray-600 dark:text-gray-300">Cancel</button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TagManager;
