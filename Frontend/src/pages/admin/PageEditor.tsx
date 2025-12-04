// Frontend/src/pages/admin/PageEditor.tsx
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { pagesApi, Page, PageCreate, ContentBlock } from '../../services/api/pages.api';

export const PageEditor: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState<PageCreate>({
    slug: '',
    title: '',
    meta_title: '',
    meta_description: '',
    meta_keywords: '',
    blocks: [],
    published: false,
  });

  useEffect(() => {
    if (id) {
      loadPage(parseInt(id));
    }
  }, [id]);

  const loadPage = async (pageId: number) => {
    try {
      setLoading(true);
      const page = await pagesApi.admin.getById(pageId);
      setFormData({
        slug: page.slug,
        title: page.title,
        meta_title: page.meta_title || '',
        meta_description: page.meta_description || '',
        meta_keywords: page.meta_keywords || '',
        blocks: page.blocks,
        published: page.published,
      });
    } catch (err) {
      console.error('Failed to load page:', err);
      alert('Failed to load page');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setSaving(true);

      if (id) {
        await pagesApi.admin.update(parseInt(id), formData);
        alert('Page updated successfully!');
      } else {
        await pagesApi.admin.create(formData);
        alert('Page created successfully!');
        navigate('/admin/pages');
      }
    } catch (err: any) {
      console.error('Save failed:', err);
      alert(err.response?.data?.detail || 'Failed to save page');
    } finally {
      setSaving(false);
    }
  };

  const addBlock = (type: string) => {
    const defaultData: Record<string, any> = {
      hero: { title: 'Hero Title', subtitle: 'Hero subtitle' },
      text: { content: '# Heading\n\nYour content here...', alignment: 'left', maxWidth: 'lg' },
      stats: { title: 'Our Stats', stats: [{ label: 'Users', value: '10k', suffix: '+' }] },
      cta: { title: 'Get Started', primaryButton: { text: 'Sign Up', link: '/signup' } },
      image: { url: '', alt: '', caption: '' },
    };

    const newBlock: ContentBlock = {
      type,
      data: defaultData[type] || {},
    };

    setFormData(prev => ({
      ...prev,
      blocks: [...prev.blocks, newBlock],
    }));
  };

  const removeBlock = (index: number) => {
    setFormData(prev => ({
      ...prev,
      blocks: prev.blocks.filter((_, i) => i !== index),
    }));
  };

  const updateBlock = (index: number, data: any) => {
    setFormData(prev => ({
      ...prev,
      blocks: prev.blocks.map((block, i) =>
        i === index ? { ...block, data } : block
      ),
    }));
  };

  const moveBlock = (index: number, direction: 'up' | 'down') => {
    const newIndex = direction === 'up' ? index - 1 : index + 1;
    if (newIndex < 0 || newIndex >= formData.blocks.length) return;

    const newBlocks = [...formData.blocks];
    [newBlocks[index], newBlocks[newIndex]] = [newBlocks[newIndex], newBlocks[index]];

    setFormData(prev => ({ ...prev, blocks: newBlocks }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          {id ? 'Edit Page' : 'Create Page'}
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Build your page with content blocks
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-8">
        {/* Basic Info */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6 space-y-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
            Basic Information
          </h2>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Slug (URL)
            </label>
            <input
              type="text"
              value={formData.slug}
              onChange={(e) => setFormData(prev => ({ ...prev, slug: e.target.value }))}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="about-us"
              required
            />
            <p className="text-sm text-gray-500 mt-1">Will be accessible at /pages/{formData.slug}</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Page Title
            </label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="About Us"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Meta Title (SEO)
            </label>
            <input
              type="text"
              value={formData.meta_title}
              onChange={(e) => setFormData(prev => ({ ...prev, meta_title: e.target.value }))}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="About Us | FastReactCMS"
              maxLength={60}
            />
            <p className="text-sm text-gray-500 mt-1">{formData.meta_title.length}/60 characters</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Meta Description (SEO)
            </label>
            <textarea
              value={formData.meta_description}
              onChange={(e) => setFormData(prev => ({ ...prev, meta_description: e.target.value }))}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="Learn more about our company and mission..."
              rows={3}
              maxLength={160}
            />
            <p className="text-sm text-gray-500 mt-1">{formData.meta_description.length}/160 characters</p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="published"
              checked={formData.published}
              onChange={(e) => setFormData(prev => ({ ...prev, published: e.target.checked }))}
              className="w-4 h-4 text-blue-600"
            />
            <label htmlFor="published" className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Published (visible to public)
            </label>
          </div>
        </div>

        {/* Content Blocks */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
              Content Blocks
            </h2>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => addBlock('hero')}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                + Hero
              </button>
              <button
                type="button"
                onClick={() => addBlock('text')}
                className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700"
              >
                + Text
              </button>
              <button
                type="button"
                onClick={() => addBlock('stats')}
                className="px-3 py-1 text-sm bg-purple-600 text-white rounded hover:bg-purple-700"
              >
                + Stats
              </button>
              <button
                type="button"
                onClick={() => addBlock('cta')}
                className="px-3 py-1 text-sm bg-orange-600 text-white rounded hover:bg-orange-700"
              >
                + CTA
              </button>
            </div>
          </div>

          {formData.blocks.length === 0 && (
            <p className="text-center text-gray-500 py-12">
              No blocks yet. Add your first block above!
            </p>
          )}

          <div className="space-y-4">
            {formData.blocks.map((block, index) => (
              <div key={index} className="border border-gray-300 dark:border-gray-600 rounded-lg p-4">
                <div className="flex justify-between items-center mb-4">
                  <span className="font-semibold text-gray-900 dark:text-white capitalize">
                    {block.type} Block
                  </span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => moveBlock(index, 'up')}
                      disabled={index === 0}
                      className="px-2 py-1 text-sm bg-gray-200 dark:bg-gray-700 rounded disabled:opacity-50"
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      onClick={() => moveBlock(index, 'down')}
                      disabled={index === formData.blocks.length - 1}
                      className="px-2 py-1 text-sm bg-gray-200 dark:bg-gray-700 rounded disabled:opacity-50"
                    >
                      ↓
                    </button>
                    <button
                      type="button"
                      onClick={() => removeBlock(index)}
                      className="px-2 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700"
                    >
                      Remove
                    </button>
                  </div>
                </div>

                <textarea
                  value={JSON.stringify(block.data, null, 2)}
                  onChange={(e) => {
                    try {
                      const data = JSON.parse(e.target.value);
                      updateBlock(index, data);
                    } catch (err) {
                      // Invalid JSON, ignore
                    }
                  }}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                  rows={6}
                />
              </div>
            ))}
          </div>
        </div>

        {/* Submit */}
        <div className="flex gap-4">
          <button
            type="submit"
            disabled={saving}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 font-semibold"
          >
            {saving ? 'Saving...' : id ? 'Update Page' : 'Create Page'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/admin/pages')}
            className="px-6 py-3 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
};

export default PageEditor;
