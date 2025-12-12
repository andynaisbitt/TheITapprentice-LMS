// Frontend/src/pages/admin/PageEditor.tsx
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { CheckCircle, Edit, ExternalLink, ArrowLeft, Trash2, ChevronUp, ChevronDown, Image as ImageIcon } from 'lucide-react';
import { pagesApi, Page, PageCreate, ContentBlock } from '../../services/api/pages.api';
import { adminBlogApi } from '../../services/api';

export const PageEditor: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [formData, setFormData] = useState<PageCreate>({
    slug: '',
    title: '',
    meta_title: '',
    meta_description: '',
    meta_keywords: '',
    canonical_url: '',
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
        canonical_url: page.canonical_url || '',
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
      } else {
        await pagesApi.admin.create(formData);
      }

      setShowSuccessModal(true);
    } catch (err: any) {
      console.error('Save failed:', err);
      alert(err.response?.data?.detail || 'Failed to save page');
    } finally {
      setSaving(false);
    }
  };

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>, blockIndex: number) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file type
    const validTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      alert('Invalid file type. Please upload JPEG, PNG, GIF, or WebP images.');
      return;
    }

    // Validate file size (10MB max)
    const maxSize = 10 * 1024 * 1024;
    if (file.size > maxSize) {
      alert('File too large. Maximum size is 10MB.');
      return;
    }

    try {
      setIsUploading(true);
      const result = await adminBlogApi.uploadImage(file);

      // Update the image block with the uploaded URL
      updateBlockData(blockIndex, { ...formData.blocks[blockIndex].data, url: result.url });

      alert(`Image uploaded successfully!`);
    } catch (err: any) {
      console.error('Image upload failed:', err);
      alert(`Upload failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const addBlock = (type: string) => {
    const defaultData: Record<string, any> = {
      hero: { title: 'Hero Title', subtitle: 'Hero subtitle', backgroundImage: '' },
      text: { content: '# Heading\n\nYour content here...', alignment: 'left', maxWidth: 'lg' },
      stats: { title: 'Our Stats', stats: [{ label: 'Users', value: '10k', suffix: '+' }] },
      cta: { title: 'Get Started', description: '', primaryButton: { text: 'Sign Up', link: '/signup' }, secondaryButton: { text: '', link: '' } },
      image: { url: '', alt: '', caption: '', width: 'full' },
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
    if (confirm('Are you sure you want to remove this block?')) {
      setFormData(prev => ({
        ...prev,
        blocks: prev.blocks.filter((_, i) => i !== index),
      }));
    }
  };

  const updateBlockData = (index: number, data: any) => {
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

  const renderBlockEditor = (block: ContentBlock, index: number) => {
    const data = block.data;

    switch (block.type) {
      case 'hero':
        return (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Title
              </label>
              <input
                type="text"
                value={data.title || ''}
                onChange={(e) => updateBlockData(index, { ...data, title: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Hero Title"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Subtitle
              </label>
              <input
                type="text"
                value={data.subtitle || ''}
                onChange={(e) => updateBlockData(index, { ...data, subtitle: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Hero subtitle"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Background Image URL (optional)
              </label>
              <input
                type="text"
                value={data.backgroundImage || ''}
                onChange={(e) => updateBlockData(index, { ...data, backgroundImage: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="https://example.com/image.jpg"
              />
            </div>
          </div>
        );

      case 'text':
        return (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Content (Markdown supported)
              </label>
              <textarea
                value={data.content || ''}
                onChange={(e) => updateBlockData(index, { ...data, content: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
                rows={10}
                placeholder="# Heading&#10;&#10;Your content here..."
              />
              <details className="mt-2 text-xs text-gray-600 dark:text-gray-400">
                <summary className="cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">
                  📖 Markdown Formatting Guide
                </summary>
                <div className="mt-2 p-3 bg-gray-100 dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700 space-y-1">
                  <p><code># Heading 1</code> - Large heading</p>
                  <p><code>## Heading 2</code> - Medium heading</p>
                  <p><code>**bold text**</code> - Bold text</p>
                  <p><code>*italic text*</code> - Italic text</p>
                  <p><code>[link text](url)</code> - Hyperlink</p>
                  <p><code>- List item</code> - Bullet point</p>
                  <p><code>1. Numbered item</code> - Numbered list</p>
                </div>
              </details>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Alignment
                </label>
                <select
                  value={data.alignment || 'left'}
                  onChange={(e) => updateBlockData(index, { ...data, alignment: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="left">Left</option>
                  <option value="center">Center</option>
                  <option value="right">Right</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Max Width
                </label>
                <select
                  value={data.maxWidth || 'lg'}
                  onChange={(e) => updateBlockData(index, { ...data, maxWidth: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="sm">Small</option>
                  <option value="md">Medium</option>
                  <option value="lg">Large</option>
                  <option value="xl">Extra Large</option>
                  <option value="full">Full Width</option>
                </select>
              </div>
            </div>
          </div>
        );

      case 'image':
        return (
          <div className="space-y-3">
            {data.url ? (
              <div className="space-y-2">
                <img
                  src={data.url}
                  alt={data.alt || 'Preview'}
                  className="w-full rounded-lg border border-gray-300 dark:border-gray-600 max-h-64 object-cover"
                />
                <button
                  type="button"
                  onClick={() => updateBlockData(index, { ...data, url: '' })}
                  className="text-sm text-red-600 dark:text-red-400 hover:text-red-700"
                >
                  Remove image
                </button>
              </div>
            ) : (
              <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center">
                <input
                  type="file"
                  accept="image/*"
                  onChange={(e) => handleImageUpload(e, index)}
                  className="hidden"
                  id={`image-upload-${index}`}
                  disabled={isUploading}
                />
                <label
                  htmlFor={`image-upload-${index}`}
                  className={`cursor-pointer text-sm flex items-center justify-center gap-2 ${
                    isUploading
                      ? 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                      : 'text-blue-600 dark:text-blue-400 hover:text-blue-700'
                  }`}
                >
                  <ImageIcon size={20} />
                  {isUploading ? 'Uploading...' : 'Upload Image'}
                </label>
              </div>
            )}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Image URL (or upload above)
              </label>
              <input
                type="text"
                value={data.url || ''}
                onChange={(e) => updateBlockData(index, { ...data, url: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="https://example.com/image.jpg"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Alt Text (for SEO)
              </label>
              <input
                type="text"
                value={data.alt || ''}
                onChange={(e) => updateBlockData(index, { ...data, alt: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Image description"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Caption (optional)
              </label>
              <input
                type="text"
                value={data.caption || ''}
                onChange={(e) => updateBlockData(index, { ...data, caption: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Optional caption"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Width
              </label>
              <select
                value={data.width || 'full'}
                onChange={(e) => updateBlockData(index, { ...data, width: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="sm">Small</option>
                <option value="md">Medium</option>
                <option value="lg">Large</option>
                <option value="full">Full Width</option>
              </select>
            </div>
          </div>
        );

      case 'cta':
        return (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Title
              </label>
              <input
                type="text"
                value={data.title || ''}
                onChange={(e) => updateBlockData(index, { ...data, title: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Get Started"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description (optional)
              </label>
              <textarea
                value={data.description || ''}
                onChange={(e) => updateBlockData(index, { ...data, description: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                rows={3}
                placeholder="Optional description text"
              />
            </div>
            <div className="border-t pt-3">
              <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Primary Button</h4>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                    Button Text
                  </label>
                  <input
                    type="text"
                    value={data.primaryButton?.text || ''}
                    onChange={(e) => updateBlockData(index, {
                      ...data,
                      primaryButton: { ...data.primaryButton, text: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                    placeholder="Sign Up"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                    Link URL
                  </label>
                  <input
                    type="text"
                    value={data.primaryButton?.link || ''}
                    onChange={(e) => updateBlockData(index, {
                      ...data,
                      primaryButton: { ...data.primaryButton, link: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                    placeholder="/signup"
                  />
                </div>
              </div>
            </div>
            <div className="border-t pt-3">
              <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Secondary Button (optional)</h4>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                    Button Text
                  </label>
                  <input
                    type="text"
                    value={data.secondaryButton?.text || ''}
                    onChange={(e) => updateBlockData(index, {
                      ...data,
                      secondaryButton: { ...data.secondaryButton, text: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                    placeholder="Learn More"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                    Link URL
                  </label>
                  <input
                    type="text"
                    value={data.secondaryButton?.link || ''}
                    onChange={(e) => updateBlockData(index, {
                      ...data,
                      secondaryButton: { ...data.secondaryButton, link: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                    placeholder="/about"
                  />
                </div>
              </div>
            </div>
          </div>
        );

      case 'stats':
        return (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Section Title
              </label>
              <input
                type="text"
                value={data.title || ''}
                onChange={(e) => updateBlockData(index, { ...data, title: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="Our Stats"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Stats (JSON format)
              </label>
              <textarea
                value={JSON.stringify(data.stats || [], null, 2)}
                onChange={(e) => {
                  try {
                    const stats = JSON.parse(e.target.value);
                    updateBlockData(index, { ...data, stats });
                  } catch (err) {
                    // Invalid JSON, ignore
                  }
                }}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
                rows={8}
                placeholder='[{"label": "Users", "value": "10k", "suffix": "+"}]'
              />
              <details className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                <summary className="cursor-pointer hover:text-gray-900 dark:hover:text-gray-200 font-medium">
                  📖 Stats JSON Format Help
                </summary>
                <div className="mt-2 p-3 bg-gray-100 dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
                  <p className="font-semibold mb-1">Required fields:</p>
                  <p className="mb-2"><code>label</code> - Stat name (e.g., "Users")</p>
                  <p className="mb-2"><code>value</code> - Stat number (e.g., "10k")</p>
                  <p className="font-semibold mb-1 mt-3">Optional fields:</p>
                  <p className="mb-2"><code>suffix</code> - Symbol after number (e.g., "+")</p>
                  <p className="font-semibold mt-3 mb-1">Example:</p>
                  <pre className="bg-white dark:bg-gray-900 p-2 rounded text-xs overflow-x-auto">
[
  &#123;"label": "Users", "value": "10k", "suffix": "+"&#125;,
  &#123;"label": "Countries", "value": "50", "suffix": ""&#125;
]</pre>
                </div>
              </details>
            </div>
          </div>
        );

      default:
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Block Data (JSON)
            </label>
            <textarea
              value={JSON.stringify(data, null, 2)}
              onChange={(e) => {
                try {
                  const newData = JSON.parse(e.target.value);
                  updateBlockData(index, newData);
                } catch (err) {
                  // Invalid JSON, ignore
                }
              }}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm"
              rows={6}
            />
          </div>
        );
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading page...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
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
                Slug (URL) <span className="text-red-500">*</span>
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
                Page Title <span className="text-red-500">*</span>
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
              <p className="text-sm text-gray-500 mt-1">{formData.meta_title?.length || 0}/60 characters</p>
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
              <p className="text-sm text-gray-500 mt-1">{formData.meta_description?.length || 0}/160 characters</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Canonical URL (Optional)
              </label>
              <input
                type="url"
                value={formData.canonical_url || ''}
                onChange={(e) => setFormData(prev => ({ ...prev, canonical_url: e.target.value }))}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="https://example.com/original-page"
                maxLength={500}
              />
              <p className="text-sm text-gray-500 mt-1">
                Use this if this page is a duplicate or syndicated version of content originally published elsewhere.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="published"
                checked={formData.published}
                onChange={(e) => setFormData(prev => ({ ...prev, published: e.target.checked }))}
                className="w-5 h-5 text-blue-600 bg-gray-100 dark:bg-gray-700 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500 checked:bg-blue-600 checked:border-blue-600"
              />
              <label htmlFor="published" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                Published (visible to public)
              </label>
            </div>
          </div>

          {/* Content Blocks */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
            <div className="flex flex-wrap justify-between items-center gap-4 mb-6">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Content Blocks ({formData.blocks.length})
              </h2>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => addBlock('hero')}
                  className="px-3 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition font-medium"
                >
                  + Hero
                </button>
                <button
                  type="button"
                  onClick={() => addBlock('text')}
                  className="px-3 py-2 text-sm bg-green-600 text-white rounded-lg hover:bg-green-700 transition font-medium"
                >
                  + Text
                </button>
                <button
                  type="button"
                  onClick={() => addBlock('image')}
                  className="px-3 py-2 text-sm bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition font-medium"
                >
                  + Image
                </button>
                <button
                  type="button"
                  onClick={() => addBlock('stats')}
                  className="px-3 py-2 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition font-medium"
                >
                  + Stats
                </button>
                <button
                  type="button"
                  onClick={() => addBlock('cta')}
                  className="px-3 py-2 text-sm bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition font-medium"
                >
                  + CTA
                </button>
              </div>
            </div>

            {formData.blocks.length === 0 && (
              <div className="text-center py-12 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg">
                <p className="text-gray-500 dark:text-gray-400 mb-4">No blocks yet. Add your first block above!</p>
                <p className="text-sm text-gray-400 dark:text-gray-500">Choose from Hero, Text, Image, Stats, or CTA blocks</p>
              </div>
            )}

            <div className="space-y-4">
              {formData.blocks.map((block, index) => (
                <div key={index} className="border-2 border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-900">
                  <div className="flex justify-between items-center mb-4">
                    <span className="font-semibold text-gray-900 dark:text-white capitalize text-lg flex items-center gap-2">
                      {block.type === 'hero' && '🎯'}
                      {block.type === 'text' && '📝'}
                      {block.type === 'image' && '🖼️'}
                      {block.type === 'stats' && '📊'}
                      {block.type === 'cta' && '🎬'}
                      {block.type} Block
                    </span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => moveBlock(index, 'up')}
                        disabled={index === 0}
                        className="p-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed transition"
                        title="Move up"
                      >
                        <ChevronUp size={18} />
                      </button>
                      <button
                        type="button"
                        onClick={() => moveBlock(index, 'down')}
                        disabled={index === formData.blocks.length - 1}
                        className="p-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed transition"
                        title="Move down"
                      >
                        <ChevronDown size={18} />
                      </button>
                      <button
                        type="button"
                        onClick={() => removeBlock(index)}
                        className="p-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition"
                        title="Remove block"
                      >
                        <Trash2 size={18} />
                      </button>
                    </div>
                  </div>

                  {renderBlockEditor(block, index)}
                </div>
              ))}
            </div>
          </div>

          {/* Submit */}
          <div className="flex gap-4 sticky bottom-4 bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
            <button
              type="submit"
              disabled={saving}
              className="flex-1 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-semibold transition"
            >
              {saving ? 'Saving...' : id ? 'Update Page' : 'Create Page'}
            </button>
            <button
              type="button"
              onClick={() => navigate('/admin/pages')}
              className="px-6 py-3 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition font-semibold"
            >
              Cancel
            </button>
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
                Your page has been {id ? 'updated' : 'created'} successfully.
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
                    window.open(`/pages/${formData.slug}`, '_blank');
                  }}
                  className="w-full px-6 py-3 bg-green-600 dark:bg-green-500 text-white rounded-lg hover:bg-green-700 dark:hover:bg-green-600 transition font-medium flex items-center justify-center gap-2"
                >
                  <ExternalLink size={20} />
                  Preview in New Tab
                </button>
              )}

              {/* Back to Pages List */}
              <button
                onClick={() => {
                  setShowSuccessModal(false);
                  navigate('/admin/pages');
                }}
                className="w-full px-6 py-3 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition font-medium flex items-center justify-center gap-2"
              >
                <ArrowLeft size={20} />
                Back to Pages
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PageEditor;
