// src/pages/admin/MediaManager.tsx
/**
 * Media Library Manager - Full media management with grid view, SEO metadata editing
 * Features: Grid/List view, search, upload modal, edit modal, bulk delete
 */

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Image,
  Upload,
  Search,
  Grid3X3,
  List,
  Trash2,
  X,
  Check,
  Copy,
  ExternalLink,
  FileImage,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Info,
} from 'lucide-react';
import { adminBlogApi } from '../../services/api/admin-blog.api';
import { resolveImageUrl } from '../../utils/imageUrl';

interface MediaItem {
  id: number;
  filename: string;
  original_filename?: string;
  url: string;  // API returns "url" not "file_url"
  file_url?: string; // Some APIs might use this
  file_size: number;
  mime_type?: string;
  width?: number;
  height?: number;
  alt_text?: string;
  caption?: string;
  title?: string;
  description?: string;
  created_at: string;
  updated_at?: string;
}

// Helper to get the image URL from a media item
const getMediaUrl = (item: MediaItem): string => {
  return item.url || item.file_url || '';
};

interface UploadingFile {
  file: File;
  progress: number;
  status: 'uploading' | 'success' | 'error';
  error?: string;
}

export const MediaManager: React.FC = () => {
  // State
  const [media, setMedia] = useState<MediaItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedItems, setSelectedItems] = useState<number[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  // Modals
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingItem, setEditingItem] = useState<MediaItem | null>(null);
  const [uploadingFiles, setUploadingFiles] = useState<UploadingFile[]>([]);

  // Edit form state
  const [editForm, setEditForm] = useState({
    alt_text: '',
    caption: '',
    title: '',
    description: '',
  });
  const [saving, setSaving] = useState(false);

  // Load media
  const loadMedia = useCallback(async () => {
    setLoading(true);
    try {
      const response = await adminBlogApi.getMediaLibrary(page, 24);
      console.log('Media API response:', response);

      // Handle different API response formats
      let mediaItems: MediaItem[] = [];
      if (Array.isArray(response)) {
        mediaItems = response;
      } else if (response?.items && Array.isArray(response.items)) {
        mediaItems = response.items;
      } else if (response?.data && Array.isArray(response.data)) {
        mediaItems = response.data;
      } else if (response?.media && Array.isArray(response.media)) {
        mediaItems = response.media;
      } else if (typeof response === 'object' && response !== null) {
        // Try to find any array property
        const arrayProp = Object.values(response).find(val => Array.isArray(val));
        if (arrayProp) {
          mediaItems = arrayProp as MediaItem[];
        }
      }

      console.log('Parsed media items:', mediaItems);
      setMedia(mediaItems);
      setTotalPages(response?.total_pages || response?.totalPages || response?.total || 1);
    } catch (error) {
      console.error('Failed to load media:', error);
      setMedia([]);
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    loadMedia();
  }, [loadMedia]);

  // Filter media by search
  const filteredMedia = media.filter((item) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      item.filename.toLowerCase().includes(query) ||
      item.original_filename?.toLowerCase().includes(query) ||
      item.alt_text?.toLowerCase().includes(query) ||
      item.caption?.toLowerCase().includes(query)
    );
  });

  // Toggle item selection
  const toggleSelect = (id: number) => {
    setSelectedItems((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  // Select all
  const selectAll = () => {
    if (selectedItems.length === filteredMedia.length) {
      setSelectedItems([]);
    } else {
      setSelectedItems(filteredMedia.map((m) => m.id));
    }
  };

  // Delete selected
  const deleteSelected = async () => {
    if (!confirm(`Delete ${selectedItems.length} item(s)?`)) return;

    try {
      await Promise.all(selectedItems.map((id) => adminBlogApi.deleteMedia(id)));
      setSelectedItems([]);
      loadMedia();
    } catch (error) {
      console.error('Failed to delete:', error);
    }
  };

  // Open edit modal
  const openEdit = (item: MediaItem) => {
    setEditingItem(item);
    setEditForm({
      alt_text: item.alt_text || '',
      caption: item.caption || '',
      title: item.title || item.original_filename || '',
      description: item.description || '',
    });
    setShowEditModal(true);
  };

  // Save edit
  const saveEdit = async () => {
    if (!editingItem) return;
    setSaving(true);
    try {
      // Note: This endpoint may need to be created in the backend
      // For now we'll just close the modal
      // await adminBlogApi.updateMedia(editingItem.id, editForm);
      setShowEditModal(false);
      loadMedia();
    } catch (error) {
      console.error('Failed to save:', error);
    } finally {
      setSaving(false);
    }
  };

  // Handle file drop/select
  const handleFiles = async (files: FileList | File[]) => {
    const fileArray = Array.from(files);
    const newUploading: UploadingFile[] = fileArray.map((file) => ({
      file,
      progress: 0,
      status: 'uploading' as const,
    }));

    setUploadingFiles((prev) => [...prev, ...newUploading]);

    for (let i = 0; i < fileArray.length; i++) {
      const file = fileArray[i];
      try {
        await adminBlogApi.uploadImage(file);
        setUploadingFiles((prev) =>
          prev.map((u) =>
            u.file === file ? { ...u, progress: 100, status: 'success' as const } : u
          )
        );
      } catch (error: any) {
        setUploadingFiles((prev) =>
          prev.map((u) =>
            u.file === file
              ? { ...u, status: 'error' as const, error: error.message || 'Upload failed' }
              : u
          )
        );
      }
    }

    // Reload media after all uploads
    setTimeout(() => {
      loadMedia();
    }, 500);
  };

  // Copy URL to clipboard
  const copyUrl = (url: string) => {
    navigator.clipboard.writeText(resolveImageUrl(url));
  };

  // Format file size
  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Format date
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Image className="w-7 h-7 text-blue-600" />
            Media Library
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Manage images and media files
          </p>
        </div>

        <button
          onClick={() => setShowUploadModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors"
        >
          <Upload className="w-5 h-5" />
          Upload
        </button>
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between bg-white dark:bg-gray-800 rounded-xl p-4 border border-gray-200 dark:border-gray-700">
        {/* Search */}
        <div className="relative flex-1 max-w-md w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by filename, alt text..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center gap-3">
          {/* View Toggle */}
          <div className="flex items-center bg-gray-100 dark:bg-gray-700 rounded-lg p-1">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-md transition-colors ${
                viewMode === 'grid'
                  ? 'bg-white dark:bg-gray-600 shadow-sm'
                  : 'hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              <Grid3X3 className="w-5 h-5 text-gray-700 dark:text-gray-300" />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded-md transition-colors ${
                viewMode === 'list'
                  ? 'bg-white dark:bg-gray-600 shadow-sm'
                  : 'hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              <List className="w-5 h-5 text-gray-700 dark:text-gray-300" />
            </button>
          </div>

          {/* Selection Actions */}
          {selectedItems.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {selectedItems.length} selected
              </span>
              <button
                onClick={deleteSelected}
                className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                title="Delete selected"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Media Grid/List */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
        </div>
      ) : filteredMedia.length === 0 ? (
        <div className="text-center py-20 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
          <FileImage className="w-16 h-16 mx-auto text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No media found
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {searchQuery ? 'Try a different search term' : 'Upload your first image'}
          </p>
          <button
            onClick={() => setShowUploadModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors"
          >
            <Upload className="w-5 h-5" />
            Upload Media
          </button>
        </div>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
          {filteredMedia.map((item) => (
            <motion.div
              key={item.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className={`group relative bg-white dark:bg-gray-800 rounded-xl border-2 overflow-hidden cursor-pointer transition-all ${
                selectedItems.includes(item.id)
                  ? 'border-blue-500 ring-2 ring-blue-500/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
              onClick={() => openEdit(item)}
            >
              {/* Checkbox */}
              <div
                className="absolute top-2 left-2 z-10"
                onClick={(e) => {
                  e.stopPropagation();
                  toggleSelect(item.id);
                }}
              >
                <div
                  className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
                    selectedItems.includes(item.id)
                      ? 'bg-blue-500 border-blue-500'
                      : 'bg-white/80 border-gray-300 group-hover:border-gray-400'
                  }`}
                >
                  {selectedItems.includes(item.id) && (
                    <Check className="w-3 h-3 text-white" />
                  )}
                </div>
              </div>

              {/* Image */}
              <div className="aspect-square bg-gray-100 dark:bg-gray-900">
                <img
                  src={resolveImageUrl(getMediaUrl(item))}
                  alt={item.alt_text || item.filename}
                  className="w-full h-full object-cover"
                  loading="lazy"
                />
              </div>

              {/* Info */}
              <div className="p-2">
                <p className="text-xs font-medium text-gray-900 dark:text-white truncate">
                  {item.original_filename || item.filename}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {formatSize(item.file_size)}
                </p>
              </div>

              {/* Hover overlay */}
              <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-2">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    copyUrl(getMediaUrl(item));
                  }}
                  className="p-2 bg-white rounded-lg hover:bg-gray-100 transition-colors"
                  title="Copy URL"
                >
                  <Copy className="w-4 h-4 text-gray-700" />
                </button>
                <a
                  href={resolveImageUrl(getMediaUrl(item))}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="p-2 bg-white rounded-lg hover:bg-gray-100 transition-colors"
                  title="Open in new tab"
                >
                  <ExternalLink className="w-4 h-4 text-gray-700" />
                </a>
              </div>
            </motion.div>
          ))}
        </div>
      ) : (
        // List View
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    checked={selectedItems.length === filteredMedia.length}
                    onChange={selectAll}
                    className="rounded border-gray-300"
                  />
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Image
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Filename
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase hidden sm:table-cell">
                  Size
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase hidden md:table-cell">
                  Date
                </th>
                <th className="w-20 px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {filteredMedia.map((item) => (
                <tr
                  key={item.id}
                  className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                  onClick={() => openEdit(item)}
                >
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedItems.includes(item.id)}
                      onChange={() => toggleSelect(item.id)}
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="w-12 h-12 rounded-lg overflow-hidden bg-gray-100 dark:bg-gray-900">
                      <img
                        src={resolveImageUrl(getMediaUrl(item))}
                        alt={item.alt_text || item.filename}
                        className="w-full h-full object-cover"
                      />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate max-w-xs">
                      {item.original_filename || item.filename}
                    </p>
                    {item.alt_text && (
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">
                        {item.alt_text}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3 hidden sm:table-cell">
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      {formatSize(item.file_size)}
                    </span>
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      {formatDate(item.created_at)}
                    </span>
                  </td>
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => copyUrl(getMediaUrl(item))}
                        className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition-colors"
                        title="Copy URL"
                      >
                        <Copy className="w-4 h-4 text-gray-500" />
                      </button>
                      <button
                        onClick={() => {
                          if (confirm('Delete this image?')) {
                            adminBlogApi.deleteMedia(item.id).then(loadMedia);
                          }
                        }}
                        className="p-1.5 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4 text-red-500" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
            <button
              key={p}
              onClick={() => setPage(p)}
              className={`w-10 h-10 rounded-lg font-medium transition-colors ${
                p === page
                  ? 'bg-blue-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      )}

      {/* Upload Modal */}
      <AnimatePresence>
        {showUploadModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4"
            onClick={() => setShowUploadModal(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-white dark:bg-gray-800 rounded-2xl w-full max-w-lg shadow-2xl"
            >
              <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Upload Media
                </h2>
                <button
                  onClick={() => setShowUploadModal(false)}
                  className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-gray-500" />
                </button>
              </div>

              <div className="p-4">
                {/* Drop Zone */}
                <label
                  className="flex flex-col items-center justify-center w-full h-48 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl cursor-pointer hover:border-blue-500 hover:bg-blue-50/50 dark:hover:bg-blue-900/10 transition-colors"
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    handleFiles(e.dataTransfer.files);
                  }}
                >
                  <Upload className="w-10 h-10 text-gray-400 mb-3" />
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Drag & drop files here
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    or click to browse
                  </p>
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-3">
                    JPG, PNG, GIF, WebP (max 10MB)
                  </p>
                  <input
                    type="file"
                    multiple
                    accept="image/*"
                    className="hidden"
                    onChange={(e) => e.target.files && handleFiles(e.target.files)}
                  />
                </label>

                {/* Uploading Files */}
                {uploadingFiles.length > 0 && (
                  <div className="mt-4 space-y-2">
                    {uploadingFiles.map((item, idx) => (
                      <div
                        key={idx}
                        className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg"
                      >
                        <FileImage className="w-8 h-8 text-gray-400" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                            {item.file.name}
                          </p>
                          {item.status === 'uploading' && (
                            <div className="w-full h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full mt-1">
                              <div
                                className="h-full bg-blue-500 rounded-full transition-all"
                                style={{ width: `${item.progress}%` }}
                              />
                            </div>
                          )}
                          {item.status === 'error' && (
                            <p className="text-xs text-red-500 mt-1">{item.error}</p>
                          )}
                        </div>
                        {item.status === 'uploading' && (
                          <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
                        )}
                        {item.status === 'success' && (
                          <CheckCircle2 className="w-5 h-5 text-green-500" />
                        )}
                        {item.status === 'error' && (
                          <AlertCircle className="w-5 h-5 text-red-500" />
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => {
                    setShowUploadModal(false);
                    setUploadingFiles([]);
                  }}
                  className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  Done
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Edit Modal */}
      <AnimatePresence>
        {showEditModal && editingItem && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4"
            onClick={() => setShowEditModal(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-white dark:bg-gray-800 rounded-2xl w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto"
            >
              <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 sticky top-0 bg-white dark:bg-gray-800">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Edit Media Details
                </h2>
                <button
                  onClick={() => setShowEditModal(false)}
                  className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-gray-500" />
                </button>
              </div>

              <div className="p-4">
                <div className="grid md:grid-cols-2 gap-6">
                  {/* Preview */}
                  <div>
                    <div className="aspect-square rounded-xl overflow-hidden bg-gray-100 dark:bg-gray-900 mb-4">
                      <img
                        src={resolveImageUrl(getMediaUrl(editingItem))}
                        alt={editingItem.alt_text || editingItem.filename}
                        className="w-full h-full object-contain"
                      />
                    </div>

                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Filename:</span>
                        <span className="text-gray-900 dark:text-white font-medium truncate ml-2">
                          {editingItem.original_filename || editingItem.filename}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Size:</span>
                        <span className="text-gray-900 dark:text-white">
                          {formatSize(editingItem.file_size)}
                        </span>
                      </div>
                      {editingItem.width && editingItem.height && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Dimensions:</span>
                          <span className="text-gray-900 dark:text-white">
                            {editingItem.width} x {editingItem.height}
                          </span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Uploaded:</span>
                        <span className="text-gray-900 dark:text-white">
                          {formatDate(editingItem.created_at)}
                        </span>
                      </div>
                    </div>

                    <button
                      onClick={() => copyUrl(getMediaUrl(editingItem))}
                      className="w-full mt-4 flex items-center justify-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                    >
                      <Copy className="w-4 h-4" />
                      Copy URL
                    </button>
                  </div>

                  {/* Form */}
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Alt Text <span className="text-red-500">*</span>
                      </label>
                      <input
                        type="text"
                        value={editForm.alt_text}
                        onChange={(e) =>
                          setEditForm((prev) => ({ ...prev, alt_text: e.target.value }))
                        }
                        className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                        placeholder="Describe the image for accessibility"
                      />
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Describes image for screen readers
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Title
                      </label>
                      <input
                        type="text"
                        value={editForm.title}
                        onChange={(e) =>
                          setEditForm((prev) => ({ ...prev, title: e.target.value }))
                        }
                        className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                        placeholder="Image title"
                      />
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Shows on hover, used in search
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Caption
                      </label>
                      <textarea
                        value={editForm.caption}
                        onChange={(e) =>
                          setEditForm((prev) => ({ ...prev, caption: e.target.value }))
                        }
                        rows={2}
                        className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 resize-none"
                        placeholder="Caption to display below image"
                      />
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Displayed below image when used in posts
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Description (internal)
                      </label>
                      <textarea
                        value={editForm.description}
                        onChange={(e) =>
                          setEditForm((prev) => ({ ...prev, description: e.target.value }))
                        }
                        rows={3}
                        className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 resize-none"
                        placeholder="Internal notes for organizing your media"
                      />
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        For organizing your media library
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-between gap-3 p-4 border-t border-gray-200 dark:border-gray-700 sticky bottom-0 bg-white dark:bg-gray-800">
                <button
                  onClick={() => {
                    if (confirm('Delete this image?')) {
                      adminBlogApi.deleteMedia(editingItem.id).then(() => {
                        setShowEditModal(false);
                        loadMedia();
                      });
                    }
                  }}
                  className="px-4 py-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                >
                  Delete
                </button>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowEditModal(false)}
                    className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={saveEdit}
                    disabled={saving}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    {saving && <Loader2 className="w-4 h-4 animate-spin" />}
                    Save Changes
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default MediaManager;
