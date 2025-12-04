// src/pages/admin/BlogPostsList.tsx
/**
 * Blog Posts Management List
 * Enhanced with bulk actions, advanced filters, and sort options
 */

import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { blogApi, adminBlogApi, adminCategoryApi } from '../../services/api';
import type { Category } from '../../services/api/admin-category.api';
import {
  Plus,
  Edit,
  Trash2,
  Eye,
  EyeOff,
  Search,
  Calendar,
  Tag,
  TrendingUp,
  Loader2,
  CheckSquare,
  Square,
  ChevronDown,
  Star,
  X,
  AlertCircle
} from 'lucide-react';

interface Post {
  id: number;
  title: string;
  slug: string;
  excerpt: string;
  published: boolean;
  is_featured: boolean;
  created_at: string;
  view_count: number;
  categories: Array<{ id: number; name: string; color?: string }>;
  tags?: Array<{ id: number; name: string; color?: string }>;
}

type SortField = 'created_at' | 'title' | 'view_count' | 'updated_at';
type SortOrder = 'asc' | 'desc';

function BlogPostsList() {
  const navigate = useNavigate();
  const [posts, setPosts] = useState<Post[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterPublished, setFilterPublished] = useState<'all' | 'published' | 'draft'>('all');
  const [filterCategory, setFilterCategory] = useState<number | null>(null);
  const [filterFeatured, setFilterFeatured] = useState<boolean | null>(null);
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  // Bulk actions state
  const [selectedPosts, setSelectedPosts] = useState<Set<number>>(new Set());
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const [showBulkMenu, setShowBulkMenu] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ show: boolean; postId?: number; isBulk?: boolean }>({
    show: false,
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [postsData, categoriesData] = await Promise.all([
        blogApi.getPosts({ page: 1, page_size: 1000 }),
        adminCategoryApi.getAll(),
      ]);
      setPosts(postsData.posts || []);
      setCategories(categoriesData || []);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Filter and sort posts
  const filteredAndSortedPosts = useMemo(() => {
    let result = posts.filter((post) => {
      const matchesSearch = post.title.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesPublished =
        filterPublished === 'all'
          ? true
          : filterPublished === 'published'
          ? post.published
          : !post.published;
      const matchesCategory =
        filterCategory === null || post.categories.some((c) => c.id === filterCategory);
      const matchesFeatured =
        filterFeatured === null || post.is_featured === filterFeatured;

      return matchesSearch && matchesPublished && matchesCategory && matchesFeatured;
    });

    // Sort
    result.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'title':
          comparison = a.title.localeCompare(b.title);
          break;
        case 'view_count':
          comparison = a.view_count - b.view_count;
          break;
        case 'created_at':
        case 'updated_at':
          comparison = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return result;
  }, [posts, searchQuery, filterPublished, filterCategory, filterFeatured, sortField, sortOrder]);

  // Bulk selection handlers
  const handleSelectAll = () => {
    if (selectedPosts.size === filteredAndSortedPosts.length) {
      setSelectedPosts(new Set());
    } else {
      setSelectedPosts(new Set(filteredAndSortedPosts.map((p) => p.id)));
    }
  };

  const handleSelectPost = (postId: number) => {
    const newSelected = new Set(selectedPosts);
    if (newSelected.has(postId)) {
      newSelected.delete(postId);
    } else {
      newSelected.add(postId);
    }
    setSelectedPosts(newSelected);
  };

  // Bulk action handlers
  const handleBulkPublish = async () => {
    if (selectedPosts.size === 0) return;

    try {
      setBulkActionLoading(true);
      await adminBlogApi.bulkUpdate({
        post_ids: Array.from(selectedPosts),
        published: true,
      });
      await loadData();
      setSelectedPosts(new Set());
      setShowBulkMenu(false);
    } catch (error) {
      console.error('Bulk publish failed:', error);
      alert('Failed to publish selected posts');
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleBulkUnpublish = async () => {
    if (selectedPosts.size === 0) return;

    try {
      setBulkActionLoading(true);
      await adminBlogApi.bulkUpdate({
        post_ids: Array.from(selectedPosts),
        published: false,
      });
      await loadData();
      setSelectedPosts(new Set());
      setShowBulkMenu(false);
    } catch (error) {
      console.error('Bulk unpublish failed:', error);
      alert('Failed to unpublish selected posts');
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleBulkFeature = async () => {
    if (selectedPosts.size === 0) return;

    try {
      setBulkActionLoading(true);
      await adminBlogApi.bulkUpdate({
        post_ids: Array.from(selectedPosts),
        is_featured: true,
      });
      await loadData();
      setSelectedPosts(new Set());
      setShowBulkMenu(false);
    } catch (error) {
      console.error('Bulk feature failed:', error);
      alert('Failed to feature selected posts');
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleBulkDelete = async () => {
    if (selectedPosts.size === 0) return;

    try {
      setBulkActionLoading(true);
      await Promise.all(
        Array.from(selectedPosts).map((id) => adminBlogApi.deletePost(id))
      );
      await loadData();
      setSelectedPosts(new Set());
      setShowBulkMenu(false);
      setDeleteConfirm({ show: false });
    } catch (error) {
      console.error('Bulk delete failed:', error);
      alert('Failed to delete selected posts');
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleSingleDelete = async (postId: number) => {
    try {
      setBulkActionLoading(true);
      await adminBlogApi.deletePost(postId);
      await loadData();
      setDeleteConfirm({ show: false });
    } catch (error) {
      console.error('Delete failed:', error);
      alert('Failed to delete post');
    } finally {
      setBulkActionLoading(false);
    }
  };

  const clearFilters = () => {
    setSearchQuery('');
    setFilterPublished('all');
    setFilterCategory(null);
    setFilterFeatured(null);
    setSortField('created_at');
    setSortOrder('desc');
  };

  const hasActiveFilters =
    searchQuery || filterPublished !== 'all' || filterCategory !== null || filterFeatured !== null;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="animate-spin h-12 w-12 text-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="bg-card border-b sticky top-16 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div>
              <h1 className="text-3xl font-bold text-foreground">Blog Posts</h1>
              <p className="text-sm text-muted-foreground mt-1">
                {selectedPosts.size > 0 ? (
                  <span className="text-primary font-medium">
                    {selectedPosts.size} selected
                  </span>
                ) : (
                  <>
                    {filteredAndSortedPosts.length} of {posts.length} posts
                  </>
                )}
              </p>
            </div>
            <div className="flex items-center gap-3">
              {/* Bulk Actions Dropdown */}
              {selectedPosts.size > 0 && (
                <div className="relative">
                  <button
                    onClick={() => setShowBulkMenu(!showBulkMenu)}
                    disabled={bulkActionLoading}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition font-medium disabled:opacity-50"
                  >
                    {bulkActionLoading ? (
                      <Loader2 className="animate-spin" size={20} />
                    ) : (
                      <>
                        <span>Bulk Actions</span>
                        <ChevronDown size={16} />
                      </>
                    )}
                  </button>

                  {showBulkMenu && !bulkActionLoading && (
                    <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-2 z-20">
                      <button
                        onClick={handleBulkPublish}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-sm text-gray-700 dark:text-gray-300 transition"
                      >
                        Publish Selected
                      </button>
                      <button
                        onClick={handleBulkUnpublish}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-sm text-gray-700 dark:text-gray-300 transition"
                      >
                        Unpublish Selected
                      </button>
                      <button
                        onClick={handleBulkFeature}
                        className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-sm text-gray-700 dark:text-gray-300 transition"
                      >
                        Feature Selected
                      </button>
                      <div className="border-t border-gray-200 dark:border-gray-700 my-2"></div>
                      <button
                        onClick={() => setDeleteConfirm({ show: true, isBulk: true })}
                        className="w-full text-left px-4 py-2 hover:bg-red-50 dark:hover:bg-red-900/20 text-sm text-red-600 dark:text-red-400 transition"
                      >
                        Delete Selected
                      </button>
                    </div>
                  )}
                </div>
              )}

              <button
                onClick={() => navigate('/admin/blog')}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition font-medium"
              >
                <Plus size={20} />
                <span>New Post</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Filters & Sort */}
        <div className="bg-card rounded-lg shadow p-4 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
            {/* Search */}
            <div className="relative">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                size={20}
              />
              <input
                type="text"
                placeholder="Search posts..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-background border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            {/* Status Filter */}
            <select
              value={filterPublished}
              onChange={(e) => setFilterPublished(e.target.value as any)}
              className="px-4 py-2 bg-background border rounded-lg focus:ring-2 focus:ring-primary"
            >
              <option value="all">All Status</option>
              <option value="published">Published</option>
              <option value="draft">Drafts</option>
            </select>

            {/* Category Filter */}
            <select
              value={filterCategory || ''}
              onChange={(e) => setFilterCategory(e.target.value ? Number(e.target.value) : null)}
              className="px-4 py-2 bg-background border rounded-lg focus:ring-2 focus:ring-primary"
            >
              <option value="">All Categories</option>
              {categories.map((cat) => (
                <option key={cat.id} value={cat.id}>
                  {cat.name}
                </option>
              ))}
            </select>
          </div>

          {/* Second Row: Featured Filter & Sort */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Featured Filter */}
            <select
              value={filterFeatured === null ? '' : filterFeatured.toString()}
              onChange={(e) =>
                setFilterFeatured(e.target.value === '' ? null : e.target.value === 'true')
              }
              className="px-4 py-2 bg-background border rounded-lg focus:ring-2 focus:ring-primary"
            >
              <option value="">All Posts</option>
              <option value="true">Featured Only</option>
              <option value="false">Non-Featured</option>
            </select>

            {/* Sort By */}
            <select
              value={sortField}
              onChange={(e) => setSortField(e.target.value as SortField)}
              className="px-4 py-2 bg-background border rounded-lg focus:ring-2 focus:ring-primary"
            >
              <option value="created_at">Sort by Date</option>
              <option value="title">Sort by Title</option>
              <option value="view_count">Sort by Views</option>
            </select>

            {/* Sort Order */}
            <select
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as SortOrder)}
              className="px-4 py-2 bg-background border rounded-lg focus:ring-2 focus:ring-primary"
            >
              <option value="desc">Descending</option>
              <option value="asc">Ascending</option>
            </select>
          </div>

          {/* Clear Filters */}
          {hasActiveFilters && (
            <div className="mt-4 flex justify-end">
              <button
                onClick={clearFilters}
                className="flex items-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition"
              >
                <X size={16} />
                Clear Filters
              </button>
            </div>
          )}
        </div>

        {/* Posts List */}
        {filteredAndSortedPosts.length === 0 ? (
          <div className="bg-card rounded-lg shadow p-12 text-center">
            <h3 className="text-xl font-semibold text-foreground mb-2">
              {posts.length === 0 ? 'No posts yet' : 'No matching posts'}
            </h3>
            <p className="text-muted-foreground mb-6">
              {posts.length === 0 ? 'Create your first blog post' : 'Try adjusting your filters'}
            </p>
            {posts.length === 0 && (
              <button
                onClick={() => navigate('/admin/blog')}
                className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition font-medium"
              >
                <Plus size={20} />
                Create First Post
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            {/* Select All */}
            <div className="flex items-center gap-3 px-4 py-2 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
              <button
                onClick={handleSelectAll}
                className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 hover:text-primary transition"
              >
                {selectedPosts.size === filteredAndSortedPosts.length ? (
                  <CheckSquare size={20} className="text-primary" />
                ) : (
                  <Square size={20} />
                )}
                <span>
                  {selectedPosts.size === filteredAndSortedPosts.length
                    ? 'Deselect All'
                    : 'Select All'}
                </span>
              </button>
              {selectedPosts.size > 0 && (
                <span className="text-sm text-muted-foreground">
                  ({selectedPosts.size} selected)
                </span>
              )}
            </div>

            {/* Post Cards */}
            {filteredAndSortedPosts.map((post) => (
              <div
                key={post.id}
                className={`bg-card rounded-lg shadow hover:shadow-lg transition-all duration-200 p-6 ${
                  selectedPosts.has(post.id) ? 'ring-2 ring-primary' : ''
                }`}
              >
                <div className="flex items-start gap-4">
                  {/* Checkbox */}
                  <button
                    onClick={() => handleSelectPost(post.id)}
                    className="mt-1 flex-shrink-0"
                  >
                    {selectedPosts.has(post.id) ? (
                      <CheckSquare size={24} className="text-primary" />
                    ) : (
                      <Square size={24} className="text-gray-400 hover:text-primary transition" />
                    )}
                  </button>

                  {/* Post Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <h3 className="text-xl font-bold text-foreground truncate">
                        {post.title}
                      </h3>
                      {post.published ? (
                        <span className="flex items-center gap-1 px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-xs font-medium rounded">
                          <Eye size={14} />
                          Published
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 px-2 py-1 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 text-xs font-medium rounded">
                          <EyeOff size={14} />
                          Draft
                        </span>
                      )}
                      {post.is_featured && (
                        <span className="flex items-center gap-1 px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 text-xs font-medium rounded">
                          <Star size={14} />
                          Featured
                        </span>
                      )}
                    </div>

                    <p className="text-muted-foreground text-sm mb-3 line-clamp-2">
                      {post.excerpt}
                    </p>

                    <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                      <div className="flex items-center gap-1">
                        <Calendar size={14} />
                        {new Date(post.created_at).toLocaleDateString()}
                      </div>
                      {post.categories.length > 0 && (
                        <div className="flex items-center gap-1">
                          <Tag size={14} />
                          <div className="flex gap-1 flex-wrap">
                            {post.categories.map((c) => (
                              <span
                                key={c.id}
                                className="px-2 py-0.5 rounded text-xs"
                                style={{
                                  backgroundColor: c.color ? `${c.color}20` : '#e5e7eb',
                                  color: c.color || '#6b7280',
                                }}
                              >
                                {c.name}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {post.view_count > 0 && (
                        <div className="flex items-center gap-1">
                          <TrendingUp size={14} />
                          {post.view_count.toLocaleString()} views
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      onClick={() => navigate(`/admin/blog/${post.id}`)}
                      className="p-2 text-primary hover:bg-primary/10 rounded-lg transition"
                      title="Edit post"
                    >
                      <Edit size={20} />
                    </button>
                    <button
                      onClick={() => window.open(`/blog/${post.slug}`, '_blank')}
                      className="p-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition"
                      title="View post"
                    >
                      <Eye size={20} />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm({ show: true, postId: post.id })}
                      className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition"
                      title="Delete post"
                    >
                      <Trash2 size={20} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteConfirm.show && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-3 bg-red-100 dark:bg-red-900/30 rounded-full">
                <AlertCircle className="text-red-600 dark:text-red-400" size={24} />
              </div>
              <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                Confirm Deletion
              </h3>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              {deleteConfirm.isBulk
                ? `Are you sure you want to delete ${selectedPosts.size} selected posts? This action cannot be undone.`
                : 'Are you sure you want to delete this post? This action cannot be undone.'}
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm({ show: false })}
                disabled={bulkActionLoading}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  deleteConfirm.isBulk
                    ? handleBulkDelete()
                    : handleSingleDelete(deleteConfirm.postId!)
                }
                disabled={bulkActionLoading}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition disabled:opacity-50 flex items-center gap-2"
              >
                {bulkActionLoading && <Loader2 className="animate-spin" size={16} />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default BlogPostsList;
