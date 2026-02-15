// src/pages/BlogList.tsx
/**
 * Blog Listing Page with Category/Tag Filtering
 * Mobile-first design with collapsible sidebar
 */

import React, { useState, useEffect, useLayoutEffect } from 'react';
import { useSearchParams, Link, useLocation } from 'react-router-dom';
import { blogApi } from '../services/api';
import { Search, Filter, X, ChevronDown, ChevronUp, SlidersHorizontal } from 'lucide-react';

interface BlogPost {
  id: number;
  title: string;
  slug: string;
  excerpt?: string;
  featured_image?: string | null;
  published_at: string | null;
  author_name?: string;
  read_time_minutes?: number;
  view_count?: number;
  categories?: Array<{ id: number; name: string; slug: string; color?: string | null; icon?: string | null }>;
  tags?: Array<{ id: number; name: string; slug: string; color?: string | null }>;
}

interface Category {
  id: number;
  name: string;
  slug: string;
  color?: string;
  icon?: string;
  post_count?: number;
}

export const BlogList: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [totalPosts, setTotalPosts] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [showMobileFilters, setShowMobileFilters] = useState(false);
  const postsPerPage = 12;

  const selectedCategory = searchParams.get('category');
  const selectedTag = searchParams.get('tag');

  // Scroll to top on page load
  useLayoutEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchQuery);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Load categories on mount
  useEffect(() => {
    const fetchCategories = async () => {
      try {
        const data = await blogApi.getCategories();
        setCategories(data);
      } catch (err) {
        console.error('Failed to load categories:', err);
      }
    };
    fetchCategories();
  }, []);

  // Load posts when filters change
  useEffect(() => {
    const fetchPosts = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await blogApi.getPosts({
          page: currentPage,
          page_size: postsPerPage,
          category: selectedCategory || undefined,
          tag: selectedTag || undefined,
          search: debouncedSearch || undefined,
        });

        // Handle both BlogPost[] and BlogPostListResponse
        const postsData = Array.isArray(response) ? response : (response.posts || []);
        const total = Array.isArray(response) ? response.length : (response.total || 0);
        setPosts(postsData);
        setTotalPosts(total);
      } catch (err) {
        console.error('Failed to load posts:', err);
        setError('Failed to load posts. Please try again.');
        setPosts([]);
        setTotalPosts(0);
      } finally {
        setLoading(false);
      }
    };
    fetchPosts();
  }, [selectedCategory, selectedTag, debouncedSearch, currentPage]);

  // Function to reload posts (for retry button)
  const loadPosts = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await blogApi.getPosts({
        page: currentPage,
        page_size: postsPerPage,
        category: selectedCategory || undefined,
        tag: selectedTag || undefined,
        search: debouncedSearch || undefined,
      });
      const postsData = Array.isArray(response) ? response : (response.posts || []);
      const total = Array.isArray(response) ? response.length : (response.total || 0);
      setPosts(postsData);
      setTotalPosts(total);
    } catch (err) {
      console.error('Failed to load posts:', err);
      setError('Failed to load posts. Please try again.');
      setPosts([]);
      setTotalPosts(0);
    } finally {
      setLoading(false);
    }
  };

  const handleCategoryFilter = (categorySlug: string | null) => {
    if (categorySlug) {
      searchParams.set('category', categorySlug);
    } else {
      searchParams.delete('category');
    }
    searchParams.delete('tag');
    setSearchParams(searchParams);
    setCurrentPage(1);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setSearchParams({});
    setSearchQuery('');
    setCurrentPage(1);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const totalPages = Math.ceil(totalPosts / postsPerPage);
  const hasFilters = selectedCategory || selectedTag || debouncedSearch;
  const activeFiltersCount = [selectedCategory, selectedTag, debouncedSearch].filter(Boolean).length;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900">
      {/* Header - Compact and modern */}
      <div className="bg-gradient-to-br from-slate-800 via-slate-900 to-slate-800 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-10 lg:py-14">
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white mb-1.5">
            {selectedCategory
              ? categories.find((c) => c.slug === selectedCategory)?.name || 'Blog Posts'
              : 'Blog Posts'}
          </h1>
          <p className="text-sm sm:text-base text-slate-400">
            {selectedCategory
              ? `Browsing posts in this category`
              : 'Explore our articles and tutorials'}
          </p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-6 lg:py-8">
        {/* Mobile Search & Filter Toggle - Always visible on mobile */}
        <div className="lg:hidden mb-4 space-y-2.5">
          {/* Mobile Search Bar */}
          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
            <input
              type="text"
              value={searchQuery}
              onChange={handleSearchChange}
              placeholder="Search posts..."
              className="w-full pl-10 pr-4 py-2.5 border border-slate-200 dark:border-slate-700 rounded-xl bg-white dark:bg-slate-800 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>

          {/* Mobile Filter Toggle Button */}
          <button
            onClick={() => setShowMobileFilters(!showMobileFilters)}
            className="w-full flex items-center justify-between px-4 py-2.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-700 dark:text-slate-300 text-sm"
          >
            <span className="flex items-center gap-2">
              <SlidersHorizontal size={16} />
              <span>Filters</span>
              {activeFiltersCount > 0 && (
                <span className="bg-blue-600 text-white text-xs px-2 py-0.5 rounded-full font-medium">
                  {activeFiltersCount}
                </span>
              )}
            </span>
            {showMobileFilters ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {/* Mobile Filters Panel - Collapsible */}
          {showMobileFilters && (
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-4">
              {/* Categories */}
              <div>
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2.5 flex items-center gap-2">
                  <Filter size={14} />
                  Categories
                </h3>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => { handleCategoryFilter(null); setShowMobileFilters(false); }}
                    className={`px-3 py-1.5 text-sm rounded-full transition font-medium ${
                      !selectedCategory
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300'
                    }`}
                  >
                    All
                  </button>
                  {categories.map((category) => (
                    <button
                      key={category.id}
                      onClick={() => { handleCategoryFilter(category.slug); setShowMobileFilters(false); }}
                      className={`px-3 py-1.5 text-sm rounded-full transition flex items-center gap-1.5 font-medium ${
                        selectedCategory === category.slug
                          ? 'text-white'
                          : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300'
                      }`}
                      style={
                        selectedCategory === category.slug
                          ? { backgroundColor: category.color || '#3B82F6' }
                          : undefined
                      }
                    >
                      {category.icon && <span>{category.icon}</span>}
                      {category.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Clear Filters */}
              {hasFilters && (
                <button
                  onClick={() => { clearFilters(); setShowMobileFilters(false); }}
                  className="w-full px-4 py-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300 rounded-lg transition flex items-center justify-center gap-2 text-sm font-medium"
                >
                  <X size={14} />
                  Clear All Filters
                </button>
              )}
            </div>
          )}
        </div>

        <div className="flex flex-col lg:flex-row gap-6 lg:gap-8">
          {/* Sidebar - Hidden on mobile (moved above as collapsible) */}
          <aside className="hidden lg:block lg:w-64 flex-shrink-0">
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-5 sticky top-4">
              {/* Search */}
              <div className="mb-5">
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  Search Posts
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={handleSearchChange}
                    placeholder="Search..."
                    className="w-full pl-10 pr-4 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                  />
                </div>
              </div>

              {/* Categories */}
              <div className="mb-5">
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
                  <Filter size={16} />
                  Categories
                </h3>
                <div className="space-y-1.5">
                  <button
                    onClick={() => handleCategoryFilter(null)}
                    className={`w-full text-left px-3 py-2 rounded-lg transition text-sm ${
                      !selectedCategory
                        ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 font-medium'
                        : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
                    }`}
                  >
                    All Posts
                  </button>
                  {categories.map((category) => (
                    <button
                      key={category.id}
                      onClick={() => handleCategoryFilter(category.slug)}
                      className={`w-full text-left px-3 py-2 rounded-lg transition flex items-center gap-2 text-sm ${
                        selectedCategory === category.slug
                          ? 'font-medium'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
                      }`}
                      style={
                        selectedCategory === category.slug
                          ? {
                              backgroundColor: `${category.color}20`,
                              color: category.color,
                            }
                          : undefined
                      }
                    >
                      {category.icon && <span>{category.icon}</span>}
                      <span className="flex-1">{category.name}</span>
                      {category.post_count !== undefined && (
                        <span className="text-xs opacity-60">({category.post_count})</span>
                      )}
                    </button>
                  ))}
                </div>
              </div>

              {/* Clear Filters */}
              {hasFilters && (
                <button
                  onClick={clearFilters}
                  className="w-full px-4 py-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300 rounded-lg transition flex items-center justify-center gap-2 text-sm font-medium"
                >
                  <X size={16} />
                  Clear Filters
                </button>
              )}
            </div>
          </aside>

          {/* Main Content - Posts Grid */}
          <main className="flex-1 min-w-0">
            {/* Results Count */}
            <div className="mb-3 sm:mb-5 flex items-center justify-between">
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {loading ? 'Loading...' : `${totalPosts} post${totalPosts !== 1 ? 's' : ''}`}
              </p>
              {hasFilters && !loading && (
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">
                  Filtered
                </span>
              )}
            </div>

            {/* Error State */}
            {error && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-4 mb-5">
                <p className="text-red-600 dark:text-red-400 text-sm">{error}</p>
                <button
                  onClick={loadPosts}
                  className="mt-2 text-sm text-red-700 dark:text-red-300 underline hover:no-underline font-medium"
                >
                  Try again
                </button>
              </div>
            )}

            {/* Posts Grid */}
            {loading ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5">
                {[...Array(6)].map((_, i) => (
                  <div
                    key={i}
                    className="bg-white dark:bg-slate-800 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700 animate-pulse"
                  >
                    <div className="aspect-[16/9] sm:aspect-video bg-slate-200 dark:bg-slate-700" />
                    <div className="p-4 space-y-3">
                      <div className="h-5 bg-slate-200 dark:bg-slate-700 rounded w-3/4" />
                      <div className="h-4 bg-slate-200 dark:bg-slate-700 rounded w-full" />
                      <div className="h-4 bg-slate-200 dark:bg-slate-700 rounded w-2/3" />
                      <div className="h-3 bg-slate-200 dark:bg-slate-700 rounded w-1/2 mt-2" />
                    </div>
                  </div>
                ))}
              </div>
            ) : posts.length === 0 ? (
              <div className="text-center py-10 sm:py-14 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
                <div className="text-slate-400 dark:text-slate-500 mb-4">
                  <Search size={44} className="mx-auto" />
                </div>
                <p className="text-slate-700 dark:text-slate-300 text-lg font-semibold mb-1">
                  No posts found
                </p>
                <p className="text-slate-500 dark:text-slate-400 text-sm mb-5">
                  {hasFilters ? 'Try adjusting your filters or search terms' : 'Check back later for new content'}
                </p>
                {hasFilters && (
                  <button
                    onClick={clearFilters}
                    className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition text-sm font-medium"
                  >
                    Clear Filters
                  </button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5">
                {posts.map((post) => (
                  <Link
                    key={post.id}
                    to={`/blog/${post.slug}`}
                    className="group bg-white dark:bg-slate-800 rounded-xl shadow-sm hover:shadow-lg border border-slate-200 dark:border-slate-700 transition-all overflow-hidden flex flex-col"
                  >
                    {/* Featured Image - Shorter on mobile */}
                    <div className="aspect-[16/9] sm:aspect-video bg-slate-100 dark:bg-slate-700 overflow-hidden relative">
                      {post.featured_image ? (
                        <img
                          src={post.featured_image}
                          alt={post.title}
                          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                          loading="lazy"
                        />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-500 via-indigo-500 to-purple-600">
                          <span className="text-white/40 text-4xl sm:text-5xl font-bold">
                            {post.title.charAt(0)}
                          </span>
                        </div>
                      )}
                      {/* Category badge on image */}
                      {post.categories && post.categories.length > 0 && (
                        <div className="absolute top-3 left-3">
                          <span
                            className="px-2.5 py-1 text-xs font-semibold rounded-full backdrop-blur-sm"
                            style={{
                              backgroundColor: post.categories[0].color
                                ? `${post.categories[0].color}dd`
                                : 'rgba(59, 130, 246, 0.9)',
                              color: '#fff',
                            }}
                          >
                            {post.categories[0].icon && <span className="mr-1">{post.categories[0].icon}</span>}
                            {post.categories[0].name}
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="p-4 flex flex-col flex-1">
                      {/* Title */}
                      <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white mb-1.5 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition line-clamp-2 leading-snug">
                        {post.title}
                      </h3>

                      {/* Excerpt */}
                      {post.excerpt && (
                        <p className="text-slate-600 dark:text-slate-400 text-sm mb-3 line-clamp-2 flex-1">
                          {post.excerpt}
                        </p>
                      )}

                      {/* Meta */}
                      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mt-auto pt-2 border-t border-slate-100 dark:border-slate-700">
                        <span>{post.published_at ? formatDate(post.published_at) : 'Draft'}</span>
                        {post.read_time_minutes && <span>{post.read_time_minutes} min read</span>}
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="mt-6 sm:mt-8 flex items-center justify-center gap-3">
                <button
                  onClick={() => { setCurrentPage((p) => Math.max(1, p - 1)); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
                  disabled={currentPage === 1}
                  className="px-3.5 py-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 transition text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  ← Prev
                </button>
                <span className="text-sm text-slate-500 dark:text-slate-400 min-w-[80px] text-center">
                  {currentPage} / {totalPages}
                </span>
                <button
                  onClick={() => { setCurrentPage((p) => Math.min(totalPages, p + 1)); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
                  disabled={currentPage === totalPages}
                  className="px-3.5 py-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 transition text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  Next →
                </button>
              </div>
            )}
          </main>
        </div>
      </div>
    </div>
  );
};

export default BlogList;
