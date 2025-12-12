// src/pages/Blog.tsx
/**
 * Blog Listing Page - With Dark Mode Support & SEO Pagination
 */

import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { motion } from 'framer-motion';
import { blogApi, BlogPost } from '../services/api';
import { resolveImageUrl } from '../utils/imageUrl';

export const Blog: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [totalPages, setTotalPages] = useState(1);
  const [categoryId, setCategoryId] = useState<number | undefined>(undefined);
  const [categoryName, setCategoryName] = useState<string>('');

  // Get page, search, and category from URL params
  const currentPage = parseInt(searchParams.get('page') || '1', 10);
  const searchTerm = searchParams.get('q') || '';
  const categorySlug = searchParams.get('category') || '';

  // Load category ID from slug when category param changes
  useEffect(() => {
    const loadCategory = async () => {
      if (categorySlug) {
        try {
          const category = await blogApi.getCategoryBySlug(categorySlug);
          setCategoryId(category.id);
          setCategoryName(category.name);
        } catch (err) {
          console.error('Error loading category:', err);
          setCategoryId(undefined);
          setCategoryName('');
        }
      } else {
        setCategoryId(undefined);
        setCategoryName('');
      }
    };
    loadCategory();
  }, [categorySlug]);

  useEffect(() => {
    loadPosts();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [currentPage, searchTerm, categoryId]);

  const loadPosts = async () => {
    try {
      setIsLoading(true);
      const response = await blogApi.getPosts({
        page: currentPage,
        page_size: 10,
        search: searchTerm || undefined,
        category_id: categoryId
      });

      setPosts(response.posts);
      setTotalPages(response.total_pages);
    } catch (err) {
      console.error('Error loading posts:', err);
      setError('Failed to load blog posts');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const newParams = new URLSearchParams();
    if (searchTerm) newParams.set('q', searchTerm);
    newParams.set('page', '1');
    setSearchParams(newParams);
  };

  const handlePageChange = (newPage: number) => {
    const newParams = new URLSearchParams(searchParams);
    newParams.set('page', newPage.toString());
    setSearchParams(newParams);
  };

  // SEO: Generate canonical URL and pagination links
  const baseUrl = 'https://yourdomain.com/blog';
  const canonicalUrl = searchTerm
    ? `${baseUrl}?q=${encodeURIComponent(searchTerm)}&page=${currentPage}`
    : currentPage > 1
      ? `${baseUrl}?page=${currentPage}`
      : baseUrl;
  const prevUrl = currentPage > 1
    ? searchTerm
      ? `${baseUrl}?q=${encodeURIComponent(searchTerm)}&page=${currentPage - 1}`
      : currentPage > 2
        ? `${baseUrl}?page=${currentPage - 1}`
        : baseUrl
    : null;
  const nextUrl = currentPage < totalPages
    ? searchTerm
      ? `${baseUrl}?q=${encodeURIComponent(searchTerm)}&page=${currentPage + 1}`
      : `${baseUrl}?page=${currentPage + 1}`
    : null;

  const handlePostClick = (slug: string) => {
    navigate(`/blog/${slug}`);
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900">
      {/* SEO: Pagination meta tags */}
      <Helmet>
        <title>{searchTerm ? `Search: ${searchTerm} - Page ${currentPage}` : currentPage > 1 ? `Blog - Page ${currentPage}` : 'Blog'} | FastReactCMS</title>
        <meta name="description" content={searchTerm ? `Search results for "${searchTerm}"` : 'Browse our latest blog posts, tutorials, and insights.'} />
        <link rel="canonical" href={canonicalUrl} />
        {prevUrl && <link rel="prev" href={prevUrl} />}
        {nextUrl && <link rel="next" href={nextUrl} />}
        {currentPage > 1 && <meta name="robots" content="noindex, follow" />}
      </Helmet>

      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-indigo-700 dark:from-blue-700 dark:to-indigo-800 text-white py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h1 className="text-4xl md:text-5xl font-bold mb-4">Blog</h1>
          <p className="text-xl text-blue-100 dark:text-blue-200">
            Insights, tutorials, and updates from our community
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 -mt-8 mb-8">
        <form onSubmit={handleSearch} className="max-w-2xl mx-auto">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-lg p-2 flex">
            <input
              type="text"
              defaultValue={searchTerm}
              onChange={(e) => {
                const newParams = new URLSearchParams(searchParams);
                if (e.target.value) {
                  newParams.set('q', e.target.value);
                } else {
                  newParams.delete('q');
                }
                newParams.set('page', '1');
                setSearchParams(newParams);
              }}
              placeholder="Search blog posts..."
              className="flex-1 px-4 py-2 focus:outline-none bg-transparent text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400"
            />
            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-600 text-white px-6 py-2 rounded-lg transition"
            >
              Search
            </button>
          </div>
        </form>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Loading State */}
        {isLoading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
            <p className="mt-4 text-gray-600 dark:text-gray-400">Loading posts...</p>
          </div>
        )}

        {/* Error State */}
        {error && !isLoading && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6 mb-8">
            <p className="text-red-600 dark:text-red-400">{error}</p>
            <button
              onClick={loadPosts}
              className="mt-4 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 underline"
            >
              Try Again
            </button>
          </div>
        )}

        {/* Posts Grid */}
        {!isLoading && !error && (
          <>
            {posts.length > 0 ? (
              <>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                    {searchTerm ? 'Search Results' : categoryName ? `Category: ${categoryName}` : 'Latest Posts'}
                  </h2>
                  {categoryName && (
                    <button
                      onClick={() => setSearchParams(new URLSearchParams())}
                      className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      Clear Filter
                    </button>
                  )}
                </div>
                <motion.div
                  className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3 }}
                >
                  {posts.map((post, index) => (
                    <motion.div
                      key={post.id}
                      onClick={() => handlePostClick(post.slug)}
                      className="bg-white dark:bg-slate-800 rounded-lg shadow-md hover:shadow-xl transition cursor-pointer overflow-hidden border border-gray-200 dark:border-slate-700"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      {post.featured_image && (
                        <img
                          src={resolveImageUrl(post.featured_image)}
                          alt={post.title}
                          className="w-full h-48 object-cover"
                        />
                      )}
                      <div className="p-6">
                        <div className="flex items-center justify-between mb-3">
                          {post.tags && post.tags.length > 0 && (
                            <span className="px-3 py-1 bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 text-xs rounded-full">
                              {post.tags[0].name}
                            </span>
                          )}
                          <time className="text-sm text-gray-500 dark:text-gray-400">
                            {new Date(post.published_at || post.created_at).toLocaleDateString()}
                          </time>
                        </div>
                        <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-3 hover:text-blue-600 dark:hover:text-blue-400 transition">
                          {post.title}
                        </h3>
                        <p className="text-gray-600 dark:text-gray-300 mb-4 line-clamp-3">
                          {post.excerpt}
                        </p>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                            <span>👁️ {post.view_count}</span>
                            <span>⏱️ {post.read_time_minutes} min</span>
                          </div>
                          <span className="text-blue-600 dark:text-blue-400 font-medium">
                            Read More →
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </motion.div>

                {/* Pagination */}
                {totalPages > 1 && (
                  <motion.div
                    className="flex justify-center items-center space-x-4 mt-12"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.3 }}
                  >
                    <button
                      onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
                      disabled={currentPage === 1}
                      className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition"
                    >
                      ← Previous
                    </button>
                    <span className="text-gray-700 dark:text-gray-300">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => handlePageChange(Math.min(totalPages, currentPage + 1))}
                      disabled={currentPage === totalPages}
                      className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition"
                    >
                      Next →
                    </button>
                  </motion.div>
                )}
              </>
            ) : (
              <div className="text-center py-12">
                <div className="text-gray-400 dark:text-gray-600 text-6xl mb-4">📝</div>
                <p className="text-gray-600 dark:text-gray-400 text-xl mb-2">
                  {searchTerm ? `No posts found for "${searchTerm}"` : 'No blog posts yet'}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-500 mb-6">
                  {searchTerm ? 'Try a different search term' : 'Create your first post in the admin panel!'}
                </p>
                {searchTerm ? (
                  <button
                    onClick={() => {
                      setSearchParams(new URLSearchParams());
                    }}
                    className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 underline"
                  >
                    Clear search
                  </button>
                ) : (
                  <button
                    onClick={() => navigate('/login')}
                    className="bg-blue-600 dark:bg-blue-700 text-white px-6 py-3 rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition"
                  >
                    Go to Admin Panel
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default Blog;