// src/pages/blog/BlogPostView.tsx
/**
 * Dynamic Blog Post Viewer - With Dark Mode Support & In-Article Ads
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import { blogApi, BlogPost } from '../../services/api';
import { Helmet } from 'react-helmet-async';
import { InArticleAd, SidebarAd } from '../../components/ads/GoogleAdSense';
import { resolveImageUrl } from '../../utils/imageUrl';
import { useAuth } from '../../state/contexts/AuthContext';

export const BlogPostView: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  
  const [post, setPost] = useState<BlogPost | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (slug) {
      loadPost(slug);
    }
  }, [slug]);

  const loadPost = async (slug: string) => {
    try {
      setIsLoading(true);
      setError('');
      const data = await blogApi.getBySlug(slug);
      setPost(data);
    } catch (err: any) {
      console.error('Error loading post:', err);
      if (err.response?.status === 404) {
        setError('Blog post not found');
      } else {
        setError('Failed to load blog post');
      }
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading post...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-900">
        <div className="max-w-md w-full bg-white dark:bg-slate-800 shadow-lg rounded-lg p-8 text-center border border-gray-200 dark:border-slate-700">
          <div className="text-red-600 dark:text-red-400 text-5xl mb-4">📄</div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">{error}</h1>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            The blog post you're looking for doesn't exist or has been removed.
          </p>
          <button
            onClick={() => navigate(isAdmin ? '/admin' : '/blog')}
            className="bg-blue-600 dark:bg-blue-700 text-white px-6 py-2 rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition"
          >
            {isAdmin ? 'Back to Admin Dashboard' : 'Back to Blog'}
          </button>
        </div>
      </div>
    );
  }

  if (!post) {
    return null;
  }

  return (
    <>
      {/* SEO Meta Tags */}
      <Helmet>
        <title>{post.meta_title || post.title}</title>
        <meta name="description" content={post.meta_description || post.excerpt} />
        {post.meta_keywords && <meta name="keywords" content={post.meta_keywords} />}
        
        {/* Open Graph / Facebook */}
        <meta property="og:type" content="article" />
        <meta property="og:title" content={post.meta_title || post.title} />
        <meta property="og:description" content={post.meta_description || post.excerpt} />
        {post.featured_image && <meta property="og:image" content={resolveImageUrl(post.featured_image)} />}

        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content={post.meta_title || post.title} />
        <meta name="twitter:description" content={post.meta_description || post.excerpt} />
        {post.featured_image && <meta name="twitter:image" content={resolveImageUrl(post.featured_image)} />}
        
        {/* Article metadata */}
        <meta property="article:published_time" content={post.published_at || post.created_at} />
        <meta property="article:modified_time" content={post.updated_at} />
        {post.tags.map(tag => (
          <meta key={tag.id} property="article:tag" content={tag.name} />
        ))}

        {/* Canonical URL - Critical for SEO */}
        {post.canonical_url ? (
          <link rel="canonical" href={post.canonical_url} />
        ) : (
          <link rel="canonical" href={`${window.location.origin}/blog/${post.slug}`} />
        )}

        {/* Add og:url for social media crawlers */}
        <meta property="og:url" content={post.canonical_url || `${window.location.origin}/blog/${post.slug}`} />
      </Helmet>

      <div className="min-h-screen bg-gray-50 dark:bg-slate-900 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            {/* Main Article Column */}
            <motion.article
              className="lg:col-span-8"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
            >
          {/* Featured Image */}
          {post.featured_image && (
            <div className="mb-8 rounded-lg overflow-hidden shadow-lg">
              <img
                src={resolveImageUrl(post.featured_image)}
                alt={post.title}
                className="w-full h-auto object-cover"
              />
            </div>
          )}

          {/* Post Header */}
          <header className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
                <time dateTime={post.published_at || post.created_at}>
                  {new Date(post.published_at || post.created_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </time>
                <span>•</span>
                <span>{post.read_time_minutes} min read</span>
                <span>•</span>
                <span>👁️ {post.view_count} views</span>
              </div>

              {/* Admin Edit Button */}
              {isAdmin && (
                <button
                  onClick={() => navigate(`/admin/blog/${post.id}`)}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white text-sm font-medium rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition-colors shadow-sm"
                  title="Edit this post"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                  Edit Post
                </button>
              )}
            </div>

            <h1 className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-gray-100 mb-4">
              {post.title}
            </h1>

            {/* Tags */}
            {post.tags && post.tags.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-6">
                {post.tags.map((tag) => (
                  <span
                    key={tag.id}
                    className="px-3 py-1 bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 text-sm rounded-full"
                  >
                    {tag.name}
                  </span>
                ))}
              </div>
            )}

            {/* Author Info (if available) */}
            {post.author && (
              <div className="flex items-center space-x-3 pb-6 border-b border-gray-200 dark:border-slate-700">
                <div className="w-12 h-12 bg-blue-600 dark:bg-blue-700 rounded-full flex items-center justify-center text-white font-semibold">
                  {post.author.first_name?.charAt(0) || post.author.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <p className="font-medium text-gray-900 dark:text-gray-100">
                    {post.author.first_name && post.author.last_name
                      ? `${post.author.first_name} ${post.author.last_name}`
                      : post.author.username}
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Author</p>
                </div>
              </div>
            )}
          </header>

          {/* Post Content */}
          <div
            className="prose prose-lg dark:prose-invert max-w-none mb-6
                     prose-headings:text-gray-900 dark:prose-headings:text-gray-100
                     prose-p:text-gray-700 dark:prose-p:text-gray-300
                     prose-a:text-blue-600 dark:prose-a:text-blue-400
                     prose-strong:text-gray-900 dark:prose-strong:text-gray-100
                     prose-code:text-gray-900 dark:prose-code:text-gray-100
                     prose-pre:bg-gray-100 dark:prose-pre:bg-slate-800"
          >
            <ReactMarkdown>{post.content}</ReactMarkdown>
          </div>

          {/* In-Article Ad (Bottom of Content) */}
          <div className="mb-12">
            <InArticleAd />
          </div>

          {/* Back Button */}
          <div className="border-t border-gray-200 dark:border-slate-700 pt-8">
            <button
              onClick={() => navigate(isAdmin ? '/admin' : '/blog')}
              className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium flex items-center"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              {isAdmin ? 'Back to Admin Dashboard' : 'Back to Blog'}
            </button>
          </div>
            </motion.article>

            {/* Sidebar Column (Desktop Only) */}
            <motion.aside
              className="lg:col-span-4 hidden lg:block"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.4, delay: 0.2 }}
            >
              {/* Sticky Sidebar - Compact */}
              <div className="sticky top-8 space-y-6">
                {/* Sidebar Ad */}
                <div className="bg-white dark:bg-slate-800 rounded-lg shadow-md p-4 border border-gray-200 dark:border-slate-700">
                  <SidebarAd />
                </div>

                {/* Category Card (if exists) */}
                {post.category && (
                  <div className="bg-white dark:bg-slate-800 rounded-lg shadow-md p-5 border border-gray-200 dark:border-slate-700">
                    <h3 className="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-3 uppercase tracking-wide">
                      Category
                    </h3>
                    <span className="inline-flex items-center px-3 py-1.5 bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 rounded-lg font-medium text-sm">
                      {post.category.name}
                    </span>
                  </div>
                )}
              </div>
            </motion.aside>
          </div>
        </div>
      </div>
    </>
  );
};

export default BlogPostView;