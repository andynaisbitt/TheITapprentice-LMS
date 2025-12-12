// src/pages/blog/BlogPostView.tsx
/**
 * Dynamic Blog Post Viewer - Beautiful, Mobile-First Design
 * Features: Centered content, optimal readability, no distracting sidebar
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import { blogApi, BlogPost } from '../../services/api';
import { Helmet } from 'react-helmet-async';
import { InArticleAd } from '../../components/ads/GoogleAdSense';
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
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-900 px-4">
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

      {/* Main Content - Centered, Magazine-Style Layout */}
      <div className="min-h-screen bg-gray-50 dark:bg-slate-900">
        <motion.article
          className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          {/* Back Button - Top */}
          <button
            onClick={() => navigate(isAdmin ? '/admin' : '/blog')}
            className="group flex items-center gap-2 text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 font-medium mb-8 transition-colors"
          >
            <svg className="w-5 h-5 transform group-hover:-translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            <span className="text-sm sm:text-base">{isAdmin ? 'Back to Admin' : 'Back to Blog'}</span>
          </button>

          {/* Post Metadata - Above Title */}
          <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-sm text-gray-600 dark:text-gray-400 mb-4">
            {post.category && (
              <>
                <span className="inline-flex items-center px-3 py-1 bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded-full font-medium text-xs sm:text-sm">
                  {post.category.name}
                </span>
                <span className="hidden sm:inline">•</span>
              </>
            )}
            <time dateTime={post.published_at || post.created_at} className="text-xs sm:text-sm">
              {new Date(post.published_at || post.created_at).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
              })}
            </time>
            <span className="hidden sm:inline">•</span>
            <span className="text-xs sm:text-sm">{post.read_time_minutes} min read</span>
            <span className="hidden sm:inline">•</span>
            <span className="text-xs sm:text-sm">👁️ {post.view_count.toLocaleString()} views</span>
          </div>

          {/* Post Title */}
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-bold text-gray-900 dark:text-gray-100 mb-4 sm:mb-6 leading-tight">
            {post.title}
          </h1>

          {/* Tags */}
          {post.tags && post.tags.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-6">
              {post.tags.map((tag) => (
                <span
                  key={tag.id}
                  className="px-2.5 py-1 bg-gray-100 dark:bg-slate-800 text-gray-700 dark:text-gray-300 text-xs sm:text-sm rounded-md border border-gray-200 dark:border-slate-700"
                >
                  #{tag.name}
                </span>
              ))}
            </div>
          )}

          {/* Author Info */}
          {post.author && (
            <div className="flex items-center justify-between pb-6 mb-8 border-b border-gray-200 dark:border-slate-700">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 sm:w-12 sm:h-12 bg-gradient-to-br from-blue-600 to-blue-700 dark:from-blue-500 dark:to-blue-600 rounded-full flex items-center justify-center text-white font-semibold text-sm sm:text-base shadow-md">
                  {post.author.first_name?.charAt(0) || post.author.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <p className="font-medium text-gray-900 dark:text-gray-100 text-sm sm:text-base">
                    {post.author.first_name && post.author.last_name
                      ? `${post.author.first_name} ${post.author.last_name}`
                      : post.author.username}
                  </p>
                  <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Author</p>
                </div>
              </div>

              {/* Admin Edit Button */}
              {isAdmin && (
                <button
                  onClick={() => navigate(`/admin/blog/${post.id}`)}
                  className="flex items-center gap-2 px-3 sm:px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white text-xs sm:text-sm font-medium rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition-colors shadow-sm"
                  title="Edit this post"
                >
                  <svg className="w-3.5 h-3.5 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                  <span className="hidden sm:inline">Edit Post</span>
                  <span className="sm:hidden">Edit</span>
                </button>
              )}
            </div>
          )}

          {/* Featured Image */}
          {post.featured_image && (
            <div className="mb-8 sm:mb-12 rounded-lg sm:rounded-xl overflow-hidden shadow-xl">
              <img
                src={resolveImageUrl(post.featured_image)}
                alt={post.featured_image_alt || post.title}
                className="w-full h-auto object-cover"
              />
              {post.featured_image_caption && (
                <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 text-center mt-2 px-4">
                  {post.featured_image_caption}
                </p>
              )}
            </div>
          )}

          {/* Post Content - Optimized Typography */}
          <div
            className="prose prose-base sm:prose-lg dark:prose-invert max-w-none mb-8 sm:mb-12
                       prose-headings:font-bold prose-headings:text-gray-900 dark:prose-headings:text-gray-100
                       prose-headings:tracking-tight prose-headings:scroll-mt-20
                       prose-h2:text-2xl sm:prose-h2:text-3xl prose-h2:mt-12 prose-h2:mb-4
                       prose-h3:text-xl sm:prose-h3:text-2xl prose-h3:mt-8 prose-h3:mb-3
                       prose-p:text-gray-700 dark:prose-p:text-gray-300 prose-p:leading-relaxed prose-p:mb-4
                       prose-a:text-blue-600 dark:prose-a:text-blue-400 prose-a:no-underline hover:prose-a:underline prose-a:font-medium
                       prose-strong:text-gray-900 dark:prose-strong:text-gray-100 prose-strong:font-semibold
                       prose-code:text-gray-900 dark:prose-code:text-gray-100 prose-code:bg-gray-100 dark:prose-code:bg-slate-800
                       prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-sm
                       prose-pre:bg-gray-100 dark:prose-pre:bg-slate-800 prose-pre:border prose-pre:border-gray-200 dark:prose-pre:border-slate-700
                       prose-pre:rounded-lg prose-pre:shadow-sm
                       prose-blockquote:border-l-4 prose-blockquote:border-blue-600 dark:prose-blockquote:border-blue-400
                       prose-blockquote:bg-blue-50 dark:prose-blockquote:bg-blue-900/10 prose-blockquote:py-4 prose-blockquote:px-6
                       prose-blockquote:rounded-r-lg prose-blockquote:not-italic
                       prose-ul:list-disc prose-ul:pl-6 prose-ul:space-y-2
                       prose-ol:list-decimal prose-ol:pl-6 prose-ol:space-y-2
                       prose-li:text-gray-700 dark:prose-li:text-gray-300
                       prose-img:rounded-lg prose-img:shadow-md"
          >
            <ReactMarkdown>{post.content}</ReactMarkdown>
          </div>

          {/* In-Article Ad */}
          <div className="my-12">
            <InArticleAd />
          </div>

          {/* Post Footer - Categories & Tags Summary */}
          <div className="border-t border-gray-200 dark:border-slate-700 pt-8 mt-12">
            <div className="flex flex-wrap gap-4 items-center justify-between">
              {/* Categories */}
              {post.categories && post.categories.length > 0 && (
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Filed under:</span>
                  <div className="flex flex-wrap gap-2">
                    {post.categories.map((category) => (
                      <span
                        key={category.id}
                        className="px-3 py-1 bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded-full text-sm font-medium"
                      >
                        {category.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Share hint (future feature) */}
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {post.view_count.toLocaleString()} views
              </div>
            </div>
          </div>

          {/* Navigation */}
          <div className="border-t border-gray-200 dark:border-slate-700 pt-8 mt-8">
            <button
              onClick={() => navigate(isAdmin ? '/admin' : '/blog')}
              className="group flex items-center gap-2 text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors"
            >
              <svg className="w-5 h-5 transform group-hover:-translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              <span className="text-sm sm:text-base">{isAdmin ? 'Back to Admin Dashboard' : 'Back to Blog'}</span>
            </button>
          </div>
        </motion.article>
      </div>
    </>
  );
};

export default BlogPostView;
