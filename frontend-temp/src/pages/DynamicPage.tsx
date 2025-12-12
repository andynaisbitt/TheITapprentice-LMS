// Frontend/src/pages/DynamicPage.tsx
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { BlockRenderer } from '../components/Pages/BlockRenderer';
import { pagesApi, Page } from '../services/api/pages.api';

interface DynamicPageProps {
  slug?: string; // Allow passing slug as prop (for hardcoded routes)
}

export const DynamicPage: React.FC<DynamicPageProps> = ({ slug: propSlug }) => {
  const { slug: urlSlug } = useParams<{ slug: string }>();
  const slug = propSlug || urlSlug; // Prop takes precedence over URL param
  const [page, setPage] = useState<Page | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPage = async () => {
      if (!slug) return;

      try {
        setLoading(true);
        setError(null);
        const data = await pagesApi.getBySlug(slug);
        setPage(data);
      } catch (err: any) {
        console.error('Failed to load page:', err);
        setError(err.response?.data?.detail || 'Page not found');
      } finally {
        setLoading(false);
      }
    };

    fetchPage();
  }, [slug]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error || !page) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-6xl font-bold text-gray-900 dark:text-white mb-4">404</h1>
          <p className="text-xl text-gray-600 dark:text-gray-400 mb-8">
            {error || 'Page not found'}
          </p>
          <a
            href="/"
            className="inline-block bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3 rounded-lg transition-colors"
          >
            Go Home
          </a>
        </div>
      </div>
    );
  }

  return (
    <>
      <Helmet>
        <title>{page.meta_title || page.title}</title>
        {page.meta_description && <meta name="description" content={page.meta_description} />}
        {page.meta_keywords && <meta name="keywords" content={page.meta_keywords} />}

        {/* Open Graph */}
        <meta property="og:title" content={page.meta_title || page.title} />
        {page.meta_description && <meta property="og:description" content={page.meta_description} />}
        <meta property="og:type" content="website" />

        {/* Twitter Card */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content={page.meta_title || page.title} />
        {page.meta_description && <meta name="twitter:description" content={page.meta_description} />}

        {/* Canonical URL - Critical for SEO */}
        {page.canonical_url ? (
          <link rel="canonical" href={page.canonical_url} />
        ) : (
          <link rel="canonical" href={`${window.location.origin}/pages/${page.slug}`} />
        )}

        {/* Add og:url for social media crawlers */}
        <meta property="og:url" content={page.canonical_url || `${window.location.origin}/pages/${page.slug}`} />
      </Helmet>

      <BlockRenderer blocks={page.blocks} />
    </>
  );
};

export default DynamicPage;
