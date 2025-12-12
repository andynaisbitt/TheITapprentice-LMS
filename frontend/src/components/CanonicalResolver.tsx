// Frontend/src/components/CanonicalResolver.tsx
/**
 * CanonicalResolver - Resolves canonical URLs to actual content
 *
 * This component handles requests to canonical URLs by:
 * 1. Constructing the full canonical URL from the path
 * 2. Querying the unified content API
 * 3. Redirecting to the appropriate slug-based URL
 *
 * Example:
 * User visits: /RAM-Price-Spikes
 * API lookup: https://theitapprentice.com/RAM-Price-Spikes
 * Result: { type: 'post', slug: 'ram-has-gone-mad-2025-price-crisis' }
 * Action: 301 redirect to /blog/ram-has-gone-mad-2025-price-crisis
 */

import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Navigate } from 'react-router-dom';
import { apiClient } from '../services/api';

interface ContentLookupResponse {
  type: 'post' | 'page';
  slug: string;
  data: any;
}

export const CanonicalResolver: React.FC = () => {
  const { possibleCanonical } = useParams<{ possibleCanonical: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  useEffect(() => {
    const resolveCanonicalUrl = async () => {
      if (!possibleCanonical) {
        setError('No path provided');
        setLoading(false);
        return;
      }

      // Excluded paths that should NOT be checked as canonical URLs
      // These are handled by specific routes and should never trigger the resolver
      const excludedPaths = [
        'login',
        'admin',
        'dashboard',
        'unsubscribe',
        'blog',
        'pages',
        'privacy',
        'terms',
        'about',
        'contact',
      ];

      // If this is an excluded path, immediately show 404
      if (excludedPaths.includes(possibleCanonical.toLowerCase())) {
        setError('Page not found');
        setLoading(false);
        return;
      }

      try {
        // Construct the full canonical URL
        const canonicalUrl = `${window.location.origin}/${possibleCanonical}`;

        // Query the unified content lookup API
        const response = await apiClient.get<ContentLookupResponse>(
          '/api/v1/content/by-canonical',
          { params: { url: canonicalUrl } }
        );

        const { type, slug } = response.data;

        // Construct the target URL based on content type
        const targetUrl = type === 'post' ? `/blog/${slug}` : `/pages/${slug}`;

        // Set redirect URL (will trigger Navigate component)
        setRedirectUrl(targetUrl);
      } catch (err: any) {
        // If 404, this is not a canonical URL - show 404
        if (err.response?.status === 404) {
          setError('Page not found');
        } else {
          setError('Failed to resolve URL');
        }
      } finally {
        setLoading(false);
      }
    };

    resolveCanonicalUrl();
  }, [possibleCanonical]);

  // If we found a redirect URL, navigate to it
  if (redirectUrl) {
    return <Navigate to={redirectUrl} replace />;
  }

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Resolving URL...</p>
        </div>
      </div>
    );
  }

  // Error state (404 or other error)
  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-900">
        <div className="max-w-md w-full bg-white dark:bg-slate-800 shadow-lg rounded-lg p-8 text-center border border-gray-200 dark:border-slate-700">
          <div className="text-red-600 dark:text-red-400 text-5xl mb-4">404</div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
            Page Not Found
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            The page you're looking for doesn't exist or has been removed.
          </p>
          <button
            onClick={() => navigate('/')}
            className="bg-blue-600 dark:bg-blue-700 text-white px-6 py-2 rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition"
          >
            Go Home
          </button>
        </div>
      </div>
    );
  }

  // Should never reach here
  return null;
};

export default CanonicalResolver;
