// src/utils/imageUrl.ts
/**
 * Utility to resolve image URLs
 * Prepends API base URL to relative image paths from uploads
 */

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8100';

/**
 * Resolve image URL
 * - If URL starts with /static, prepend API base URL
 * - If URL is already absolute (http/https), return as-is
 * - Otherwise, return the URL unchanged
 */
export const resolveImageUrl = (url?: string | null): string => {
  if (!url) return '';

  // Already absolute URL
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url;
  }

  // Relative path from backend (uploaded images)
  if (url.startsWith('/static/')) {
    return `${API_URL}${url}`;
  }

  // Already has base URL or is a data URL
  return url;
};
