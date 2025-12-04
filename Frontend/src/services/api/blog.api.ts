// src/services/api/blog.api.ts
/**
 * Public blog API endpoints
 */

import { apiClient } from './client';
import { BlogPost, BlogPostListResponse, BlogPostFilters, Tag } from './types';

export const blogApi = {
  /**
   * Get published blog posts (public)
   */
  getPosts: async (filters?: BlogPostFilters): Promise<BlogPostListResponse> => {
    const response = await apiClient.get<BlogPostListResponse>('/api/v1/blog/posts', {
      params: filters,
    });
    return response.data;
  },

  /**
   * Get single post by slug (public)
   */
  getBySlug: async (slug: string): Promise<BlogPost> => {
    const response = await apiClient.get<BlogPost>(`/api/v1/blog/posts/${slug}`);
    return response.data;
  },

  /**
   * Get featured posts (public)
   */
  getFeatured: async (limit: number = 5): Promise<BlogPost[]> => {
    const response = await apiClient.get<BlogPost[]>('/api/v1/blog/posts/featured/list', {
      params: { limit },
    });
    return response.data;
  },

  /**
   * Get popular posts (public)
   */
  getPopular: async (limit: number = 5): Promise<BlogPost[]> => {
    const response = await apiClient.get<BlogPost[]>('/api/v1/blog/posts/popular/list', {
      params: { limit },
    });
    return response.data;
  },

  /**
   * Get recent posts (public)
   */
  getRecent: async (limit: number = 5): Promise<BlogPost[]> => {
    const response = await apiClient.get<BlogPost[]>('/api/v1/blog/posts/recent/list', {
      params: { limit },
    });
    return response.data;
  },

  /**
   * Get all tags (public)
   */
  getTags: async (): Promise<Tag[]> => {
    const response = await apiClient.get<Tag[]>('/api/v1/blog/tags');
    return response.data;
  },

  /**
   * Get tag by slug (public)
   */
  getTagBySlug: async (slug: string): Promise<Tag> => {
    const response = await apiClient.get<Tag>(`/api/v1/blog/tags/${slug}`);
    return response.data;
  },

  /**
   * Get blog statistics (public)
   */
  getStats: async (): Promise<{
    total_posts: number;
    total_categories: number;
    total_views: number;
    total_tags: number;
  }> => {
    const response = await apiClient.get('/api/v1/blog/stats');
    return response.data;
  },

  /**
   * Get all categories (public)
   */
  getCategories: async (): Promise<Array<{
    id: number;
    name: string;
    slug: string;
    color?: string;
    icon?: string;
    post_count?: number;
  }>> => {
    const response = await apiClient.get('/api/v1/blog/categories');
    return response.data;
  },

  /**
   * Get category by slug (public)
   */
  getCategoryBySlug: async (slug: string): Promise<{
    id: number;
    name: string;
    slug: string;
    description?: string;
    color?: string;
    icon?: string;
    post_count?: number;
  }> => {
    const response = await apiClient.get(`/api/v1/blog/categories/${slug}`);
    return response.data;
  },
};