// src/services/api/admin-blog.api.ts
/**
 * Admin blog API endpoints (Protected)
 */

import { apiClient } from './client';
import {
  BlogPost,
  BlogPostCreate,
  BlogPostUpdate,
  BlogPostListResponse,
  BlogPostFilters,
  Tag,
  TagCreate,
  TagUpdate,
  BulkPostUpdate,
  BulkUpdateResponse,
} from './types';

export const adminBlogApi = {
  // ============================================================================
  // POST MANAGEMENT
  // ============================================================================

  /**
   * Get all posts including drafts (admin only)
   */
  getAllPosts: async (filters?: BlogPostFilters): Promise<BlogPostListResponse> => {
    const response = await apiClient.get<BlogPostListResponse>('/api/v1/admin/blog/posts', {
      params: filters,
    });
    return response.data;
  },

  /**
   * Get single post by ID (admin only)
   */
  getPostById: async (postId: number): Promise<BlogPost> => {
    const response = await apiClient.get<BlogPost>(`/api/v1/admin/blog/posts/${postId}`);
    return response.data;
  },

  /**
   * Create new post (admin only)
   */
  createPost: async (postData: BlogPostCreate): Promise<BlogPost> => {
    const response = await apiClient.post<BlogPost>('/api/v1/admin/blog/posts', postData);
    return response.data;
  },

  /**
   * Update post (admin only)
   */
  updatePost: async (postId: number, postData: BlogPostUpdate): Promise<BlogPost> => {
    const response = await apiClient.put<BlogPost>(`/api/v1/admin/blog/posts/${postId}`, postData);
    return response.data;
  },

  /**
   * Delete post (admin only)
   */
  deletePost: async (postId: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/blog/posts/${postId}`);
  },

  /**
   * Toggle publish status (admin only)
   */
  togglePublish: async (postId: number, published: boolean): Promise<BlogPost> => {
    const response = await apiClient.patch<BlogPost>(
      `/api/v1/admin/blog/posts/${postId}/publish`,
      null,
      { params: { published } }
    );
    return response.data;
  },

  /**
   * Bulk update posts (admin only)
   */
  bulkUpdate: async (bulkData: BulkPostUpdate): Promise<BulkUpdateResponse> => {
    const response = await apiClient.post<BulkUpdateResponse>(
      '/api/v1/admin/blog/posts/bulk-update',
      bulkData
    );
    return response.data;
  },

  // ============================================================================
  // TAG MANAGEMENT
  // ============================================================================

  /**
   * Create tag (admin only)
   */
  createTag: async (tagData: TagCreate): Promise<Tag> => {
    const response = await apiClient.post<Tag>('/api/v1/admin/blog/tags', tagData);
    return response.data;
  },

  /**
   * Update tag (admin only)
   */
  updateTag: async (tagId: number, tagData: TagUpdate): Promise<Tag> => {
    const response = await apiClient.put<Tag>(`/api/v1/admin/blog/tags/${tagId}`, tagData);
    return response.data;
  },

  /**
   * Delete tag (admin only)
   */
  deleteTag: async (tagId: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/blog/tags/${tagId}`);
  },

  // ============================================================================
  // MEDIA MANAGEMENT
  // ============================================================================

  /**
   * Upload image
   */
  uploadImage: async (
    file: File,
    altText?: string,
    caption?: string,
    optimize: boolean = true
  ): Promise<{
    id: number;
    filename: string;
    url: string;
    file_size: number;
    width: number;
    height: number;
    alt_text?: string;
    caption?: string;
  }> => {
    const formData = new FormData();
    formData.append('file', file);
    if (altText) formData.append('alt_text', altText);
    if (caption) formData.append('caption', caption);
    formData.append('optimize', optimize.toString());

    const response = await apiClient.post('/api/v1/admin/blog/media/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  /**
   * Get media library
   */
  getMediaLibrary: async (page: number = 1, pageSize: number = 20) => {
    const response = await apiClient.get('/api/v1/admin/blog/media', {
      params: { page, page_size: pageSize },
    });
    return response.data;
  },

  /**
   * Delete media file
   */
  deleteMedia: async (mediaId: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/blog/media/${mediaId}`);
  },
};