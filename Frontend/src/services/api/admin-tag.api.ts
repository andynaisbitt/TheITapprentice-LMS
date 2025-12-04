// src/services/api/admin-tag.api.ts
/**
 * Admin Tag Management API
 */

import { apiClient } from './client';
import type { Tag, TagCreate, TagUpdate } from './types';

export const adminTagApi = {
  /**
   * Get all tags (admin)
   */
  getAll: async (): Promise<Tag[]> => {
    const response = await apiClient.get<Tag[]>('/api/v1/blog/tags');
    return response.data;
  },

  /**
   * Create tag (admin)
   */
  create: async (data: TagCreate): Promise<Tag> => {
    const response = await apiClient.post<Tag>('/api/v1/admin/blog/tags', data);
    return response.data;
  },

  /**
   * Update tag (admin)
   */
  update: async (id: number, data: TagUpdate): Promise<Tag> => {
    const response = await apiClient.put<Tag>(`/api/v1/admin/blog/tags/${id}`, data);
    return response.data;
  },

  /**
   * Delete tag (admin)
   */
  delete: async (id: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/blog/tags/${id}`);
  },
};
