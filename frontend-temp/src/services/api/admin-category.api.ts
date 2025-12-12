// src/services/api/admin-category.api.ts
/**
 * Admin Category Management API
 */

import { apiClient } from './client';

export interface Category {
  id: number;
  name: string;
  slug: string;
  description?: string;
  parent_id?: number;
  color: string;
  icon?: string;
  meta_title?: string;
  meta_description?: string;
  display_order: number;
  created_at: string;
  updated_at?: string;
  post_count?: number;
}

export interface CategoryCreate {
  name: string;
  description?: string;
  parent_id?: number;
  color?: string;
  icon?: string;
  meta_title?: string;
  meta_description?: string;
}

export interface CategoryUpdate {
  name?: string;
  description?: string;
  parent_id?: number;
  color?: string;
  icon?: string;
  meta_title?: string;
  meta_description?: string;
  display_order?: number;
}

export const adminCategoryApi = {
  /**
   * Get all categories (admin)
   */
  getAll: async (): Promise<Category[]> => {
    const response = await apiClient.get<Category[]>('/api/v1/admin/blog/categories');
    return response.data;
  },

  /**
   * Create category (admin)
   */
  create: async (data: CategoryCreate): Promise<Category> => {
    const response = await apiClient.post<Category>('/api/v1/admin/blog/categories', data);
    return response.data;
  },

  /**
   * Update category (admin)
   */
  update: async (id: number, data: CategoryUpdate): Promise<Category> => {
    const response = await apiClient.put<Category>(`/api/v1/admin/blog/categories/${id}`, data);
    return response.data;
  },

  /**
   * Delete category (admin)
   */
  delete: async (id: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/blog/categories/${id}`);
  },
};
