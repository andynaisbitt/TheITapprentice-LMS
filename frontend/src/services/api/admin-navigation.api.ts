// src/services/api/admin-navigation.api.ts
/**
 * Admin navigation API endpoints
 */

import { apiClient } from './client';
import { MenuItem } from './navigation.api';

export interface MenuItemCreate {
  label: string;
  url: string;
  order?: number;
  parent_id?: number | null;
  visible?: boolean;
  show_in_header?: boolean;
  show_in_footer?: boolean;
  target_blank?: boolean;
}

export interface MenuItemUpdate {
  label?: string;
  url?: string;
  order?: number;
  parent_id?: number | null;
  visible?: boolean;
  show_in_header?: boolean;
  show_in_footer?: boolean;
  target_blank?: boolean;
}

export const adminNavigationApi = {
  /**
   * Get all menu items (admin)
   */
  getAll: async (): Promise<MenuItem[]> => {
    const response = await apiClient.get<MenuItem[]>('/api/v1/admin/navigation');
    return response.data;
  },

  /**
   * Get single menu item by ID
   */
  getById: async (id: number): Promise<MenuItem> => {
    const response = await apiClient.get<MenuItem>(`/api/v1/admin/navigation/${id}`);
    return response.data;
  },

  /**
   * Create new menu item
   */
  create: async (data: MenuItemCreate): Promise<MenuItem> => {
    const response = await apiClient.post<MenuItem>('/api/v1/admin/navigation', data);
    return response.data;
  },

  /**
   * Update menu item
   */
  update: async (id: number, data: MenuItemUpdate): Promise<MenuItem> => {
    const response = await apiClient.put<MenuItem>(`/api/v1/admin/navigation/${id}`, data);
    return response.data;
  },

  /**
   * Delete menu item
   */
  delete: async (id: number): Promise<void> => {
    await apiClient.delete(`/api/v1/admin/navigation/${id}`);
  },

  /**
   * Bulk reorder menu items
   */
  reorder: async (items: Array<{ id: number; order: number }>): Promise<void> => {
    await apiClient.post('/api/v1/admin/navigation/reorder', items);
  },
};
