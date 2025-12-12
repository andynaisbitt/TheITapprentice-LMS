// src/services/api/navigation.api.ts
/**
 * Navigation API endpoints
 */

import { apiClient } from './client';

export interface MenuItem {
  id: number;
  label: string;
  url: string;
  order: number;
  parent_id: number | null;
  visible: boolean;
  show_in_header: boolean;
  show_in_footer: boolean;
  target_blank: boolean;
  created_at: string;
  updated_at: string | null;
  children?: MenuItem[];  // For dropdown/submenu items
}

export interface NavigationResponse {
  header_items: MenuItem[];
  footer_items: MenuItem[];
}

export const navigationApi = {
  /**
   * Get all visible navigation items (public)
   */
  getNavigation: async (): Promise<NavigationResponse> => {
    const response = await apiClient.get<NavigationResponse>('/api/v1/navigation');
    return response.data;
  },
};
