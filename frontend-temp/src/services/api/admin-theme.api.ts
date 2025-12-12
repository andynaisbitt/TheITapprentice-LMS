// src/services/api/admin-theme.api.ts
/**
 * Admin theme API endpoints
 */

import { apiClient } from './client';
import { ThemeSettings } from './theme.api';

export interface ThemeSettingsUpdate {
  primary_color?: string;
  secondary_color?: string;
  accent_color?: string;
  background_light?: string;
  background_dark?: string;
  text_light?: string;
  text_dark?: string;
  font_family?: string;
  heading_font?: string;
  font_size_base?: string;
  container_width?: string;
  border_radius?: string;
  custom_css?: string | null;
  logo_url?: string | null;
  logo_dark_url?: string | null;
  site_name?: string;
  tagline?: string | null;
  advanced_settings?: Record<string, any>;
}

export const adminThemeApi = {
  /**
   * Get theme settings (admin)
   */
  get: async (): Promise<ThemeSettings> => {
    const response = await apiClient.get<ThemeSettings>('/api/v1/admin/theme');
    return response.data;
  },

  /**
   * Update theme settings
   */
  update: async (data: ThemeSettingsUpdate): Promise<ThemeSettings> => {
    const response = await apiClient.put<ThemeSettings>('/api/v1/admin/theme', data);
    return response.data;
  },

  /**
   * Reset theme to defaults
   */
  reset: async (): Promise<ThemeSettings> => {
    const response = await apiClient.post<ThemeSettings>('/api/v1/admin/theme/reset');
    return response.data;
  },
};
