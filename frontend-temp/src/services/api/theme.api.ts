// src/services/api/theme.api.ts
/**
 * Theme API endpoints
 */

import { apiClient } from './client';

export interface ThemeSettings {
  id: number;
  primary_color: string;
  secondary_color: string;
  accent_color: string;
  background_light: string;
  background_dark: string;
  text_light: string;
  text_dark: string;
  font_family: string;
  heading_font: string;
  font_size_base: string;
  container_width: string;
  border_radius: string;
  custom_css: string | null;
  logo_url: string | null;
  logo_dark_url: string | null;
  site_name: string;
  tagline: string | null;
  advanced_settings: Record<string, any>;
  updated_at: string | null;
}

export const themeApi = {
  /**
   * Get theme settings (public)
   */
  getTheme: async (): Promise<ThemeSettings> => {
    const response = await apiClient.get<ThemeSettings>('/api/v1/theme');
    return response.data;
  },
};
