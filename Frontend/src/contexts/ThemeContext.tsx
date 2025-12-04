// src/contexts/ThemeContext.tsx
/**
 * Theme Context Provider
 * Fetches theme settings from API and injects CSS variables
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import { themeApi, ThemeSettings } from '../services/api/theme.api';

interface ThemeContextType {
  theme: ThemeSettings | null;
  loading: boolean;
  refreshTheme: () => Promise<void>;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setTheme] = useState<ThemeSettings | null>(null);
  const [loading, setLoading] = useState(true);

  const loadTheme = async () => {
    try {
      const themeData = await themeApi.getTheme();
      setTheme(themeData);
      applyTheme(themeData);
    } catch (error) {
      console.error('Failed to load theme:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyTheme = (themeSettings: ThemeSettings) => {
    const root = document.documentElement;

    // Inject CSS variables
    root.style.setProperty('--color-primary', themeSettings.primary_color);
    root.style.setProperty('--color-secondary', themeSettings.secondary_color);
    root.style.setProperty('--color-accent', themeSettings.accent_color);
    root.style.setProperty('--color-background-light', themeSettings.background_light);
    root.style.setProperty('--color-background-dark', themeSettings.background_dark);
    root.style.setProperty('--color-text-light', themeSettings.text_light);
    root.style.setProperty('--color-text-dark', themeSettings.text_dark);
    root.style.setProperty('--font-family', themeSettings.font_family);
    root.style.setProperty('--font-heading', themeSettings.heading_font);
    root.style.setProperty('--font-size-base', themeSettings.font_size_base);
    root.style.setProperty('--container-width', themeSettings.container_width);
    root.style.setProperty('--border-radius', themeSettings.border_radius);

    // Apply background colors directly to body
    const isDarkMode = root.classList.contains('dark');
    document.body.style.backgroundColor = isDarkMode
      ? themeSettings.background_dark
      : themeSettings.background_light;

    // Inject dynamic CSS to override Tailwind classes with theme colors
    let themeStyleElement = document.getElementById('dynamic-theme-overrides');
    if (!themeStyleElement) {
      themeStyleElement = document.createElement('style');
      themeStyleElement.id = 'dynamic-theme-overrides';
      document.head.appendChild(themeStyleElement);
    }

    themeStyleElement.textContent = `
      /* Apply theme background colors - ONLY when NOT using dark mode classes */
      html:not(.dark) body {
        background-color: ${themeSettings.background_light} !important;
      }
      html.dark body {
        background-color: ${themeSettings.background_dark} !important;
      }

      /* Override common white/gray backgrounds in LIGHT MODE ONLY */
      html:not(.dark) .bg-white {
        background-color: ${themeSettings.background_light} !important;
      }
      html:not(.dark) .bg-gray-50 {
        background-color: ${adjustColor(themeSettings.background_light, 5)} !important;
      }
      html:not(.dark) .bg-gray-100 {
        background-color: ${adjustColor(themeSettings.background_light, 10)} !important;
      }

      /* Override common dark backgrounds in DARK MODE ONLY */
      html.dark .bg-slate-900 {
        background-color: ${themeSettings.background_dark} !important;
      }
      html.dark .bg-slate-800 {
        background-color: ${adjustColor(themeSettings.background_dark, 10)} !important;
      }
      html.dark .bg-gray-800 {
        background-color: ${adjustColor(themeSettings.background_dark, 10)} !important;
      }

      /* Apply theme text colors - properly scoped */
      html:not(.dark) .text-gray-900 {
        color: ${themeSettings.text_light} !important;
      }
      html.dark .text-white {
        color: ${themeSettings.text_dark} !important;
      }

      /* Apply theme primary color to buttons and links - works in both modes */
      .bg-blue-600 {
        background-color: ${themeSettings.primary_color} !important;
      }
      .bg-blue-700 {
        background-color: ${adjustColor(themeSettings.primary_color, -10)} !important;
      }
      .hover\\:bg-blue-700:hover {
        background-color: ${adjustColor(themeSettings.primary_color, -10)} !important;
      }
      .text-blue-600 {
        color: ${themeSettings.primary_color} !important;
      }
      .border-blue-600 {
        border-color: ${themeSettings.primary_color} !important;
      }
    `;

    // Inject custom CSS if provided
    let customStyleElement = document.getElementById('custom-theme-css');
    if (themeSettings.custom_css) {
      if (!customStyleElement) {
        customStyleElement = document.createElement('style');
        customStyleElement.id = 'custom-theme-css';
        document.head.appendChild(customStyleElement);
      }
      customStyleElement.textContent = themeSettings.custom_css;
    } else if (customStyleElement) {
      customStyleElement.remove();
    }
  };

  // Helper function to adjust color brightness
  const adjustColor = (color: string, percent: number): string => {
    const num = parseInt(color.replace('#', ''), 16);
    const amt = Math.round(2.55 * percent);
    const R = (num >> 16) + amt;
    const G = (num >> 8 & 0x00FF) + amt;
    const B = (num & 0x0000FF) + amt;
    return '#' + (
      0x1000000 +
      (R < 255 ? (R < 1 ? 0 : R) : 255) * 0x10000 +
      (G < 255 ? (G < 1 ? 0 : G) : 255) * 0x100 +
      (B < 255 ? (B < 1 ? 0 : B) : 255)
    ).toString(16).slice(1).toUpperCase();
  };

  const refreshTheme = async () => {
    setLoading(true);
    await loadTheme();
  };

  useEffect(() => {
    loadTheme();
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, loading, refreshTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
