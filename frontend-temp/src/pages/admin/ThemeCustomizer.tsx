// src/pages/admin/ThemeCustomizer.tsx
/**
 * Theme Customizer - Admin interface for theme settings
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminThemeApi, ThemeSettingsUpdate } from '../../services/api/admin-theme.api';
import { ThemeSettings } from '../../services/api/theme.api';
import { useTheme } from '../../contexts/ThemeContext';

export const ThemeCustomizer: React.FC = () => {
  const navigate = useNavigate();
  const { refreshTheme } = useTheme();
  const [settings, setSettings] = useState<ThemeSettings | null>(null);
  const [formData, setFormData] = useState<ThemeSettingsUpdate>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await adminThemeApi.get();
      setSettings(data);
      setFormData(data);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load theme settings');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      const updated = await adminThemeApi.update(formData);
      setSettings(updated);
      setSuccessMessage('Theme settings saved successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);

      // Refresh theme in the app
      await refreshTheme();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to save theme settings');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Are you sure you want to reset theme to defaults? This cannot be undone.')) return;

    try {
      setSaving(true);
      const resetData = await adminThemeApi.reset();
      setSettings(resetData);
      setFormData(resetData);
      setSuccessMessage('Theme reset to defaults!');
      setTimeout(() => setSuccessMessage(null), 3000);

      // Refresh theme in the app
      await refreshTheme();
    } catch (err: any) {
      alert('Failed to reset theme');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="p-8">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading theme settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Theme Customizer
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Customize colors, fonts, and layout
            </p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => navigate('/admin')}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
            >
              ← Back to Dashboard
            </button>
            <button
              onClick={handleReset}
              disabled={saving}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition font-medium disabled:opacity-50"
            >
              Reset to Defaults
            </button>
          </div>
        </div>

        {/* Success Message */}
        {successMessage && (
          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 mb-6">
            <p className="text-green-600 dark:text-green-400">{successMessage}</p>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
            <p className="text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-6">
          {/* Site Identity */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Site Identity
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Site Name
                </label>
                <input
                  type="text"
                  value={formData.site_name || ''}
                  onChange={(e) => setFormData({ ...formData, site_name: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Tagline
                </label>
                <input
                  type="text"
                  value={formData.tagline || ''}
                  onChange={(e) => setFormData({ ...formData, tagline: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </div>

          {/* Colors */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Colors
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { key: 'primary_color', label: 'Primary' },
                { key: 'secondary_color', label: 'Secondary' },
                { key: 'accent_color', label: 'Accent' },
                { key: 'background_light', label: 'Background (Light)' },
                { key: 'background_dark', label: 'Background (Dark)' },
                { key: 'text_light', label: 'Text (Light Mode)' },
                { key: 'text_dark', label: 'Text (Dark Mode)' },
              ].map((field) => (
                <div key={field.key}>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    {field.label}
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="color"
                      value={formData[field.key as keyof ThemeSettingsUpdate] as string || '#000000'}
                      onChange={(e) => setFormData({ ...formData, [field.key]: e.target.value })}
                      className="w-16 h-10 border border-gray-300 dark:border-gray-600 rounded cursor-pointer"
                    />
                    <input
                      type="text"
                      value={formData[field.key as keyof ThemeSettingsUpdate] as string || ''}
                      onChange={(e) => setFormData({ ...formData, [field.key]: e.target.value })}
                      className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="#000000"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Typography */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Typography
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Body Font
                </label>
                <input
                  type="text"
                  value={formData.font_family || ''}
                  onChange={(e) => setFormData({ ...formData, font_family: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Inter, system-ui, sans-serif"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Heading Font
                </label>
                <input
                  type="text"
                  value={formData.heading_font || ''}
                  onChange={(e) => setFormData({ ...formData, heading_font: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Inter, system-ui, sans-serif"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Base Font Size
                </label>
                <input
                  type="text"
                  value={formData.font_size_base || ''}
                  onChange={(e) => setFormData({ ...formData, font_size_base: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="16px"
                />
              </div>
            </div>
          </div>

          {/* Layout */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Layout
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Container Width
                </label>
                <input
                  type="text"
                  value={formData.container_width || ''}
                  onChange={(e) => setFormData({ ...formData, container_width: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="1280px"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Border Radius
                </label>
                <input
                  type="text"
                  value={formData.border_radius || ''}
                  onChange={(e) => setFormData({ ...formData, border_radius: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="0.5rem"
                />
              </div>
            </div>
          </div>

          {/* Custom CSS */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Custom CSS
            </h2>
            <textarea
              value={formData.custom_css || ''}
              onChange={(e) => setFormData({ ...formData, custom_css: e.target.value })}
              rows={10}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="/* Add custom CSS here */"
            />
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Custom CSS will be injected into the page. Use with caution.
            </p>
          </div>

          {/* Save Button */}
          <div className="flex justify-end gap-3">
            <button
              type="submit"
              disabled={saving}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ThemeCustomizer;
