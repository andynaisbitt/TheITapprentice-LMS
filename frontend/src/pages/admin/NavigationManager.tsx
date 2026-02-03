// src/pages/admin/NavigationManager.tsx
/**
 * Navigation Manager - Admin CRUD interface for menu items
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminNavigationApi, MenuItemCreate, MenuItemUpdate } from '../../services/api/admin-navigation.api';
import { MenuItem } from '../../services/api/navigation.api';
import { usePlugins } from '../../state/contexts/PluginsContext';

// Quick-add templates for plugin pages
const PLUGIN_TEMPLATES = [
  { id: 'tutorials', label: 'Tutorials', url: '/tutorials', icon: '📚', plugin: 'tutorials' },
  { id: 'courses', label: 'Courses', url: '/courses', icon: '🎓', plugin: 'courses' },
  { id: 'games', label: 'Practice', url: '/typing-practice', icon: '⌨️', plugin: 'typing_game', altLabels: ['Games', 'Practice', 'Typing Practice'] },
  { id: 'quizzes', label: 'Quizzes', url: '/quizzes', icon: '❓', plugin: 'quizzes' },
];

export const NavigationManager: React.FC = () => {
  const navigate = useNavigate();
  const { isPluginEnabled } = usePlugins();
  const [items, setItems] = useState<MenuItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingItem, setEditingItem] = useState<MenuItem | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showQuickAdd, setShowQuickAdd] = useState(false);
  const [quickAddLabel, setQuickAddLabel] = useState('');
  const [selectedTemplate, setSelectedTemplate] = useState<typeof PLUGIN_TEMPLATES[0] | null>(null);
  const [formData, setFormData] = useState<MenuItemCreate>({
    label: '',
    url: '',
    order: 0,
    visible: true,
    show_in_header: true,
    show_in_footer: false,
    target_blank: false,
  });

  useEffect(() => {
    loadItems();
  }, []);

  const loadItems = async () => {
    try {
      setLoading(true);
      const data = await adminNavigationApi.getAll();
      setItems(data);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load navigation items');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminNavigationApi.create(formData);
      setShowCreateModal(false);
      resetForm();
      loadItems();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create menu item');
    }
  };

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingItem) return;

    try {
      await adminNavigationApi.update(editingItem.id, formData as MenuItemUpdate);
      setEditingItem(null);
      resetForm();
      loadItems();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update menu item');
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this menu item?')) return;

    try {
      await adminNavigationApi.delete(id);
      loadItems();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete menu item');
    }
  };

  const handleMoveUp = (index: number) => {
    if (index === 0) return;
    const newItems = [...items];
    [newItems[index], newItems[index - 1]] = [newItems[index - 1], newItems[index]];
    updateOrder(newItems);
  };

  const handleMoveDown = (index: number) => {
    if (index === items.length - 1) return;
    const newItems = [...items];
    [newItems[index], newItems[index + 1]] = [newItems[index + 1], newItems[index]];
    updateOrder(newItems);
  };

  const updateOrder = async (newItems: MenuItem[]) => {
    const orderData = newItems.map((item, idx) => ({ id: item.id, order: idx }));
    try {
      await adminNavigationApi.reorder(orderData);
      setItems(newItems);
    } catch (err: any) {
      alert('Failed to reorder items');
    }
  };

  const startEdit = (item: MenuItem) => {
    setEditingItem(item);
    setFormData({
      label: item.label,
      url: item.url,
      order: item.order,
      parent_id: item.parent_id,
      visible: item.visible,
      show_in_header: item.show_in_header,
      show_in_footer: item.show_in_footer,
      target_blank: item.target_blank,
    });
  };

  const resetForm = () => {
    setFormData({
      label: '',
      url: '',
      order: 0,
      visible: true,
      show_in_header: true,
      show_in_footer: false,
      target_blank: false,
    });
  };

  // Quick add a plugin page to navigation
  const handleQuickAdd = async (template: typeof PLUGIN_TEMPLATES[0], customLabel?: string) => {
    const label = customLabel || template.label;

    // Check if this URL already exists
    const existingItem = items.find(item => item.url === template.url);
    if (existingItem) {
      alert(`A menu item for "${template.url}" already exists.`);
      return;
    }

    try {
      await adminNavigationApi.create({
        label,
        url: template.url,
        order: items.length,
        visible: true,
        show_in_header: true,
        show_in_footer: false,
        target_blank: false,
      });
      loadItems();
      setShowQuickAdd(false);
      setSelectedTemplate(null);
      setQuickAddLabel('');
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to add menu item');
    }
  };

  // Get available templates (plugins that are enabled but not yet in nav)
  const getAvailableTemplates = () => {
    return PLUGIN_TEMPLATES.filter(template => {
      const isEnabled = isPluginEnabled(template.plugin);
      const alreadyInNav = items.some(item => item.url === template.url);
      return isEnabled && !alreadyInNav;
    });
  };

  if (loading) {
    return (
      <div className="p-8">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading navigation...</p>
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
              Navigation Manager
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Manage header and footer menu items
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
              onClick={() => setShowCreateModal(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition font-medium"
            >
              + Add Menu Item
            </button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
            <p className="text-red-600 dark:text-red-400">{error}</p>
          </div>
        )}

        {/* Quick Add Plugin Pages */}
        {getAvailableTemplates().length > 0 && (
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-6">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-blue-900 dark:text-blue-100">
                  Quick Add Plugin Pages
                </h3>
                <p className="text-xs text-blue-700 dark:text-blue-300">
                  Add enabled plugins to your navigation with one click
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {getAvailableTemplates().map(template => (
                <div key={template.id} className="relative">
                  {selectedTemplate?.id === template.id ? (
                    <div className="flex items-center gap-2 bg-white dark:bg-gray-800 rounded-lg p-2 shadow-sm">
                      <input
                        type="text"
                        value={quickAddLabel}
                        onChange={(e) => setQuickAddLabel(e.target.value)}
                        placeholder={template.label}
                        className="w-32 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />
                      <button
                        onClick={() => handleQuickAdd(template, quickAddLabel || template.label)}
                        className="px-2 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700"
                      >
                        Add
                      </button>
                      <button
                        onClick={() => {
                          setSelectedTemplate(null);
                          setQuickAddLabel('');
                        }}
                        className="px-2 py-1 text-xs text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                      >
                        ✕
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => {
                        setSelectedTemplate(template);
                        setQuickAddLabel(template.label);
                      }}
                      className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-gray-800 rounded-lg shadow-sm hover:shadow-md transition text-sm font-medium text-gray-700 dark:text-gray-200"
                    >
                      <span>{template.icon}</span>
                      <span>{template.label}</span>
                      <span className="text-blue-600 dark:text-blue-400">+</span>
                    </button>
                  )}
                </div>
              ))}
            </div>
            <p className="mt-2 text-xs text-blue-600 dark:text-blue-400">
              Tip: Click a button to customize the label (e.g., "Games" → "Practice")
            </p>
          </div>
        )}

        {/* Menu Items List */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Order
                </th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Label
                </th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
                  URL
                </th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Location
                </th>
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Visible
                </th>
                <th className="text-right px-6 py-4 text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                    No menu items yet. Click "Add Menu Item" to create one.
                  </td>
                </tr>
              ) : (
                items.map((item, index) => (
                  <tr
                    key={item.id}
                    className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition"
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-gray-600 dark:text-gray-400">
                          {item.order}
                        </span>
                        <div className="flex flex-col">
                          <button
                            onClick={() => handleMoveUp(index)}
                            disabled={index === 0}
                            className="text-gray-400 hover:text-blue-600 disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            ▲
                          </button>
                          <button
                            onClick={() => handleMoveDown(index)}
                            disabled={index === items.length - 1}
                            className="text-gray-400 hover:text-blue-600 disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            ▼
                          </button>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        {item.parent_id && (
                          <span className="text-gray-400">↳</span>
                        )}
                        <span className="text-sm font-medium text-gray-900 dark:text-white">
                          {item.label}
                        </span>
                        {item.parent_id && (
                          <span className="px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 text-xs rounded">
                            Submenu
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        {item.url}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        {item.show_in_header && (
                          <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs rounded">
                            Header
                          </span>
                        )}
                        {item.show_in_footer && (
                          <span className="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-xs rounded">
                            Footer
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`px-2 py-1 text-xs rounded ${
                          item.visible
                            ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                            : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                        }`}
                      >
                        {item.visible ? 'Visible' : 'Hidden'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => startEdit(item)}
                          className="px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded transition"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(item.id)}
                          className="px-3 py-1 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Create/Edit Modal */}
        {(showCreateModal || editingItem) && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {editingItem ? 'Edit Menu Item' : 'Create Menu Item'}
                </h2>
              </div>

              <form onSubmit={editingItem ? handleUpdate : handleCreate} className="p-6 space-y-4">
                {/* Label */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Label *
                  </label>
                  <input
                    type="text"
                    value={formData.label}
                    onChange={(e) => setFormData({ ...formData, label: e.target.value })}
                    required
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Home"
                  />
                </div>

                {/* URL */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    URL *
                  </label>
                  <input
                    type="text"
                    value={formData.url}
                    onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                    required
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="/"
                  />
                </div>

                {/* Parent Menu */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Parent Menu (for dropdown/submenu)
                  </label>
                  <select
                    value={formData.parent_id || ''}
                    onChange={(e) => setFormData({ ...formData, parent_id: e.target.value ? parseInt(e.target.value) : null })}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="">No parent (top-level menu item)</option>
                    {items
                      .filter(item => !item.parent_id && (!editingItem || item.id !== editingItem.id))
                      .map(item => (
                        <option key={item.id} value={item.id}>
                          {item.label}
                        </option>
                      ))
                    }
                  </select>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Select a parent to make this a dropdown submenu item
                  </p>
                </div>

                {/* Checkboxes */}
                <div className="grid grid-cols-2 gap-4">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.visible}
                      onChange={(e) => setFormData({ ...formData, visible: e.target.checked })}
                      className="w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Visible</span>
                  </label>

                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.show_in_header}
                      onChange={(e) => setFormData({ ...formData, show_in_header: e.target.checked })}
                      className="w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Show in Header</span>
                  </label>

                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.show_in_footer}
                      onChange={(e) => setFormData({ ...formData, show_in_footer: e.target.checked })}
                      className="w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Show in Footer</span>
                  </label>

                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.target_blank}
                      onChange={(e) => setFormData({ ...formData, target_blank: e.target.checked })}
                      className="w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Open in New Tab</span>
                  </label>
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <button
                    type="button"
                    onClick={() => {
                      setShowCreateModal(false);
                      setEditingItem(null);
                      resetForm();
                    }}
                    className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition font-medium"
                  >
                    {editingItem ? 'Update' : 'Create'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NavigationManager;
