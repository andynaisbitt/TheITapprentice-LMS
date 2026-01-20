// src/pages/admin/PluginManager.tsx
/**
 * Plugin Manager
 * Enable/disable plugins and view plugin status via API
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Puzzle,
  ToggleLeft,
  ToggleRight,
  Settings,
  AlertCircle,
  CheckCircle,
  Loader2,
  ExternalLink,
  RefreshCw,
} from 'lucide-react';
import { api } from '../../api/client';

interface PluginStats {
  [key: string]: number | string;
}

interface Plugin {
  id: string;
  name: string;
  description: string;
  version: string;
  enabled: boolean;
  status: 'active' | 'inactive' | 'error';
  has_admin_ui: boolean;
  admin_route?: string;
  public_routes: string[];
  stats?: PluginStats;
}

interface PluginListResponse {
  plugins: Plugin[];
  total_enabled: number;
  total_available: number;
}

export const PluginManager: React.FC = () => {
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [totalEnabled, setTotalEnabled] = useState(0);
  const [totalAvailable, setTotalAvailable] = useState(0);

  useEffect(() => {
    loadPlugins();
  }, []);

  const loadPlugins = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.get<PluginListResponse>('/api/v1/admin/plugins');
      setPlugins(response.data.plugins);
      setTotalEnabled(response.data.total_enabled);
      setTotalAvailable(response.data.total_available);
    } catch (err: any) {
      console.error('Failed to load plugins:', err);
      setError(err.response?.data?.detail || 'Failed to load plugins');
    } finally {
      setLoading(false);
    }
  };

  const togglePlugin = async (pluginId: string, currentEnabled: boolean) => {
    setSaving(pluginId);
    try {
      const response = await api.put(`/api/v1/admin/plugins/${pluginId}/toggle`, {
        enabled: !currentEnabled,
      });

      if (response.data.success) {
        // Update local state
        setPlugins(plugins.map(p =>
          p.id === pluginId
            ? { ...p, enabled: !currentEnabled, status: !currentEnabled ? 'active' : 'inactive' }
            : p
        ));
        setTotalEnabled(prev => !currentEnabled ? prev + 1 : prev - 1);
      }
    } catch (err: any) {
      console.error('Failed to toggle plugin:', err);
      alert(err.response?.data?.detail || 'Failed to toggle plugin');
    } finally {
      setSaving(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-red-600" />
            <p className="text-red-800 dark:text-red-200">{error}</p>
          </div>
          <button
            onClick={loadPlugins}
            className="mt-3 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Plugin Manager
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Enable or disable plugins to customize your platform
          </p>
        </div>
        <button
          onClick={loadPlugins}
          className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>

      {/* Summary */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 flex items-center gap-4">
        <div className="p-3 bg-primary/10 rounded-lg">
          <Puzzle className="w-6 h-6 text-primary" />
        </div>
        <div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {totalEnabled} / {totalAvailable}
          </p>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Plugins Active
          </p>
        </div>
      </div>

      {/* Plugin List */}
      <div className="space-y-4">
        {plugins.map((plugin) => (
          <div
            key={plugin.id}
            className={`
              bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6
              border-l-4 transition-all duration-200
              ${plugin.enabled
                ? 'border-green-500'
                : 'border-gray-300 dark:border-gray-600'
              }
            `}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-3 flex-wrap">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {plugin.name}
                  </h3>
                  <span className="px-2 py-0.5 text-xs font-medium rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                    v{plugin.version}
                  </span>
                  {plugin.status === 'active' && (
                    <span className="flex items-center gap-1 text-xs text-green-600 dark:text-green-400">
                      <CheckCircle className="w-3 h-3" />
                      Active
                    </span>
                  )}
                  {plugin.status === 'error' && (
                    <span className="flex items-center gap-1 text-xs text-red-600 dark:text-red-400">
                      <AlertCircle className="w-3 h-3" />
                      Error
                    </span>
                  )}
                </div>
                <p className="text-gray-500 dark:text-gray-400 mt-1">
                  {plugin.description}
                </p>

                {/* Plugin Stats (when enabled) */}
                {plugin.enabled && plugin.stats && Object.keys(plugin.stats).length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-4">
                    {Object.entries(plugin.stats).map(([key, value]) => (
                      <div key={key} className="text-sm">
                        <span className="text-gray-500 dark:text-gray-400 capitalize">
                          {key.replace(/_/g, ' ')}:
                        </span>{' '}
                        <span className="font-medium text-gray-900 dark:text-white">
                          {value}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Routes info (when enabled) */}
                {plugin.enabled && plugin.public_routes.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {plugin.public_routes.map((route) => (
                      <Link
                        key={route}
                        to={route}
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
                      >
                        {route}
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-3">
                {/* Admin Settings Link */}
                {plugin.enabled && plugin.has_admin_ui && plugin.admin_route && (
                  <Link
                    to={plugin.admin_route}
                    className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                    title="Plugin settings"
                  >
                    <Settings className="w-5 h-5" />
                  </Link>
                )}

                {/* Toggle */}
                <button
                  onClick={() => togglePlugin(plugin.id, plugin.enabled)}
                  disabled={saving === plugin.id}
                  className="relative"
                >
                  {saving === plugin.id ? (
                    <Loader2 className="w-8 h-8 animate-spin text-primary" />
                  ) : plugin.enabled ? (
                    <ToggleRight className="w-10 h-10 text-green-500 hover:text-green-600 transition-colors" />
                  ) : (
                    <ToggleLeft className="w-10 h-10 text-gray-400 hover:text-gray-500 transition-colors" />
                  )}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Note */}
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-yellow-800 dark:text-yellow-200 font-medium">
              Note: Plugin changes require a server restart
            </p>
            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
              After toggling plugins, restart the backend server for route changes to take effect.
              The plugin enabled state is saved to the database immediately.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PluginManager;
