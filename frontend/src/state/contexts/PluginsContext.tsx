// src/state/contexts/PluginsContext.tsx
/**
 * Plugins Context
 * Provides plugin enabled status throughout the application
 * Used to dynamically show/hide navigation items and features based on enabled plugins
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { apiClient } from '../../services/api/client';

export interface Plugin {
  id: string;
  name: string;
  description: string;
  version: string;
  enabled: boolean;
  status: 'active' | 'inactive' | 'error';
  has_admin_ui: boolean;
  admin_route?: string;
  public_routes: string[];
}

interface PluginsContextType {
  plugins: Plugin[];
  loading: boolean;
  error: string | null;
  isPluginEnabled: (pluginId: string) => boolean;
  refreshPlugins: () => Promise<void>;
}

const PluginsContext = createContext<PluginsContextType | undefined>(undefined);

export const PluginsProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPlugins = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<{ plugins: Plugin[] }>('/api/v1/admin/plugins');
      setPlugins(response.data.plugins);
    } catch (err: any) {
      console.error('Failed to fetch plugins:', err);
      // Don't set error for non-admin users - they just won't have plugin info
      if (err.response?.status !== 401 && err.response?.status !== 403) {
        setError(err.response?.data?.detail || 'Failed to load plugins');
      }
      // Set default empty state
      setPlugins([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPlugins();
  }, [fetchPlugins]);

  const isPluginEnabled = useCallback(
    (pluginId: string): boolean => {
      const plugin = plugins.find((p) => p.id === pluginId);
      return plugin?.enabled ?? false;
    },
    [plugins]
  );

  const refreshPlugins = useCallback(async () => {
    await fetchPlugins();
  }, [fetchPlugins]);

  return (
    <PluginsContext.Provider
      value={{
        plugins,
        loading,
        error,
        isPluginEnabled,
        refreshPlugins,
      }}
    >
      {children}
    </PluginsContext.Provider>
  );
};

export const usePlugins = (): PluginsContextType => {
  const context = useContext(PluginsContext);
  if (context === undefined) {
    throw new Error('usePlugins must be used within a PluginsProvider');
  }
  return context;
};

export default PluginsContext;
