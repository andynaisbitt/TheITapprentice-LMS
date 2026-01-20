// src/pages/admin/SystemHealthPage.tsx
/**
 * System Health Dashboard
 * Shows API, database, and plugin status
 */

import { useState, useEffect } from 'react';
import {
  Server,
  Database,
  Puzzle,
  Wifi,
  CheckCircle,
  AlertCircle,
  XCircle,
  RefreshCw,
  Clock,
  Loader2,
} from 'lucide-react';

interface HealthCheck {
  id: string;
  name: string;
  status: 'healthy' | 'warning' | 'error' | 'checking';
  message: string;
  responseTime?: number;
  lastChecked?: string;
}

export const SystemHealthPage: React.FC = () => {
  const [checks, setChecks] = useState<HealthCheck[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    runHealthChecks();
  }, []);

  const runHealthChecks = async () => {
    setRefreshing(true);

    // Simulate health checks
    const mockChecks: HealthCheck[] = [
      {
        id: 'api',
        name: 'API Server',
        status: 'healthy',
        message: 'All endpoints responding',
        responseTime: 45,
        lastChecked: new Date().toISOString(),
      },
      {
        id: 'database',
        name: 'Database',
        status: 'healthy',
        message: 'PostgreSQL connected',
        responseTime: 12,
        lastChecked: new Date().toISOString(),
      },
      {
        id: 'plugins',
        name: 'Plugins',
        status: 'healthy',
        message: '3 of 4 plugins active',
        lastChecked: new Date().toISOString(),
      },
      {
        id: 'network',
        name: 'External Services',
        status: 'healthy',
        message: 'OAuth, Email services OK',
        responseTime: 120,
        lastChecked: new Date().toISOString(),
      },
    ];

    // Simulate delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    setChecks(mockChecks);
    setLoading(false);
    setRefreshing(false);
  };

  const getStatusIcon = (status: HealthCheck['status']) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'warning':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'checking':
        return <Loader2 className="w-5 h-5 text-gray-400 animate-spin" />;
    }
  };

  const getServiceIcon = (id: string) => {
    switch (id) {
      case 'api':
        return Server;
      case 'database':
        return Database;
      case 'plugins':
        return Puzzle;
      case 'network':
        return Wifi;
      default:
        return Server;
    }
  };

  const overallStatus = checks.some(c => c.status === 'error')
    ? 'error'
    : checks.some(c => c.status === 'warning')
    ? 'warning'
    : 'healthy';

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            System Health
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Monitor the status of your platform services
          </p>
        </div>
        <button
          onClick={runHealthChecks}
          disabled={refreshing}
          className="inline-flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Overall Status */}
      <div className={`
        rounded-xl p-6 border-2
        ${overallStatus === 'healthy'
          ? 'bg-green-50 dark:bg-green-900/20 border-green-500'
          : overallStatus === 'warning'
          ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-500'
          : 'bg-red-50 dark:bg-red-900/20 border-red-500'
        }
      `}>
        <div className="flex items-center gap-4">
          {getStatusIcon(overallStatus)}
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              {overallStatus === 'healthy'
                ? 'All Systems Operational'
                : overallStatus === 'warning'
                ? 'Minor Issues Detected'
                : 'System Issues Detected'
              }
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Last checked: {new Date().toLocaleTimeString()}
            </p>
          </div>
        </div>
      </div>

      {/* Health Checks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {checks.map((check) => {
          const ServiceIcon = getServiceIcon(check.id);

          return (
            <div
              key={check.id}
              className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg">
                    <ServiceIcon className="w-5 h-5 text-gray-600 dark:text-gray-300" />
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-900 dark:text-white">
                      {check.name}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {check.message}
                    </p>
                  </div>
                </div>
                {getStatusIcon(check.status)}
              </div>

              {check.responseTime && (
                <div className="mt-4 flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                  <Clock className="w-4 h-4" />
                  Response time: {check.responseTime}ms
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SystemHealthPage;
