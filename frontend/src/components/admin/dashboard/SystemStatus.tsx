// src/components/admin/dashboard/SystemStatus.tsx
/**
 * System health status indicators
 */

import {
  Server,
  Database,
  Puzzle,
  Wifi,
  CheckCircle,
  AlertCircle,
  XCircle,
  Loader2,
} from 'lucide-react';

export type StatusType = 'healthy' | 'warning' | 'error' | 'loading';

export interface SystemStatusItem {
  id: string;
  name: string;
  status: StatusType;
  message?: string;
}

interface SystemStatusProps {
  items: SystemStatusItem[];
  loading?: boolean;
}

const statusConfig = {
  healthy: {
    icon: CheckCircle,
    color: 'text-green-500',
    bgColor: 'bg-green-500',
    label: 'Healthy',
  },
  warning: {
    icon: AlertCircle,
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-500',
    label: 'Warning',
  },
  error: {
    icon: XCircle,
    color: 'text-red-500',
    bgColor: 'bg-red-500',
    label: 'Error',
  },
  loading: {
    icon: Loader2,
    color: 'text-gray-400',
    bgColor: 'bg-gray-400',
    label: 'Checking...',
  },
};

const defaultIcons: Record<string, typeof Server> = {
  api: Server,
  database: Database,
  plugins: Puzzle,
  network: Wifi,
};

export const SystemStatus: React.FC<SystemStatusProps> = ({
  items,
  loading = false,
}) => {
  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="flex items-center gap-3 animate-pulse">
            <div className="w-2 h-2 bg-gray-300 dark:bg-gray-600 rounded-full" />
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-20" />
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-16 ml-auto" />
          </div>
        ))}
      </div>
    );
  }

  // Calculate overall status
  const hasError = items.some((item) => item.status === 'error');
  const hasWarning = items.some((item) => item.status === 'warning');
  const overallStatus = hasError ? 'error' : hasWarning ? 'warning' : 'healthy';
  const overallConfig = statusConfig[overallStatus];

  return (
    <div className="space-y-4">
      {/* Overall Status */}
      <div className="flex items-center gap-2 pb-3 border-b border-gray-200 dark:border-gray-700">
        <div className={`w-3 h-3 rounded-full ${overallConfig.bgColor} animate-pulse`} />
        <span className="text-sm font-semibold text-gray-900 dark:text-white">
          System {overallConfig.label}
        </span>
      </div>

      {/* Individual Status Items */}
      <div className="space-y-2">
        {items.map((item) => {
          const config = statusConfig[item.status];
          const StatusIcon = config.icon;
          const ItemIcon = defaultIcons[item.id.toLowerCase()] || Server;

          return (
            <div
              key={item.id}
              className="flex items-center gap-3 py-2"
            >
              {/* Status indicator */}
              <div className={`w-2 h-2 rounded-full ${config.bgColor}`} />

              {/* Icon and name */}
              <div className="flex items-center gap-2 flex-1">
                <ItemIcon className="w-4 h-4 text-gray-400" />
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  {item.name}
                </span>
              </div>

              {/* Status */}
              <div className="flex items-center gap-1">
                <StatusIcon
                  className={`w-4 h-4 ${config.color} ${
                    item.status === 'loading' ? 'animate-spin' : ''
                  }`}
                />
                <span className={`text-xs font-medium ${config.color}`}>
                  {item.message || config.label}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SystemStatus;
