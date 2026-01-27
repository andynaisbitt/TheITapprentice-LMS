// frontend/src/components/ui/Toast.tsx
/**
 * Toast Notification System
 * Global toast notifications with auto-dismiss and stacking
 */
import React, { createContext, useContext, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react';

// Toast types
export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
}

interface ToastContextValue {
  toasts: Toast[];
  toast: {
    success: (message: string, duration?: number) => void;
    error: (message: string, duration?: number) => void;
    warning: (message: string, duration?: number) => void;
    info: (message: string, duration?: number) => void;
  };
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

const toastConfig: Record<ToastType, { icon: React.ElementType; bgClass: string; iconClass: string }> = {
  success: {
    icon: CheckCircle,
    bgClass: 'bg-green-50 dark:bg-green-900/30 border-green-200 dark:border-green-800',
    iconClass: 'text-green-600 dark:text-green-400',
  },
  error: {
    icon: XCircle,
    bgClass: 'bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800',
    iconClass: 'text-red-600 dark:text-red-400',
  },
  warning: {
    icon: AlertTriangle,
    bgClass: 'bg-yellow-50 dark:bg-yellow-900/30 border-yellow-200 dark:border-yellow-800',
    iconClass: 'text-yellow-600 dark:text-yellow-400',
  },
  info: {
    icon: Info,
    bgClass: 'bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800',
    iconClass: 'text-blue-600 dark:text-blue-400',
  },
};

// Toast Item Component
const ToastItem: React.FC<{ toast: Toast; onRemove: (id: string) => void }> = ({ toast, onRemove }) => {
  const config = toastConfig[toast.type];
  const IconComponent = config.icon;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, x: 100, scale: 0.95 }}
      transition={{ type: 'spring', duration: 0.4 }}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg border shadow-lg ${config.bgClass} min-w-[300px] max-w-md`}
    >
      <IconComponent className={`w-5 h-5 flex-shrink-0 ${config.iconClass}`} />
      <p className="flex-1 text-sm font-medium text-gray-900 dark:text-white">
        {toast.message}
      </p>
      <button
        onClick={() => onRemove(toast.id)}
        className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded transition"
      >
        <X className="w-4 h-4" />
      </button>
    </motion.div>
  );
};

// Toast Container Component
const ToastContainer: React.FC<{ toasts: Toast[]; onRemove: (id: string) => void }> = ({ toasts, onRemove }) => {
  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onRemove={onRemove} />
        ))}
      </AnimatePresence>
    </div>
  );
};

// Toast Provider
export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback((type: ToastType, message: string, duration = 4000) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newToast: Toast = { id, type, message, duration };

    setToasts((prev) => [...prev, newToast]);

    // Auto-dismiss
    if (duration > 0) {
      setTimeout(() => {
        removeToast(id);
      }, duration);
    }
  }, [removeToast]);

  const toast = {
    success: (message: string, duration?: number) => addToast('success', message, duration),
    error: (message: string, duration?: number) => addToast('error', message, duration),
    warning: (message: string, duration?: number) => addToast('warning', message, duration),
    info: (message: string, duration?: number) => addToast('info', message, duration),
  };

  return (
    <ToastContext.Provider value={{ toasts, toast, removeToast }}>
      {children}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  );
};

// Hook to use toast
export const useToast = (): ToastContextValue => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};

export default ToastProvider;
