// src/pages/admin/PlaceholderPage.tsx
/**
 * Generic placeholder page for admin routes under development
 */

import { Construction, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';

interface PlaceholderPageProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  backLink?: string;
  backLabel?: string;
}

export const PlaceholderPage: React.FC<PlaceholderPageProps> = ({
  title,
  description = 'This feature is coming soon.',
  icon: Icon = Construction,
  backLink = '/admin',
  backLabel = 'Back to Dashboard',
}) => {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div className="text-center max-w-md">
        <div className="w-16 h-16 mx-auto mb-6 bg-primary/10 rounded-full flex items-center justify-center">
          <Icon className="w-8 h-8 text-primary" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
          {title}
        </h1>
        <p className="text-gray-500 dark:text-gray-400 mb-6">
          {description}
        </p>
        <Link
          to={backLink}
          className="inline-flex items-center gap-2 text-primary hover:underline"
        >
          <ArrowLeft className="w-4 h-4" />
          {backLabel}
        </Link>
      </div>
    </div>
  );
};

export default PlaceholderPage;
