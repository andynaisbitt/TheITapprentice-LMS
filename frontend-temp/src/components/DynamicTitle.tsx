// src/components/DynamicTitle.tsx
/**
 * Dynamically updates the page title based on site settings
 */
import { Helmet } from 'react-helmet-async';
import { useSiteSettings } from '../hooks/useSiteSettings';

export const DynamicTitle: React.FC = () => {
  const { settings } = useSiteSettings();

  return (
    <Helmet>
      <title>{settings.siteTitle} - {settings.siteTagline || 'Modern Blog Platform'}</title>
      <meta name="description" content={settings.metaDescription} />
      {settings.metaKeywords && <meta name="keywords" content={settings.metaKeywords} />}
    </Helmet>
  );
};
