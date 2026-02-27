// src/components/layout/Layout.tsx
/**
 * Main Layout Wrapper
 * Wraps all pages with Header, Footer, and Public Sidebar
 */

import { useEffect } from 'react';
import { Header } from './Header';
import { Footer } from './Footer';
import { PublicSidebar } from './PublicSidebar';
import { NewsletterModal } from '../NewsletterModal';
import { useNewsletterModal } from '../../hooks/useNewsletterModal';
import { useSiteSettings } from '../../store/useSiteSettingsStore';
import { usePublicSidebar } from '../../hooks/usePublicSidebar';

interface LayoutProps {
  children: React.ReactNode;
  /**
   * Hide header (for auth pages)
   */
  hideHeader?: boolean;
  /**
   * Hide footer (for admin pages)
   */
  hideFooter?: boolean;
  /**
   * Full width content (no max-width container)
   */
  fullWidth?: boolean;
}

export const Layout: React.FC<LayoutProps> = ({
  children,
  hideHeader = false,
  hideFooter = false,
  fullWidth = false,
}) => {
  const { isOpen: isNewsletterOpen, closeModal } = useNewsletterModal();
  const { settings } = useSiteSettings();
  const {
    isOpen: isSidebarOpen,
    toggleSidebar,
    closeSidebar,
    toggleSection,
    isSectionExpanded,
    expandedSections,
  } = usePublicSidebar();

  // Initialize dark mode from localStorage on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else if (savedTheme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      // Default to light mode or system preference
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (prefersDark) {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      }
    }
  }, []);

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 dark:bg-slate-900">
      {!hideHeader && <Header onToggleDesktopSidebar={toggleSidebar} />}

      {/* Desktop Sidebar Drawer - only shown on md+ screens */}
      <PublicSidebar
        isOpen={isSidebarOpen}
        onClose={closeSidebar}
        expandedSections={expandedSections}
        onToggleSection={toggleSection}
        isSectionExpanded={isSectionExpanded}
      />

      <main className={`flex-1 ${fullWidth ? '' : 'max-w-7xl mx-auto w-full'}`}>
        {children}
      </main>

      {!hideFooter && <Footer />}

      {/* Newsletter Modal - Only render if newsletter is enabled */}
      {settings.newsletterEnabled && (
        <NewsletterModal isOpen={isNewsletterOpen} onClose={closeModal} />
      )}
    </div>
  );
};

export default Layout;
