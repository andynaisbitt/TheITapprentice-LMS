// src/components/layout/Footer.tsx
/**
 * Main Footer Component
 * Includes links, social media, newsletter signup, and copyright
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { blogApi } from '../../services/api';
import { navigationApi, MenuItem } from '../../services/api/navigation.api';
import { useSiteSettings } from '../../hooks/useSiteSettings';
import { openNewsletterModal } from '../../hooks/useNewsletterModal';
import { Mail } from 'lucide-react';

interface Category {
  id: number;
  name: string;
  slug: string;
  post_count?: number;
  color?: string;
  icon?: string;
}

export const Footer: React.FC = () => {
  const { settings } = useSiteSettings();
  const [email, setEmail] = useState('');
  const [subscribed, setSubscribed] = useState(false);
  const [categories, setCategories] = useState<Category[]>([]);
  const [footerItems, setFooterItems] = useState<MenuItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadData = async () => {
      try {
        // Load categories (show all, including empty ones)
        const categoriesData = await blogApi.getCategories();
        const topCategories = categoriesData
          .sort((a, b) => (b.post_count || 0) - (a.post_count || 0))
          .slice(0, 5);
        setCategories(topCategories);

        // Load footer navigation
        const navigationData = await navigationApi.getNavigation();
        setFooterItems(navigationData.footer_items);
      } catch (err) {
        console.error('Failed to load footer data:', err);
        // Fallback to default footer links
        setFooterItems([
          { id: 3, label: 'About', url: '/about', order: 3, parent_id: null, visible: true, show_in_header: true, show_in_footer: true, target_blank: false, created_at: '', updated_at: null },
          { id: 4, label: 'Contact', url: '/contact', order: 4, parent_id: null, visible: true, show_in_header: true, show_in_footer: true, target_blank: false, created_at: '', updated_at: null },
          { id: 5, label: 'Privacy Policy', url: '/privacy', order: 5, parent_id: null, visible: true, show_in_header: false, show_in_footer: true, target_blank: false, created_at: '', updated_at: null },
          { id: 6, label: 'Terms of Service', url: '/terms', order: 6, parent_id: null, visible: true, show_in_header: false, show_in_footer: true, target_blank: false, created_at: '', updated_at: null },
        ]);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const handleNewsletterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) return;

    try {
      const response = await fetch('/api/v1/newsletter/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        setSubscribed(true);
        setEmail('');
        setTimeout(() => setSubscribed(false), 5000);
      } else {
        console.error('Newsletter subscription failed:', data.detail);
        alert(data.detail || 'Subscription failed. Please try again.');
      }
    } catch (error) {
      console.error('Newsletter subscription error:', error);
      alert('Failed to subscribe. Please try again later.');
    }
  };

  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-gray-900 dark:bg-black text-gray-300">
      {/* Main Footer Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className={`grid grid-cols-1 gap-8 ${
          settings.newsletterEnabled
            ? 'md:grid-cols-2 lg:grid-cols-4'
            : 'md:grid-cols-3 lg:grid-cols-3 max-w-5xl mx-auto'
        }`}>
          {/* About Section */}
          <div>
            <div className="flex items-center space-x-3 mb-4">
              {settings.logoUrl ? (
                <img
                  src={settings.logoUrl}
                  alt={settings.siteTitle}
                  className="h-10 w-auto"
                />
              ) : (
                <>
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
                    <span className="text-white font-bold text-xl">
                      {settings.siteTitle.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <span className="text-xl font-bold text-white">{settings.siteTitle}</span>
                </>
              )}
            </div>
            <p className="text-sm text-gray-400 leading-relaxed">
              {settings.metaDescription}
            </p>
            <div className="mt-6 flex space-x-4">
              {/* Social Media Icons - Only show if URL is configured */}
              {settings.twitterHandle && (
                <a
                  href={`https://twitter.com/${settings.twitterHandle.replace('@', '')}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-blue-400 transition"
                  aria-label="Twitter"
                >
                  <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M8.29 20.251c7.547 0 11.675-6.253 11.675-11.675 0-.178 0-.355-.012-.53A8.348 8.348 0 0022 5.92a8.19 8.19 0 01-2.357.646 4.118 4.118 0 001.804-2.27 8.224 8.224 0 01-2.605.996 4.107 4.107 0 00-6.993 3.743 11.65 11.65 0 01-8.457-4.287 4.106 4.106 0 001.27 5.477A4.072 4.072 0 012.8 9.713v.052a4.105 4.105 0 003.292 4.022 4.095 4.095 0 01-1.853.07 4.108 4.108 0 003.834 2.85A8.233 8.233 0 012 18.407a11.616 11.616 0 006.29 1.84" />
                  </svg>
                </a>
              )}
              {settings.githubUrl && (
                <a
                  href={settings.githubUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-white transition"
                  aria-label="GitHub"
                >
                  <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                    <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                  </svg>
                </a>
              )}
              {settings.linkedinUrl && (
                <a
                  href={settings.linkedinUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-blue-500 transition"
                  aria-label="LinkedIn"
                >
                  <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
                  </svg>
                </a>
              )}
              {settings.facebookUrl && (
                <a
                  href={settings.facebookUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 hover:text-blue-600 transition"
                  aria-label="Facebook"
                >
                  <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" />
                  </svg>
                </a>
              )}
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-white font-semibold text-lg mb-4">Quick Links</h3>
            {loading ? (
              <div className="text-sm text-gray-400">Loading...</div>
            ) : (
              <ul className="space-y-2">
                {footerItems.map((item) => (
                  <li key={item.id}>
                    {item.target_blank ? (
                      <a
                        href={item.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-gray-400 hover:text-white transition text-sm"
                      >
                        {item.label}
                      </a>
                    ) : (
                      <Link
                        to={item.url}
                        className="text-gray-400 hover:text-white transition text-sm"
                      >
                        {item.label}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Categories */}
          <div>
            <h3 className="text-white font-semibold text-lg mb-4">Categories</h3>
            {loading ? (
              <div className="text-sm text-gray-400">Loading...</div>
            ) : categories.length > 0 ? (
              <ul className="space-y-2">
                {categories.map((category) => (
                  <li key={category.id}>
                    <Link
                      to={`/blog?category=${category.slug}`}
                      className="text-gray-400 hover:text-white transition text-sm flex items-center gap-2"
                    >
                      {category.icon && <span>{category.icon}</span>}
                      <span>{category.name}</span>
                      {category.post_count && category.post_count > 0 && (
                        <span className="text-xs text-gray-500">
                          ({category.post_count})
                        </span>
                      )}
                    </Link>
                  </li>
                ))}
                <li>
                  <Link
                    to="/blog"
                    className="text-blue-400 hover:text-blue-300 transition text-sm font-medium"
                  >
                    View All Categories →
                  </Link>
                </li>
              </ul>
            ) : (
              <p className="text-sm text-gray-500">No categories yet</p>
            )}
          </div>

          {/* Newsletter - Only show if enabled */}
          {settings.newsletterEnabled && (
            <div>
              <h3 className="text-white font-semibold text-lg mb-4">Newsletter</h3>
              <p className="text-sm text-gray-400 mb-4">
                Subscribe to get the latest posts delivered directly to your inbox.
              </p>
              <form onSubmit={handleNewsletterSubmit} className="space-y-2">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Your email address"
                  required
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition text-sm"
                />
                <button
                  type="submit"
                  className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition font-medium text-sm"
                >
                  Subscribe
                </button>
                {subscribed && (
                  <p className="text-sm text-green-400">
                    ✓ Thank you for subscribing!
                  </p>
                )}
              </form>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Bar */}
      <div className="border-t border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
            <div className="flex flex-col items-center md:items-start space-y-1">
              <p className="text-sm text-gray-400">
                © {currentYear} {settings.siteTitle}. All rights reserved.
              </p>
              {settings.showPoweredBy && (
                <p className="text-xs text-gray-500">
                  Powered by{' '}
                  <a
                    href="https://github.com/andynaisbitt/fastreactcms"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-blue-400 transition"
                  >
                    FastReactCMS
                  </a>
                </p>
              )}
            </div>
            <div className="flex items-center space-x-6 text-sm text-gray-400">
              {/* Newsletter Modal Button - Show if newsletter enabled but hidden from footer */}
              {settings.newsletterEnabled && (
                <button
                  onClick={openNewsletterModal}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition font-medium text-sm"
                >
                  <Mail size={16} />
                  Subscribe
                </button>
              )}
              <Link to="/privacy" className="hover:text-white transition">
                Privacy
              </Link>
              <Link to="/terms" className="hover:text-white transition">
                Terms
              </Link>
              <a href="/sitemap.xml" target="_blank" rel="noopener noreferrer" className="hover:text-white transition">
                Sitemap
              </a>
              <a href="/rss.xml" target="_blank" rel="noopener noreferrer" className="hover:text-white transition">
                RSS Feed
              </a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
