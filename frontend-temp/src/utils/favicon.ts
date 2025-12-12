/**
 * Favicon utility for dynamic favicon updates with theme support
 * Handles light/dark mode favicon switching
 */

interface FaviconConfig {
  light: string | null;
  dark: string | null;
}

/**
 * Update the page favicon dynamically based on theme
 * @param faviconUrl - URL to the favicon (absolute or relative)
 * @param isDarkMode - Whether dark mode is active
 */
export function updateFavicon(faviconUrl: string, isDarkMode?: boolean) {
  if (!faviconUrl) return;

  // Remove existing favicon links
  const existingLinks = document.querySelectorAll("link[rel*='icon']");
  existingLinks.forEach(link => link.remove());

  // Detect file type
  const ext = faviconUrl.split('.').pop()?.toLowerCase();
  let type = 'image/x-icon'; // default
  if (ext === 'svg') type = 'image/svg+xml';
  else if (ext === 'png') type = 'image/png';
  else if (ext === 'webp') type = 'image/webp';

  // Create and add new favicon link
  const link = document.createElement('link');
  link.rel = 'icon';
  link.type = type;
  link.href = faviconUrl;
  document.head.appendChild(link);

  console.log(`✓ Favicon updated: ${faviconUrl} (${isDarkMode ? 'dark' : 'light'} mode)`);
}

/**
 * Update favicon with theme awareness
 * @param config - Object with light and dark favicon URLs
 * @param isDarkMode - Whether dark mode is currently active
 */
export function updateFaviconWithTheme(config: FaviconConfig, isDarkMode: boolean) {
  // Determine which favicon to use
  let faviconUrl: string;

  if (isDarkMode && config.dark) {
    // Dark mode with dark favicon available
    faviconUrl = config.dark;
  } else if (!isDarkMode && config.light) {
    // Light mode with light favicon available
    faviconUrl = config.light;
  } else if (config.light) {
    // Fallback to light favicon if dark not available
    faviconUrl = config.light;
  } else if (config.dark) {
    // Fallback to dark favicon if light not available
    faviconUrl = config.dark;
  } else {
    // No custom favicon, use default
    faviconUrl = isDarkMode ? '/apprentice-dark.svg' : '/apprentice.svg';
  }

  updateFavicon(faviconUrl, isDarkMode);
}

/**
 * Detect if dark mode is currently active
 * Checks both localStorage (user preference) and system preference
 */
export function isDarkMode(): boolean {
  // Check localStorage first (user's explicit choice)
  const stored = localStorage.getItem('theme');
  if (stored === 'dark') return true;
  if (stored === 'light') return false;

  // Fallback to system preference
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

/**
 * Setup theme change listener for favicon updates
 * @param config - Object with light and dark favicon URLs
 * @returns Cleanup function to remove listeners
 */
export function setupFaviconThemeListener(config: FaviconConfig): () => void {
  // Update favicon immediately
  updateFaviconWithTheme(config, isDarkMode());

  // Listen for theme changes in localStorage
  const handleStorageChange = (e: StorageEvent) => {
    if (e.key === 'theme') {
      updateFaviconWithTheme(config, isDarkMode());
    }
  };

  // Listen for system theme changes
  const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
  const handleSystemThemeChange = () => {
    // Only update if user hasn't set explicit preference
    if (!localStorage.getItem('theme')) {
      updateFaviconWithTheme(config, isDarkMode());
    }
  };

  window.addEventListener('storage', handleStorageChange);
  darkModeQuery.addEventListener('change', handleSystemThemeChange);

  // Also listen for custom theme toggle events (if your app dispatches them)
  const handleThemeToggle = () => {
    updateFaviconWithTheme(config, isDarkMode());
  };
  window.addEventListener('themeChanged', handleThemeToggle);

  // Return cleanup function
  return () => {
    window.removeEventListener('storage', handleStorageChange);
    darkModeQuery.removeEventListener('change', handleSystemThemeChange);
    window.removeEventListener('themeChanged', handleThemeToggle);
  };
}
