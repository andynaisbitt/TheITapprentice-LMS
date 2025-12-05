import { BrowserRouter } from 'react-router-dom';
import { HelmetProvider } from 'react-helmet-async';
import { useEffect } from 'react';
import { AuthProvider } from './state/contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { AppRoutes } from './routes/routes';
import { GoogleAnalytics, initGA } from './components/analytics/GoogleAnalytics';
import { initAdSense } from './components/ads/GoogleAdSense';
import { CookieConsent } from './components/CookieConsent';
import './index.css';

function App() {
  useEffect(() => {
    // Listen for cookie consent updates
    const handleConsentUpdate = (event: CustomEvent) => {
      const preferences = event.detail;

      // Initialize analytics if consent given
      if (preferences.analytics) {
        initGA();
      }

      // Initialize ads if consent given
      if (preferences.marketing) {
        initAdSense();
      }
    };

    window.addEventListener('cookieConsentUpdated', handleConsentUpdate as EventListener);

    // Check if consent already exists in localStorage
    const stored = localStorage.getItem('cookie_consent');
    if (stored) {
      try {
        const data = JSON.parse(stored);
        if (data.preferences) {
          // Initialize services based on existing consent
          if (data.preferences.analytics) {
            initGA();
          }
          if (data.preferences.marketing) {
            initAdSense();
          }
        }
      } catch (error) {
        console.error('Error loading existing consent:', error);
      }
    }

    return () => {
      window.removeEventListener('cookieConsentUpdated', handleConsentUpdate as EventListener);
    };
  }, []);

  return (
    <HelmetProvider>
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <GoogleAnalytics />
            <CookieConsent />
            <AppRoutes />
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    </HelmetProvider>
  );
}

export default App;
