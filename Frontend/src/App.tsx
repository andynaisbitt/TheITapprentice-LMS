import { BrowserRouter } from 'react-router-dom';
import { HelmetProvider } from 'react-helmet-async';
import { AuthProvider } from './state/contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { AppRoutes } from './routes/routes';
import { GoogleAnalytics } from './components/analytics/GoogleAnalytics';
import { GoogleAdSense } from './components/analytics/GoogleAdSense';
import { CookieConsent } from './components/CookieConsent';
import { DynamicTitle } from './components/DynamicTitle';
import { FaviconManager } from './components/FaviconManager';
import { StoreInitializer } from './store/StoreInitializer';
import { initializeConsentMode, initializeFromStorage } from './utils/googleConsentMode';
import './index.css';

// CRITICAL: Initialize Google Consent Mode v2 BEFORE app renders
// This must run before any Google scripts (Analytics, AdSense) load
initializeConsentMode();
initializeFromStorage();

function App() {
  return (
    <HelmetProvider>
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <StoreInitializer />
            <DynamicTitle />
            <FaviconManager />
            <GoogleAnalytics />
            <GoogleAdSense />
            <CookieConsent />
            <AppRoutes />
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    </HelmetProvider>
  );
}

export default App;
