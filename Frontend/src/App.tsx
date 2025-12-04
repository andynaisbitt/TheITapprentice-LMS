import { BrowserRouter } from 'react-router-dom';
import { HelmetProvider } from 'react-helmet-async';
import { useEffect } from 'react';
import { AuthProvider } from './state/contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { AppRoutes } from './routes/routes';
import { GoogleAnalytics, initGA } from './components/analytics/GoogleAnalytics';
import { initAdSense } from './components/ads/GoogleAdSense';
import './index.css';

function App() {
  useEffect(() => {
    // Initialize Google Analytics
    initGA();

    // Initialize Google AdSense
    initAdSense();
  }, []);

  return (
    <HelmetProvider>
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <GoogleAnalytics />
            <AppRoutes />
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    </HelmetProvider>
  );
}

export default App;
