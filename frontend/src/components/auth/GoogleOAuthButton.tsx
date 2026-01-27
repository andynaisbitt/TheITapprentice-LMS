// src/components/auth/GoogleOAuthButton.tsx
/**
 * Google OAuth Login Button Component
 *
 * SETUP REQUIRED:
 * 1. npm install @react-oauth/google jwt-decode
 * 2. Wrap app in GoogleOAuthProvider in App.tsx
 * 3. Add VITE_GOOGLE_CLIENT_ID to .env
 */

import { useNavigate, useLocation } from 'react-router-dom';
import { oauthApi } from '../../services/api/oauth.api';
import { useState } from 'react';
import { useAuth } from '../../state/contexts/AuthContext';

import { GoogleLogin, CredentialResponse } from '@react-oauth/google';
import { jwtDecode } from 'jwt-decode';

interface GoogleOAuthButtonProps {
  mode: 'login' | 'register';
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

interface GoogleJWT {
  sub: string; // Google ID
  email: string;
  given_name: string;
  family_name: string;
  picture?: string;
  email_verified: boolean;
}

export const GoogleOAuthButton: React.FC<GoogleOAuthButtonProps> = ({
  mode,
  onSuccess,
  onError,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { refreshAuth } = useAuth();
  const [loading, setLoading] = useState(false);

  // Determine where to redirect after login
  const getReturnUrl = (): string | null => {
    const searchParams = new URLSearchParams(location.search);
    return searchParams.get('returnUrl') || (location.state as any)?.from?.pathname || null;
  };

  const handleGoogleSuccess = async (credentialResponse: CredentialResponse) => {
    if (!credentialResponse.credential) {
      onError?.('No credential received from Google');
      return;
    }

    setLoading(true);

    try {
      // Decode JWT token from Google
      const decoded = jwtDecode<GoogleJWT>(credentialResponse.credential);

      console.log('Google OAuth success:', decoded);

      // Call backend OAuth endpoint
      const user = await oauthApi.googleLogin({
        email: decoded.email,
        google_id: decoded.sub,
        first_name: decoded.given_name,
        last_name: decoded.family_name,
        avatar_url: decoded.picture,
      });

      console.log('Backend OAuth success:', user);

      // Update auth context so navigation re-renders with logged-in state
      await refreshAuth();

      // Success callback
      onSuccess?.();

      // Navigate on next tick to ensure auth state has propagated to all consumers
      const returnUrl = getReturnUrl();
      setTimeout(() => {
        if (returnUrl) {
          navigate(returnUrl, { replace: true });
        } else if (user.role === 'admin' || user.is_admin) {
          navigate('/admin', { replace: true });
        } else {
          navigate('/dashboard', { replace: true });
        }
      }, 0);
    } catch (error: any) {
      console.error('Google OAuth error:', error);
      const errorMessage = error.response?.data?.detail || 'Google sign-in failed. Please try again.';
      onError?.(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleError = () => {
    console.error('Google OAuth failed');
    onError?.('Google sign-in failed. Please try again.');
  };

  return (
    <GoogleLogin
      onSuccess={handleGoogleSuccess}
      onError={handleGoogleError}
      useOneTap={false}
      theme="outline"
      size="large"
      width="100%"
      text={mode === 'login' ? 'signin_with' : 'signup_with'}
    />
  );
};

export default GoogleOAuthButton;
