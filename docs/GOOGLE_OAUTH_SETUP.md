# Google OAuth Setup Guide

This guide walks you through setting up Google OAuth authentication for the BlogCMS platform.

---

## 📋 Prerequisites

- Google Cloud Console account
- Node.js project with npm/yarn
- Backend FastAPI server running
- Frontend React app running

---

## 🔧 Step 1: Install Frontend Dependencies

```bash
cd frontend
npm install @react-oauth/google jwt-decode
```

---

## 🌐 Step 2: Google Cloud Console Setup

### 2.1 Create or Select Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown (top nav bar)
3. Click "New Project" or select existing project
4. Name your project: `BlogCMS` or `The IT Apprentice`
5. Click "Create"

### 2.2 Enable Google+ API

1. In the left sidebar, navigate to **APIs & Services** → **Library**
2. Search for "Google+ API"
3. Click on it and press **Enable**

### 2.3 Configure OAuth Consent Screen

1. Navigate to **APIs & Services** → **OAuth consent screen**
2. Choose **External** (for public access) or **Internal** (for organization only)
3. Click **Create**

**Fill in the form:**

- **App name:** `The IT Apprentice` (or your blog name)
- **User support email:** `your-email@example.com`
- **App logo:** (optional) Upload your logo
- **App domain:**
  - Application home page: `https://theitapprentice.com`
  - Privacy policy: `https://theitapprentice.com/privacy`
  - Terms of service: `https://theitapprentice.com/terms`
- **Authorized domains:** Add `theitapprentice.com` (or your domain)
- **Developer contact:** `your-email@example.com`

4. Click **Save and Continue**
5. **Scopes:** Skip this step (default scopes are fine)
6. **Test users:** Add your email for testing (if using External)
7. Click **Save and Continue**
8. Review and click **Back to Dashboard**

### 2.4 Create OAuth 2.0 Client ID

1. Navigate to **APIs & Services** → **Credentials**
2. Click **+ Create Credentials** → **OAuth client ID**
3. **Application type:** Select **Web application**
4. **Name:** `BlogCMS Web Client`

**Authorized JavaScript origins:**
```
http://localhost:5173
https://theitapprentice.com
```

**Authorized redirect URIs:**
```
http://localhost:5173
http://localhost:5173/login
http://localhost:5173/register
https://theitapprentice.com
https://theitapprentice.com/login
https://theitapprentice.com/register
```

5. Click **Create**
6. **IMPORTANT:** Copy your **Client ID** and **Client Secret**
7. Store them securely (you'll need them in the next step)

---

## 🔐 Step 3: Configure Environment Variables

### 3.1 Backend Configuration

Create or edit `backend/.env`:

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5173/auth/google/callback
```

### 3.2 Frontend Configuration

Create or edit `frontend/.env`:

```env
# Google OAuth Configuration
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

**⚠️ Security Note:**
- The Client ID is safe to expose in frontend code (it's public)
- The Client Secret should NEVER be in frontend code (backend only)

---

## 🔨 Step 4: Update Frontend Code

### 4.1 Wrap App with GoogleOAuthProvider

Edit `frontend/src/App.tsx`:

```typescript
import { GoogleOAuthProvider } from '@react-oauth/google';

function App() {
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

  if (!googleClientId) {
    console.error('VITE_GOOGLE_CLIENT_ID is not set in environment variables');
  }

  return (
    <GoogleOAuthProvider clientId={googleClientId || ''}>
      <HelmetProvider>
        <BrowserRouter>
          <ThemeProvider>
            <AuthProvider>
              {/* ... rest of your app */}
              <AppRoutes />
            </AuthProvider>
          </ThemeProvider>
        </BrowserRouter>
      </HelmetProvider>
    </GoogleOAuthProvider>
  );
}

export default App;
```

### 4.2 Enable GoogleOAuthButton Component

Edit `frontend/src/components/auth/GoogleOAuthButton.tsx`:

**UNCOMMENT** the section marked with:
```typescript
// UNCOMMENT THIS WHEN @react-oauth/google IS INSTALLED:
```

**And REMOVE** the `PlaceholderButton` return statement at the bottom.

---

## ✅ Step 5: Test the Integration

### 5.1 Start Backend Server

```bash
cd backend
uvicorn app.main:app --reload
```

Verify OAuth endpoint is available:
```bash
curl http://localhost:8000/api/v1/auth/oauth/google
```

### 5.2 Start Frontend Server

```bash
cd frontend
npm run dev
```

Open browser: `http://localhost:5173`

### 5.3 Test Login Flow

1. Navigate to `http://localhost:5173/login`
2. Click "Sign in with Google" button
3. Select your Google account
4. Grant permissions
5. Should redirect to `/admin` dashboard
6. Check browser console for any errors

### 5.4 Test Registration Flow

1. Navigate to `http://localhost:5173/register`
2. Click "Sign up with Google" button
3. Select your Google account
4. Grant permissions
5. Should redirect to `/admin` dashboard
6. Verify new user was created in database

---

## 🔍 Troubleshooting

### Issue: "redirect_uri_mismatch" error

**Cause:** The redirect URI in your request doesn't match the URIs configured in Google Cloud Console.

**Solution:**
1. Check the redirect URI in the error message
2. Add it exactly (including trailing slash) to Google Cloud Console → Credentials
3. Wait a few minutes for changes to propagate
4. Try again

### Issue: "invalid_client" error

**Cause:** Client ID or Client Secret is incorrect.

**Solution:**
1. Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env` files
2. Make sure there are no extra spaces or quotes
3. Regenerate credentials if needed in Google Cloud Console

### Issue: Google button doesn't appear

**Cause:** `@react-oauth/google` not installed or `VITE_GOOGLE_CLIENT_ID` not set.

**Solution:**
1. Run `npm install @react-oauth/google jwt-decode`
2. Verify `.env` file has `VITE_GOOGLE_CLIENT_ID=...`
3. Restart Vite dev server (`npm run dev`)
4. Check browser console for errors

### Issue: "Access blocked" error

**Cause:** OAuth consent screen not published or test users not added.

**Solution:**
1. Go to Google Cloud Console → OAuth consent screen
2. If using External type, add your email to "Test users"
3. Or publish the app (requires verification for production)

### Issue: User created but not logged in

**Cause:** Cookies not being set or CORS issues.

**Solution:**
1. Check browser dev tools → Application → Cookies
2. Verify `access_token` cookie is present
3. Check CORS settings in `backend/app/main.py`
4. Ensure `allow_credentials=True` in CORS config

---

## 🔒 Security Best Practices

### 1. **Never Expose Client Secret**
- Only use Client Secret in backend
- Never commit it to Git
- Use environment variables

### 2. **Validate JWT Tokens**
- The backend OAuth endpoint already validates Google JWT tokens
- Uses Google's public keys automatically

### 3. **HTTPS in Production**
- Always use HTTPS for OAuth redirects in production
- Update authorized origins/redirects in Google Console

### 4. **Restrict Redirect URIs**
- Only add exact URIs you need
- Don't use wildcards
- Remove localhost URIs in production

### 5. **Rate Limiting**
- The OAuth endpoint has built-in rate limiting
- Consider adding IP-based limits for extra security

---

## 🌍 Production Deployment

### 1. Update Google Cloud Console

**Add production URIs:**

Authorized JavaScript origins:
```
https://theitapprentice.com
https://www.theitapprentice.com
```

Authorized redirect URIs:
```
https://theitapprentice.com/login
https://theitapprentice.com/register
```

**Remove development URIs:**
```
http://localhost:5173  ← REMOVE THIS
```

### 2. Update Environment Variables

**Backend (production `.env`):**
```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://theitapprentice.com/auth/google/callback
```

**Frontend (build process):**
```env
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

### 3. Publish OAuth Consent Screen

1. Go to Google Cloud Console → OAuth consent screen
2. Click "Publish App"
3. Submit for verification (required for >100 users)

**Verification Requirements:**
- Privacy policy URL
- Terms of service URL
- App domain verification
- Screen recordings of OAuth flow
- May take 1-2 weeks

---

## 📊 Monitoring & Analytics

### Track OAuth Usage

Monitor these metrics:
- Number of Google OAuth logins vs. email/password logins
- OAuth error rate
- Average OAuth flow completion time

### Database Queries

**Count Google users:**
```sql
SELECT COUNT(*) FROM users WHERE google_id IS NOT NULL;
```

**Find users with both Google and password:**
```sql
SELECT email, username FROM users
WHERE google_id IS NOT NULL AND hashed_password IS NOT NULL;
```

---

## 🔗 Useful Links

- [Google OAuth Documentation](https://developers.google.com/identity/protocols/oauth2)
- [@react-oauth/google Docs](https://www.npmjs.com/package/@react-oauth/google)
- [Google Cloud Console](https://console.cloud.google.com/)
- [OAuth Debugging Tool](https://developers.google.com/oauthplayground/)

---

## ✅ Setup Checklist

- [ ] Install `@react-oauth/google` and `jwt-decode`
- [ ] Create Google Cloud project
- [ ] Enable Google+ API
- [ ] Configure OAuth consent screen
- [ ] Create OAuth 2.0 credentials
- [ ] Copy Client ID and Secret
- [ ] Add Client ID to frontend `.env`
- [ ] Add Client ID and Secret to backend `.env`
- [ ] Wrap app with `GoogleOAuthProvider`
- [ ] Uncomment code in `GoogleOAuthButton.tsx`
- [ ] Test login flow
- [ ] Test registration flow
- [ ] Verify user creation in database
- [ ] Test unlinking Google account
- [ ] Review security settings
- [ ] Update for production deployment

---

**Need Help?** Check the troubleshooting section above or create an issue in the repository.
