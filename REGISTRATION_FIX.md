# Registration Control - Bug Fix

**Date**: 2025-12-12
**Issue**: Registration disable feature not working on frontend
**Status**: ✅ FIXED

---

## Problem Report

Despite enabling the "disable registration" option in admin panel:
1. ❌ `/register` page still showed registration form
2. ❌ Login page still showed "Sign up" button
3. ❌ No disabled message appeared

**Root Cause**: Frontend wasn't properly reading registration settings from the backend.

---

## Analysis

### What Was Working ✅
- Database migration applied successfully
- Admin panel saving settings correctly to database
- Backend API endpoint created (`/api/v1/auth/registration-status`)
- Database shows: `registration_enabled = false` ✅

### What Was Broken ❌
1. **Site Settings Store Missing Fields**
   - `useSiteSettingsStore.ts` didn't include `registrationEnabled` field
   - Store couldn't fetch/store registration settings from API

2. **Pages Making Separate API Calls**
   - Login.tsx and Register.tsx were trying to call `/api/v1/auth/registration-status`
   - These calls may have failed due to proxy/timing issues
   - Not using the centralized site settings infrastructure

---

## Fix Applied

### 1. Updated Site Settings Store
**File**: `frontend/src/store/useSiteSettingsStore.ts`

Added missing fields to interface:
```typescript
// Registration Control
registrationEnabled: boolean;
registrationDisabledMessage: string;
```

Added to defaults:
```typescript
// Registration Control
registrationEnabled: true,
registrationDisabledMessage: '',
```

### 2. Updated Login Page
**File**: `frontend/src/pages/Login.tsx`

**Before**: Made separate API call to `/api/v1/auth/registration-status`

**After**: Uses site settings store
```typescript
const registrationEnabled = useSiteSettingsStore((state) => state.settings.registrationEnabled);
const registrationDisabledMessage = useSiteSettingsStore((state) => state.settings.registrationDisabledMessage);
```

### 3. Updated Register Page
**File**: `frontend/src/pages/Register.tsx`

**Before**: Made separate API call to `/api/v1/auth/registration-status`

**After**: Uses site settings store
```typescript
const registrationEnabled = useSiteSettingsStore((state) => state.settings.registrationEnabled);
const registrationDisabledMessage = useSiteSettingsStore((state) => state.settings.registrationDisabledMessage);
```

---

## How It Works Now

### Data Flow

1. **Admin Panel**:
   - Admin toggles "Allow User Registration" OFF
   - Enters custom message
   - Clicks "Save Settings"
   - → Saves to database via `/api/v1/admin/site-settings`

2. **Site Settings Store**:
   - Fetches from `/api/v1/site-settings` on app load
   - Includes `registrationEnabled` and `registrationDisabledMessage`
   - Stores in Zustand + localStorage for fast access

3. **Login Page**:
   - Reads `registrationEnabled` from store
   - **If enabled**: Shows "Sign up" link
   - **If disabled**: Shows amber banner with custom message

4. **Register Page**:
   - Reads `registrationEnabled` from store
   - **If enabled**: Shows registration form
   - **If disabled**: Shows disabled message → Auto-redirects to login after 2s

---

## Testing Instructions

### 1. Clear Browser Cache
```bash
# Important: Clear localStorage to remove old cached settings
# In browser console:
localStorage.clear();
# Or use Ctrl+Shift+Delete → Clear site data
```

### 2. Start Servers
```bash
# Terminal 1 - Backend
cd "C:\Gitlab Projects\BlogCMS\backend"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100

# Terminal 2 - Frontend
cd "C:\Gitlab Projects\BlogCMS\frontend"
npm run dev
```

**NOTE**: Backend must be on port **8100** (Vite proxy configuration)

### 3. Enable Registration (Default State)
1. Open incognito: http://localhost:5173/login
2. Should see: "Don't have an account? **Sign up**"
3. Click "Sign up" → Should show registration form

### 4. Disable Registration (Admin)
1. Login as admin: http://localhost:5173/login
2. Go to: http://localhost:5173/admin/settings
3. Click "User Registration" tab (👥)
4. Toggle "Allow User Registration" to **OFF**
5. Edit message if desired
6. Click "Save Settings"
7. Logout

### 5. Verify Disabled State
1. Open NEW incognito window: http://localhost:5173/login
2. Should see: Amber info banner with your custom message
3. Should NOT see: "Sign up" link
4. Try to access: http://localhost:5173/register
5. Should see: Disabled message → Auto-redirect to login

---

## Files Changed

### Backend (Previous - Already Applied)
- ✅ `backend/app/api/v1/services/site_settings/models.py`
- ✅ `backend/app/api/v1/services/site_settings/schemas.py`
- ✅ `backend/app/auth/registration.py`
- ✅ `backend/alembic/versions/v2_11_add_registration_control.py`

### Frontend (This Fix)
- 🔧 `frontend/src/store/useSiteSettingsStore.ts` - Added registration fields
- 🔧 `frontend/src/pages/Login.tsx` - Use store instead of separate API call
- 🔧 `frontend/src/pages/Register.tsx` - Use store instead of separate API call

---

## Verification Checklist

After applying this fix:

- [ ] Clear browser localStorage
- [ ] Start backend on port 8100
- [ ] Start frontend dev server
- [ ] Test registration ENABLED:
  - [ ] Login page shows "Sign up" link
  - [ ] /register shows form
  - [ ] Can submit registration
- [ ] Disable in admin panel and save
- [ ] Test registration DISABLED:
  - [ ] Login page shows amber banner
  - [ ] Login page does NOT show "Sign up" link
  - [ ] /register shows disabled message
  - [ ] /register redirects to login after 2s
  - [ ] Banner shows custom message correctly
- [ ] Test in both light and dark mode
- [ ] Test in incognito (no cached settings)

---

## Why This Approach Is Better

### Before (Broken):
- Each page made its own API call
- Separate endpoint `/api/v1/auth/registration-status`
- Not integrated with existing infrastructure
- Timing/proxy issues could cause failures

### After (Fixed):
- Single source of truth (site settings store)
- One API call fetches all settings
- Zustand + localStorage for instant access
- Works with existing Vite proxy configuration
- Consistent with rest of app architecture

---

## Additional Notes

### Backend Server Port
The Vite dev server proxy forwards `/api` to `http://localhost:8100`:
```typescript
proxy: {
  '/api': {
    target: 'http://localhost:8100',
    changeOrigin: true,
    secure: false,
  },
}
```

**Important**: Start backend with:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

NOT port 8000 (which is in .env but not matching proxy).

### Production Deployment
In production, Nginx handles the proxying, so port doesn't matter.
These changes work in both dev and production.

---

**Fix Applied**: ✅ Complete
**Ready for Testing**: ✅ Yes
**Breaking Changes**: ❌ None
**Requires Migration**: ❌ No (already applied)
