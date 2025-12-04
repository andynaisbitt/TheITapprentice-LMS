# BlogCMS V1 - Quick Start Guide

## 🚀 5-Minute Setup

### 1. Frontend Setup (Already Running!)
Your frontend is currently running at: **http://localhost:5174**

```bash
# If you need to restart:
cd "C:\Gitlab Projects\BlogCMS\Frontend"
npm run dev
```

### 2. Backend Setup
```bash
# Navigate to backend
cd "C:\Gitlab Projects\BlogCMS\Backend"

# Activate virtual environment
venv\Scripts\activate

# Start server (should use existing PostgreSQL from ITApp)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

**Database:** Already configured to use `itapp_postgres` container on port 5432 → `blogcms_db`

### 3. First Login
1. Open: http://localhost:5174/login
2. Login with admin credentials from `.env`:
   - Email: `admin@blogcms.local`
   - Password: `AdminBlogCMS2025!`

### 4. Customize Homepage
1. Navigate to: **Admin → Site Settings**
2. Click **Homepage** tab
3. Customize:
   - **Hero Title:** Your blog name
   - **Hero Subtitle:** Your tagline/description
   - **Badge Text:** e.g., "Tech Blog", "Personal Blog", "Dev Notes"
   - **Primary CTA:** "Read Articles", "Start Reading", etc.
   - **Secondary CTA:** "About Me", "Contact", etc.
   - **Stats:** Leave blank to hide, or add custom values
4. Click **Save Settings**
5. Refresh homepage to see changes!

### 5. Create First Blog Post
1. Go to: **Admin → Blog Posts**
2. Click **"Create New Post"**
3. Fill in:
   - Title
   - Content (supports markdown)
   - Excerpt (for previews)
   - Categories (create new if needed)
   - Tags
   - Featured image URL (optional)
   - SEO fields (meta title, description)
4. Toggle **"Published"** switch
5. Click **"Save Post"**

---

## 📋 Customization Checklist

### Must Customize Before Launch:
- [ ] Homepage hero title
- [ ] Homepage subtitle
- [ ] Badge text
- [ ] CTA button text
- [ ] Site title (SEO tab)
- [ ] Site tagline (SEO tab)
- [ ] Meta description (SEO tab)
- [ ] Site URL (SEO tab)
- [ ] Contact email (Contact tab)

### Optional Customizations:
- [ ] Stats section (show/hide)
- [ ] Google Analytics ID (Analytics tab)
- [ ] Social media links (Social tab)
- [ ] Theme colors (coming in V1.2)

---

## 🎨 Example Customizations

### Personal Tech Blog
```
Hero Title: "Code & Coffee"
Hero Subtitle: "Exploring modern web development, one espresso at a time"
Badge Text: "Developer Blog"
Primary CTA: "Read Articles"
Secondary CTA: "About Me"
```

### Business Blog
```
Hero Title: "Company Insights"
Hero Subtitle: "Industry news, product updates, and expert analysis"
Badge Text: "Official Blog"
Primary CTA: "Latest Updates"
Secondary CTA: "Contact Sales"
```

### Portfolio Blog
```
Hero Title: "Creative Works"
Hero Subtitle: "Design, code, and everything in between"
Badge Text: "Portfolio"
Primary CTA: "View Projects"
Secondary CTA: "Hire Me"
```

---

## 🔄 Forking for TheITapprentice

### When you're ready to fork for ITApp:

1. **Clone BlogCMS to private repo:**
   ```bash
   cd "C:\Gitlab Projects"
   cp -r BlogCMS ITApp-Private-Blog
   cd ITApp-Private-Blog
   git init
   git remote add origin <your-private-repo-url>
   git add .
   git commit -m "Fork BlogCMS V1 for ITApprentice"
   git push -u origin main
   ```

2. **Customize for ITApprentice:**
   - Hero Title: "The IT Apprentice Blog"
   - Hero Subtitle: "IT training, career advice, and skill development"
   - Badge Text: "Education Platform"
   - Stats: Show actual ITApp stats
   - Add ITApp branding/colors

3. **Database Migration:**
   - Already using same PostgreSQL container
   - Blog tables already exist in `blogcms_db`
   - Can import posts from ITApp if needed

---

## 🚢 Deployment Options

### Option 1: Vercel (Frontend) + Railway (Backend)
- **Vercel:** Free tier, auto-deploy from Git
- **Railway:** $5/month, includes PostgreSQL
- **Total:** ~$5/month

### Option 2: Google Cloud Platform
- **Cloud Run:** Backend container
- **Cloud Storage:** Frontend static files
- **Cloud SQL:** PostgreSQL database
- **Total:** ~$10-30/month (see `docs/DEPLOYMENT.md`)

### Option 3: DigitalOcean App Platform
- **App:** $5/month
- **Database:** $15/month
- **Total:** ~$20/month

---

## 🧪 Testing Checklist

Before deploying:
- [ ] Test homepage with custom settings
- [ ] Create sample blog post
- [ ] Verify post displays correctly
- [ ] Test category filtering
- [ ] Test tag filtering
- [ ] Test search functionality
- [ ] Check mobile responsiveness
- [ ] Verify dark mode works
- [ ] Test admin panel on mobile
- [ ] Clear cache and test fresh load

---

## 📞 Need Help?

1. **Check console:** F12 in browser
2. **Review logs:** Backend terminal output
3. **Check settings:** `localStorage.getItem('blogcms_settings')`
4. **Reset settings:** Site Settings → Reset to Defaults
5. **Check docs:** `README.md` and `docs/` folder

---

## ✅ You're Ready!

Your BlogCMS V1 instance is configured and ready to use!

**Current Status:**
- ✅ Frontend running: http://localhost:5174
- ⏳ Backend: Start with `uvicorn app.main:app --reload --host 0.0.0.0 --port 8100`
- ⏳ Database: Using existing PostgreSQL from ITApp
- ✅ Settings: Customize at `/admin/settings`

**Happy blogging! 🎉**
