# FastReactCMS

> **A modern, production-ready blog and CMS platform built for developers who want to ship fast without sacrificing control.**

[![Version](https://img.shields.io/badge/Version-1.5-brightgreen.svg)](https://github.com/andynaisbitt/Fast-React-CMS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-18.x-61dafb.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://www.typescriptlang.org/)
[![Security: A+](https://img.shields.io/badge/Security-A%2B-success.svg)](docs/development/SECURITY_AUDIT_REPORT.md)
[![Contributors Welcome](https://img.shields.io/badge/Contributors-Welcome-orange.svg)](docs/development/CONTRIBUTING.md)

---

## Screenshots

> - Admin Dashboard
<img width="1250" height="976" alt="image" src="https://github.com/user-attachments/assets/a913dc86-a4be-4d4e-936c-e1e31dba9466" />

> - Blog Editor with Markdown Preview
<img width="1229" height="1312" alt="image" src="https://github.com/user-attachments/assets/4acd5dc2-c74a-42de-b979-07f41a2b9d26" />

> - Theme Customization Panel + Dark Mode Interface
<img width="2469" height="1327" alt="image" src="https://github.com/user-attachments/assets/88b1ea6d-606d-4dd3-ab1f-febf2d061217" />

> - Dynamic Page Builder
<img width="1266" height="1267" alt="image" src="https://github.com/user-attachments/assets/652cc3ea-f0ad-4e32-bccc-f64caf65bf89" />

> - Category & Tag Management
<img width="1269" height="1038" alt="image" src="https://github.com/user-attachments/assets/21261c28-0e3e-4624-8a4f-610349c08ca7" />


**Want to contribute screenshots?** Fork the repo, take screenshots, and submit a PR!

---

## ✨ What's New in v1.5 (December 15, 2025)

FastReactCMS v1.5 brings major refactoring improvements, comprehensive documentation, and **production-tested stability**:

🎯 **State Management Upgrade** - Replaced scattered Context providers with Zustand for centralized, type-safe state
🔧 **Cleaner Codebase** - Eliminated 57 lines of boilerplate with Pydantic alias automation
📚 **Documentation Overhaul** - Added 2,283+ lines of documentation including comprehensive ARCHITECTURE.md
📦 **Bundle Size Reduced** - 402 kB → 399.90 kB (-2.16 kB)
🏗️ **Production Battle-Tested** - Resolved configuration issues and documented comprehensive troubleshooting approaches
🔒 **Security Hardened** - A+ security rating with HTTP-only cookies, CSRF protection, and bcrypt hashing

> **Calling Contributors!** This project is actively seeking contributors to help improve code quality, documentation, and OSS best practices. Check out [CONTRIBUTING.md](docs/development/CONTRIBUTING.md)!

See the full [Roadmap](#roadmap) below for details.

---

## Features

FastReactCMS combines the best of modern web development with a developer-first approach:

### Core Features
- **Modern Tech Stack** - React 18 + TypeScript + FastAPI + PostgreSQL
- **Lightning Fast** - Vite builds, optimized queries, and smart caching
- **SEO Optimized** - Canonical URLs, SSR for crawlers, meta tags, RSS feeds, sitemaps, and schema markup
- **Hybrid SSR** - Fast SPA for users, server-rendered HTML for search engines and social media crawlers
- **Dynamic Pages** - Modular block system for building custom pages without code
- **Theme Customization** - Real-time color and typography controls
- **Dark Mode** - Beautiful dark theme across the entire platform
- **Mobile-First** - Responsive design that works on every device
- **Homepage Builder** - Fully customizable homepage with hero, carousel, categories, and stats sections
- **SEO Diagnostic Tool** - Built-in 9-test SEO analyzer for all content

### Content Management
- **Rich Blog Editor** - Markdown support, image uploads, and SEO optimization
- **Category & Tag System** - Organize content with unlimited categories and tags
- **Draft System** - Save and publish content when ready
- **Media Library** - Image upload and management with SVG support
- **Newsletter System** - Email subscription and newsletter management (v1.3)
- **Logo & Favicon Upload** - Custom branding with theme-aware light/dark mode support
- **Comprehensive Site Settings** - Centralized control for SEO, analytics, branding, and more

### Security & Performance
- **HTTP-Only Cookies** - JWT tokens never exposed to JavaScript (XSS protection)
- **CSRF Protection** - Token-based protection on all state-changing requests
- **bcrypt Password Hashing** - Industry-standard password security
- **Rate Limiting** - Brute force protection on authentication
- **SVG XSS Prevention** - Secure SVG upload validation blocks malicious code
- **CSP-Compliant Analytics** - Google Analytics & AdSense integration following Content Security Policy
- **Secure by Default** - See our [Security Audit Report](SECURITY_AUDIT_REPORT.md) (A+ rating)

### Developer Experience
- **Type-Safe** - Full TypeScript coverage
- **API Documentation** - Interactive FastAPI docs at `/docs`
- **Hot Reload** - Fast development with Vite HMR
- **Database Migrations** - Alembic for version-controlled schema changes
- **Clean Architecture** - Modular, maintainable codebase

---

## Quick Start

### Prerequisites

- **Python 3.10+** with pip
- **Node.js 18+** with npm
- **PostgreSQL 14+**

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/andynaisbitt/Fast-React-CMS.git
cd Fast-React-CMS
```

#### 2. Install PostgreSQL

**Automated Setup (Linux/macOS):**
```bash
# One-command setup! This script will:
# - Install PostgreSQL (if not installed)
# - Create database and user with secure password
# - Generate .env file with all secrets
# - Run database migrations
chmod +x deployment/setup-postgres.sh
./deployment/setup-postgres.sh
```

**Manual PostgreSQL Setup:**

**On Ubuntu/Debian:**
```bash
# Install PostgreSQL
sudo apt update
sudo apt install -y postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql

# In PostgreSQL prompt:
CREATE DATABASE fastreactcms;
CREATE USER fastreactcms_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE fastreactcms TO fastreactcms_user;

-- Connect to database
\c fastreactcms
GRANT ALL ON SCHEMA public TO fastreactcms_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO fastreactcms_user;

-- Exit
\q
```

**On macOS:**
```bash
# Install via Homebrew
brew install postgresql@14
brew services start postgresql@14

# Create database
createdb fastreactcms

# Create user (use psql to set password)
psql fastreactcms
CREATE USER fastreactcms_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE fastreactcms TO fastreactcms_user;
\q
```

**On Windows:**
1. Download PostgreSQL from https://www.postgresql.org/download/windows/
2. Run installer and remember your postgres password
3. Open SQL Shell (psql) and run:
```sql
CREATE DATABASE fastreactcms;
CREATE USER fastreactcms_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE fastreactcms TO fastreactcms_user;
\c fastreactcms
GRANT ALL ON SCHEMA public TO fastreactcms_user;
```

#### 3. Backend Setup

```bash
cd Backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Edit .env with your database credentials
# DATABASE_URL=postgresql://fastreactcms_user:your_secure_password@localhost/fastreactcms
nano .env  # or use any text editor

# Generate secure secrets for production
# SECRET_KEY (run this):
openssl rand -hex 32

# CSRF_SECRET_KEY (run this):
openssl rand -hex 32

# Add these to .env file

# Run database migrations
alembic upgrade head

# Seed initial data (admin user, categories, sample content)
python scripts/create_admin.py
python scripts/seed_categories.py
python scripts/seed_navigation_theme.py
python scripts/seed_pages.py
python scripts/seed_sample_content.py

# Start backend server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

Backend will be running at: `http://localhost:8100`
API docs available at: `http://localhost:8100/docs`

#### 4. Frontend Setup

```bash
cd Frontend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env
# Ensure VITE_API_URL matches your backend URL

# Start development server
npm run dev
```

Frontend will be running at: `http://localhost:5173`

#### 5. First Login

- Navigate to `http://localhost:5173/admin`
- Login with the admin credentials you created during `create_admin.py`
- Start creating content!

---

## Technology Stack

### Frontend
- **React 18** - Modern UI library with concurrent features
- **TypeScript** - Type-safe JavaScript
- **Vite** - Lightning-fast build tool and dev server
- **Tailwind CSS** - Utility-first CSS framework
- **React Router** - Client-side routing
- **Axios** - HTTP client with interceptors
- **React Markdown** - Markdown rendering
- **Framer Motion** - Smooth animations

### Backend
- **FastAPI** - Modern Python web framework
- **SQLAlchemy** - SQL ORM with full typing support
- **Alembic** - Database migration tool
- **PostgreSQL** - Production-grade relational database
- **Pydantic** - Data validation using Python type annotations
- **python-jose** - JWT token handling
- **bcrypt** - Password hashing
- **SlowAPI** - Rate limiting middleware

### Security
- **HTTP-Only Cookies** - Secure JWT storage
- **CSRF Tokens** - Cross-site request forgery protection
- **CORS** - Configured cross-origin resource sharing
- **Password Hashing** - bcrypt with automatic salting
- **Rate Limiting** - Brute force attack prevention
- **Input Validation** - Pydantic schemas on all endpoints

---

## Project Structure

> **Note:** Directories `Backend/` and `Frontend/` are being renamed to lowercase (`backend/`, `frontend/`) to follow OSS conventions. Use `rename-dirs.sh` for safe migration.

```
FastReactCMS/
├── backend/                  # (formerly Backend/)
│   ├── alembic/              # Database migrations
│   ├── app/
│   │   ├── api/v1/           # API endpoints and services
│   │   │   ├── endpoints/    # Route handlers
│   │   │   ├── schemas/      # Pydantic schemas (with auto alias_generator=to_camel)
│   │   │   └── services/     # Business logic
│   │   ├── auth/             # Authentication routes
│   │   ├── core/             # Core config and security
│   │   ├── pages/            # Dynamic pages system
│   │   └── users/            # User management
│   ├── scripts/              # Utility scripts (seeding, etc.)
│   ├── static/               # Static files and uploads
│   ├── .env.example          # Environment variables template
│   ├── alembic.ini           # Alembic configuration
│   └── requirements.txt      # Python dependencies
├── frontend/                 # (formerly Frontend/)
│   ├── src/
│   │   ├── components/       # React components
│   │   │   ├── Admin/        # Admin panel components
│   │   │   ├── Blog/         # Blog components
│   │   │   ├── Layout/       # Layout components
│   │   │   └── Pages/        # Dynamic page components
│   │   ├── pages/            # Page-level components
│   │   ├── services/         # API clients
│   │   ├── store/            # Zustand state management (v1.5)
│   │   ├── hooks/            # Custom React hooks
│   │   ├── utils/            # Utility functions
│   │   └── types/            # TypeScript type definitions
│   ├── .env.example          # Frontend environment template
│   ├── package.json          # NPM dependencies
│   └── vite.config.ts        # Vite configuration
├── deployment/
│   ├── nginx.conf            # NGINX configuration
│   ├── setup-nginx.sh        # NGINX setup script
│   ├── setup-postgres.sh     # PostgreSQL setup script
│   └── fastreactcms.service  # systemd service configuration
├── docs/
│   ├── deployment/           # Deployment guides
│   ├── development/          # Contributing, setup, security
│   ├── features/             # Feature documentation
│   ├── releases/             # Release notes
│   ├── setup/                # Analytics, AdSense setup
│   └── README.md             # Documentation index
├── ARCHITECTURE.md           # System architecture guide (v1.5)
├── rename-dirs.sh            # Directory rename helper script (v1.5)
├── .gitignore                # Git exclusions
├── LICENSE                   # MIT License
└── README.md                 # This file
```

---

## Configuration

### Backend Environment Variables

Key environment variables in `Backend/.env`:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/fastreactcms

# Security (CHANGE THESE!)
SECRET_KEY=your-secret-key-min-32-chars
CSRF_SECRET_KEY=your-csrf-secret-key-min-32-chars

# Admin User
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=secure-password-min-12-chars

# Cookie Security
COOKIE_SECURE=false  # Set to 'true' in production (requires HTTPS)
COOKIE_SAMESITE=lax

# CORS
CORS_ORIGINS=["http://localhost:5173"]  # Update with production domain
```

See `Backend/.env.example` for complete configuration options.

### Frontend Environment Variables

Key environment variables in `Frontend/.env`:

```env
# API URL (must match backend)
VITE_API_URL=http://localhost:8100
```

See `Frontend/.env.example` for complete configuration options.

---

## Usage

### Creating Your First Blog Post

1. Navigate to `/admin` and login
2. Click "Blog" in the admin sidebar
3. Click "Create Post"
4. Fill in:
   - Title and slug
   - Content (Markdown supported)
   - Excerpt for previews
   - Categories and tags
   - SEO meta tags
   - Featured image (optional)
5. Toggle "Published" and save

### Customizing Your Site

1. Go to `/admin/settings/site`
2. Configure across 8 comprehensive tabs:
   - **Homepage**: Hero section, CTAs, stats display
   - **Homepage Layout**: Carousel, categories, recent posts sections
   - **SEO & Domain**: Meta tags, Open Graph, site URL
   - **Branding & Logo**: Upload logos and favicons (light/dark mode)
   - **Analytics & Ads**: Google Analytics, AdSense (CSP-compliant)
   - **Social Media**: Twitter, Facebook, LinkedIn, GitHub links
   - **Contact Info**: Email addresses
   - **Email & Newsletter**: SMTP configuration, newsletter settings

### Building Custom Pages

1. Go to `/admin/pages`
2. Click "Create Page"
3. Use the block editor to add:
   - Text blocks
   - Headings
   - Images
   - Code snippets
   - Callouts
   - Timelines
   - And more!

### Managing Categories & Tags

1. Go to `/admin/blog/categories` or `/admin/blog/tags`
2. Add, edit, or delete as needed
3. Assign colors and icons for better organization

---

## Production Deployment

> **📖 Complete Deployment Guide Available!**
> See [docs/deployment/DEPLOYMENT.md](docs/deployment/DEPLOYMENT.md) for comprehensive production deployment instructions including:
> - Google Cloud VM setup
> - Domain & DNS configuration (with/without Cloudflare)
> - PostgreSQL installation and tuning
> - NGINX reverse proxy with SSL (config in `deployment/nginx.conf`)
> - Let's Encrypt SSL certificates
> - CDN setup (Cloudflare/Google Cloud CDN)
> - Monitoring and maintenance
> - Performance optimization

### Before Deploying

**Critical Security Steps:**

1. **Generate Strong Secrets**:
   ```bash
   # Generate SECRET_KEY (32+ characters)
   openssl rand -hex 32

   # Generate CSRF_SECRET_KEY (32+ characters)
   openssl rand -hex 32
   ```

2. **Update Environment Variables**:
   ```env
   # Backend/.env
   COOKIE_SECURE=true
   ENVIRONMENT=production
   CORS_ORIGINS=["https://yourdomain.com","https://www.yourdomain.com"]
   SECRET_KEY=<generated-secret>
   CSRF_SECRET_KEY=<generated-secret>
   ADMIN_PASSWORD=<strong-password-min-12-chars>
   ```

3. **Enable HTTPS** - Required for secure cookies

4. **Update CORS Origins** - Add your production domain(s)

5. **Database Backups** - Configure automated backups

See our [Security Audit Report](docs/development/SECURITY_AUDIT_REPORT.md) for detailed security guidance.

### Deployment Options

FastReactCMS can be deployed to:
- **VPS** (DigitalOcean, Linode, AWS EC2)
- **PaaS** (Heroku, Railway, Render)
- **Docker** (Docker Compose, Kubernetes)
- **Serverless** (AWS Lambda + RDS, Google Cloud Run)

### Build for Production

**Frontend:**
```bash
cd Frontend
npm run build
# Output in Frontend/dist/
```

**Backend:**
```bash
cd Backend
# Install production dependencies
pip install -r requirements.txt

# Run with production server (gunicorn recommended)
gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8100
```

---

## API Documentation

FastReactCMS provides interactive API documentation via FastAPI:

- **Swagger UI**: `http://localhost:8100/docs`
- **ReDoc**: `http://localhost:8100/redoc`

### Key Endpoints

#### Authentication
- `POST /auth/login` - Login with credentials
- `POST /auth/register` - Register new user
- `GET /auth/me` - Get current user
- `POST /auth/refresh` - Refresh authentication token

#### Blog
- `GET /api/v1/blog/posts` - List blog posts (paginated)
- `GET /api/v1/blog/posts/{slug}` - Get single post
- `POST /api/v1/blog/posts` - Create post (admin)
- `PUT /api/v1/blog/posts/{id}` - Update post (admin)
- `DELETE /api/v1/blog/posts/{id}` - Delete post (admin)

#### Categories & Tags
- `GET /api/v1/blog/categories` - List categories
- `GET /api/v1/blog/tags` - List tags
- `POST /api/v1/blog/categories` - Create category (admin)
- `POST /api/v1/blog/tags` - Create tag (admin)

#### Pages
- `GET /api/v1/pages` - List pages
- `GET /api/v1/pages/{slug}` - Get single page
- `POST /api/v1/pages` - Create page (admin)

See `/docs` for complete API reference.

---

## Contributing

We welcome contributions! Please see [docs/development/CONTRIBUTING.md](docs/development/CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests (if applicable)
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Code Style

- **Frontend**: ESLint + Prettier (run `npm run lint`)
- **Backend**: Black + isort for Python formatting
- **Commits**: Use conventional commit format

---

## Security

FastReactCMS takes security seriously. We've completed a comprehensive security audit with an **A+ (95/100)** rating.

### Security Features
- HTTP-Only Cookies (JWT never exposed to JavaScript)
- CSRF Protection on all state-changing requests
- bcrypt Password Hashing with automatic salting
- Rate Limiting on authentication endpoints
- Secure CORS Configuration
- Input Validation with Pydantic schemas
- Auto Token Refresh System

See our complete [Security Audit Report](docs/development/SECURITY_AUDIT_REPORT.md) for details.

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead:
1. Contact the maintainers privately
2. Provide detailed information about the vulnerability
3. Allow 48 hours for initial response

We take all security reports seriously and will respond promptly.

---

## Roadmap

### ✅ v1.5 (Current - December 15, 2025)

> **Note to the OSS Community:**
> I'm still learning best practices for open-source development! Feedback from Reddit and GitHub has been incredibly helpful. If you see areas for improvement in code standards, documentation, or project structure, please open an issue or PR. Looking for contributors who can help improve this project! 🙏

**Latest Refactoring (v1.5 - December 12-15, 2025):**
- ✅ **Zustand State Management** - Centralized state architecture replacing scattered Context providers
  - Created `SiteSettingsStore` with global site configuration
  - Automatic persistence via `persist` middleware
  - Type-safe selectors and actions
  - Fully backward compatible with existing code
- ✅ **Pydantic Alias Automation** - Eliminated 57 lines of manual camelCase conversion boilerplate
  - Added `alias_generator=to_camel` to all Pydantic schemas
  - Automatic snake_case ↔ camelCase conversion
  - Bundle size reduced: 402.06 kB → 399.90 kB (-2.16 kB)
- ✅ **Documentation Overhaul**
  - New `ARCHITECTURE.md` - 650+ line comprehensive architecture guide
  - Updated `docs/` structure with organized deployment, development, and feature docs
  - Production troubleshooting documentation
  - Security audit report (A+ rating)
- ✅ **Production Hardening**
  - Resolved configuration issues (case sensitivity, environment variables, CORS)
  - File permission fixes for multi-user deployment
  - Browser cache handling best practices documented
  - Battle-tested with 48-hour production incident and full recovery
- ✅ **OSS Standards**
  - Directory rename script for lowercase conventions (`Backend/` → `backend/`, `Frontend/` → `frontend/`)
  - Cleaned documentation structure (essential docs only, no "AI slop")
  - Professional README and contribution guidelines

**Build Status:** ✅ All builds passing | **Security Rating:** A+ (95/100) | **Bundle Size:** 399.90 kB | **Production:** Battle-tested ✅

**Core Features:**
- ✅ Blog system with categories and tags
- ✅ Dynamic page builder with modular blocks
- ✅ Theme customization (colors, typography, navigation)
- ✅ SEO optimization (meta tags, slugs, RSS feeds, sitemap, canonical URLs)
- ✅ Admin panel with content management
- ✅ User authentication (JWT + HTTP-only cookies)
- ✅ Security hardening (CSRF, bcrypt, rate limiting, SVG XSS prevention)
- ✅ CSP-compliant Google Analytics & AdSense integration
- ✅ Responsive design (mobile/tablet/desktop)
- ✅ Dark mode support
- ✅ Image upload and management (PNG, JPG, WebP, SVG)
- ✅ Markdown support for content
- ✅ Server-side rendering for search engine crawlers

**Newsletter System (v1.3):**
- ✅ Email newsletter subscription system
- ✅ SMTP configuration (SendGrid/custom)
- ✅ Subscriber management with search
- ✅ Newsletter composer with HTML support
- ✅ Public unsubscribe page
- ✅ Mobile-optimized admin interface
- ✅ Active/Inactive subscriber tracking

**Homepage Customization (v1.4):**
- ✅ Fully customizable hero section (title, subtitle, badge, CTAs)
- ✅ Homepage stats display (articles, readers, "100% free" badges - configurable or hidden)
- ✅ Featured carousel with crossfade transitions and autoplay (7-second intervals)
- ✅ Categories showcase with customizable limits (1-20 categories)
- ✅ Recent posts grid with flexible layouts (1-50 posts)
- ✅ Toggle sections on/off via admin panel (hero, carousel, categories, recent posts)
- ✅ Mobile-optimized homepage layout with responsive breakpoints
- ✅ Carousel performance optimization (reduced re-renders, smooth transitions)

**SEO & Social Media (v1.4):**
- ✅ **Canonical URL System** - Custom short URLs for posts and pages (e.g., `/RAM-Price-Spikes`)
- ✅ **Server-Side Rendering (SSR)** - Hybrid approach for crawlers only
  - Regular users → Fast SPA (603 bytes)
  - Crawlers (Googlebot, Facebookbot, LinkedIn) → SSR with meta tags (2,876 bytes)
- ✅ **Social Media Previews** - Proper Open Graph and Twitter Card meta tags
- ✅ **SEO Diagnostic Tool** - 9 automated tests (meta tags, headings, images, links, etc.)
- ✅ **Comprehensive Meta Tags** - Homepage and blog posts fully optimized
- ✅ **Performance Optimized SSR** - LRU cache (100 pages, 1-hour TTL), <50ms cached, <200ms uncached

**Branding & Assets (v1.4):**
- ✅ Logo upload system (light & dark mode variants)
- ✅ Theme-aware favicon system (automatically switches with theme)
- ✅ SVG upload support with XSS security validation
- ✅ Favicon management through admin panel
- ✅ Default minimalist wizard/apprentice favicons included
- ✅ Database-driven branding (no .env files needed)

**Mobile UX Improvements (v1.4):**
- ✅ Mobile-first blog post redesign with optimized typography
- ✅ Blog post sidebar optimization for tablets and mobile
- ✅ Responsive navigation with mobile hamburger menu
- ✅ Touch-friendly admin interface

**Analytics & Monetization (v1.4):**
- ✅ CSP-compliant Google Analytics 4 integration
- ✅ CSP-compliant Google AdSense integration
- ✅ ID validation prevents injection attacks
- ✅ No `innerHTML` usage (security hardened)
- ✅ DNT (Do Not Track) respect
- ✅ GDPR-compliant settings
- ✅ Database-driven configuration (update without rebuilds)
- ✅ Multiple ad unit types (article, sidebar, banner)

**Version History:**
- **v1.5 (12-15 Dec 2025)**: Zustand state management, Pydantic alias automation, comprehensive documentation overhaul, production hardening, OSS standards preparation
- **v1.4 (Dec 2025)**: Canonical URLs + SSR, favicon upload, homepage customization, logo upload, CSP-compliant analytics, SEO diagnostics, mobile UX improvements (77 commits)
- **v1.3 (Dec 2025)**: Newsletter system with complete subscriber management
- **v1.2 (Dec 2025)**: Mobile UX improvements across admin panel
- **v1.1 (Dec 2025)**: Production deployment fixes and optimizations
- **v1.0 (Nov 2025)**: Initial production release

### 📋 Future Enhancements (Community Driven)
FastReactCMS is designed as a **developer-friendly foundation** - not a bloated all-in-one solution.

We intentionally keep the core lean so developers can:
- Build custom features without fighting the framework
- Add their own integrations and services
- Extend the block system with custom components
- Implement their own authentication providers
- Create custom admin pages

**Potential community additions:**
- Comment system with moderation
- Advanced media library (image optimization, CDN)
- Content scheduling (publish at specific dates)
- Email notifications for new posts
- Social media auto-posting
- Multi-author support with roles
- Search functionality (full-text PostgreSQL)
- Content versioning and revisions
- Newsletter templates and automation
- A/B testing for newsletters

**Not Planned:**
- ❌ Multi-language/i18n (English only, fork if needed)
- ❌ Plugin marketplace (developers extend directly)
- ❌ E-commerce features (use dedicated solutions)
- ❌ All-in-one bloat (we stay focused on core CMS)

---

## FAQ

**Q: Is FastReactCMS free?**
A: Yes! FastReactCMS is open source under the MIT License. Use it for personal projects, commercial work, or anything in between.

**Q: Can I use this in production?**
A: Absolutely! FastReactCMS is production-ready and has passed comprehensive security audits. Just ensure you follow the production deployment guidelines.

**Q: Do I need to know React and Python?**
A: For basic usage (creating content, customizing themes), no coding is required. For advanced customization, knowledge of React and Python/FastAPI is helpful.

**Q: Can I customize the design?**
A: Yes! The theme system allows extensive customization through the admin panel. For deeper changes, you can modify the React components and Tailwind CSS.

**Q: Is there a hosted version?**
A: Not currently. FastReactCMS is self-hosted, giving you complete control over your data and infrastructure.

**Q: What databases are supported?**
A: PostgreSQL is recommended and fully tested. SQLite works for development but is not recommended for production.

---

## License

FastReactCMS is released under the [MIT License](LICENSE).

Copyright (c) 2025 FastReactCMS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

---

## Acknowledgments

FastReactCMS is built with amazing open-source technologies:

- [React](https://reactjs.org/) - UI library
- [FastAPI](https://fastapi.tiangolo.com/) - Backend framework
- [Vite](https://vitejs.dev/) - Build tool
- [Tailwind CSS](https://tailwindcss.com/) - CSS framework
- [PostgreSQL](https://www.postgresql.org/) - Database
- [SQLAlchemy](https://www.sqlalchemy.org/) - ORM
- [Alembic](https://alembic.sqlalchemy.org/) - Database migrations
- And many more amazing projects!

---

## Documentation

FastReactCMS includes comprehensive documentation for developers and contributors:

### Core Documentation
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Complete system architecture guide (v1.5)
  - System overview and design patterns
  - Tech stack breakdown with justifications
  - Security architecture and best practices
  - API architecture and conventions
  - Frontend patterns and state management
  - Database schema and migrations
  - Build and deployment guides

### Additional Resources
- **[docs/](docs/)** - Complete documentation index
  - **[docs/deployment/](docs/deployment/)** - Deployment guides and troubleshooting
  - **[docs/development/](docs/development/)** - Contributing guidelines, setup, and security audits
  - **[docs/features/](docs/features/)** - Feature documentation (SEO, newsletters)
  - **[docs/releases/](docs/releases/)** - Release notes and changelogs
  - **[docs/setup/](docs/setup/)** - Analytics and AdSense setup guides

---

## Support

- **Documentation**: Check [ARCHITECTURE.md](ARCHITECTURE.md), this README, and the [docs/](docs/) folder
- **API Docs**: Interactive docs at `/docs` when running the backend
- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/andynaisbitt/Fast-React-CMS/issues)
- **Discussions**: Ask questions and share ideas on [GitHub Discussions](https://github.com/andynaisbitt/Fast-React-CMS/discussions)
- **Contributors Welcome**: See [docs/development/CONTRIBUTING.md](docs/development/CONTRIBUTING.md) - help improve OSS standards!

---

**Ready to build something amazing?** Get started with the [Quick Start](#quick-start) guide above!

Happy blogging!
