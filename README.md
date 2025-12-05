# FastReactCMS

> **A modern, production-ready blog and CMS platform built for developers who want to ship fast without sacrificing control.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-18.x-61dafb.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://www.typescriptlang.org/)
[![Security: A+](https://img.shields.io/badge/Security-A%2B-success.svg)](SECURITY_AUDIT_REPORT.md)

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

## Features

FastReactCMS combines the best of modern web development with a developer-first approach:

### Core Features
- **Modern Tech Stack** - React 18 + TypeScript + FastAPI + PostgreSQL
- **Lightning Fast** - Vite builds, optimized queries, and smart caching
- **SEO Optimized** - Built-in meta tags, RSS feeds, sitemaps, and schema markup
- **Dynamic Pages** - Modular block system for building custom pages without code
- **Theme Customization** - Real-time color and typography controls
- **Dark Mode** - Beautiful dark theme across the entire platform
- **Mobile-First** - Responsive design that works on every device

### Content Management
- **Rich Blog Editor** - Markdown support, image uploads, and SEO optimization
- **Category & Tag System** - Organize content with unlimited categories and tags
- **Draft System** - Save and publish content when ready
- **Media Library** - Image upload and management
- **Comment System** - Built-in commenting (optional per post)

### Security & Performance
- **HTTP-Only Cookies** - JWT tokens never exposed to JavaScript (XSS protection)
- **CSRF Protection** - Token-based protection on all state-changing requests
- **bcrypt Password Hashing** - Industry-standard password security
- **Rate Limiting** - Brute force protection on authentication
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
chmod +x setup-postgres.sh
./setup-postgres.sh
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

```
FastReactCMS/
├── Backend/
│   ├── alembic/              # Database migrations
│   ├── app/
│   │   ├── api/v1/           # API endpoints and services
│   │   │   ├── endpoints/    # Route handlers
│   │   │   ├── schemas/      # Pydantic schemas
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
├── Frontend/
│   ├── src/
│   │   ├── components/       # React components
│   │   │   ├── Admin/        # Admin panel components
│   │   │   ├── Blog/         # Blog components
│   │   │   ├── Layout/       # Layout components
│   │   │   └── Pages/        # Dynamic page components
│   │   ├── pages/            # Page-level components
│   │   ├── services/         # API clients
│   │   ├── state/            # Context providers
│   │   ├── hooks/            # Custom React hooks
│   │   ├── utils/            # Utility functions
│   │   └── types/            # TypeScript type definitions
│   ├── .env.example          # Frontend environment template
│   ├── package.json          # NPM dependencies
│   └── vite.config.ts        # Vite configuration
├── .gitignore                # Git exclusions
├── SECURITY_AUDIT_REPORT.md  # Security audit results
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

### Customizing Your Theme

1. Go to `/admin/settings/site`
2. Configure:
   - **General**: Site name, tagline, logo
   - **Theme**: Colors (light/dark mode), typography
   - **Navigation**: Menu items, dropdowns
   - **SEO**: Default meta tags, social sharing
   - **Integrations**: Google Analytics, AdSense

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
> See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive production deployment instructions including:
> - Google Cloud VM setup
> - Domain & DNS configuration (with/without Cloudflare)
> - PostgreSQL installation and tuning
> - NGINX reverse proxy with SSL
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

See our [Security Audit Report](SECURITY_AUDIT_REPORT.md) for detailed security guidance.

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

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

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

See our complete [Security Audit Report](SECURITY_AUDIT_REPORT.md) for details.

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead:
1. Contact the maintainers privately
2. Provide detailed information about the vulnerability
3. Allow 48 hours for initial response

We take all security reports seriously and will respond promptly.

---

## Roadmap

### ✅ v1.0 (Current - Production Ready)
- ✅ Blog system with categories and tags
- ✅ Dynamic page builder with modular blocks
- ✅ Theme customization (colors, typography, navigation)
- ✅ SEO optimization (meta tags, slugs, RSS feeds)
- ✅ Admin panel with content management
- ✅ User authentication (JWT + HTTP-only cookies)
- ✅ Security hardening (CSRF, bcrypt, rate limiting)
- ✅ Google Analytics & AdSense integration ready
- ✅ Responsive design (mobile/tablet/desktop)
- ✅ Dark mode support
- ✅ Image upload and management
- ✅ Markdown support for content

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
- Newsletter subscription system
- Search functionality (full-text PostgreSQL)
- Content versioning and revisions

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

## Support

- **Documentation**: Check this README and inline code documentation
- **API Docs**: Interactive docs at `/docs` when running the backend
- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/andynaisbitt/Fast-React-CMS/issues)
- **Discussions**: Ask questions and share ideas on [GitHub Discussions](https://github.com/andynaisbitt/Fast-React-CMS/discussions)

---

**Ready to build something amazing?** Get started with the [Quick Start](#quick-start) guide above!

Happy blogging!
