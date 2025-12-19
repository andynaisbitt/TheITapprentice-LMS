# FastReactCMS

> **A modern, production-ready blog and CMS platform built for developers who want to ship fast without sacrificing control.**

[![Version](https://img.shields.io/badge/Version-1.6-brightgreen.svg)](https://github.com/andynaisbitt/Fast-React-CMS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-18.x-61dafb.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://www.typescriptlang.org/)
[![Security: A+](https://img.shields.io/badge/Security-A%2B-success.svg)](docs/development/SECURITY_AUDIT_REPORT.md)
[![Contributors Welcome](https://img.shields.io/badge/Contributors-Welcome-orange.svg)](docs/development/CONTRIBUTING.md)

---

## Screenshots

<img width="800" alt="Admin Dashboard" src="https://github.com/user-attachments/assets/a913dc86-a4be-4d4e-936c-e1e31dba9466" />

<img width="800" alt="Blog Editor with Markdown Preview" src="https://github.com/user-attachments/assets/4acd5dc2-c74a-42de-b979-07f41a2b9d26" />

<img width="800" alt="Theme Customization + Dark Mode" src="https://github.com/user-attachments/assets/88b1ea6d-606d-4dd3-ab1f-febf2d061217" />

<img width="800" alt="Dynamic Page Builder" src="https://github.com/user-attachments/assets/652cc3ea-f0ad-4e32-bccc-f64caf65bf89" />

<img width="800" alt="Category & Tag Management" src="https://github.com/user-attachments/assets/21261c28-0e3e-4624-8a4f-610349c08ca7" />


**Want to contribute screenshots?** Fork the repo, take screenshots, and submit a PR!

---

## ✨ What's New in v1.6 (December 19, 2025)

FastReactCMS v1.6 brings **critical security hardening** and comprehensive vulnerability fixes:

🔒 **Security Score: C → A+ (98/100)** - Eliminated all 5 critical/high vulnerabilities identified in penetration testing
🛡️ **SQL Injection Protection** - Triple-layer defense with API validation, input sanitization, and ORM parameterization
🚫 **DoS Protection** - Added content length limits (5MB) and array size limits (1000 elements) to prevent resource exhaustion
🖼️ **Decompression Bomb Protection** - Dimension checks prevent malicious images from consuming server memory
🔐 **Null Byte Sanitization** - Fixed path traversal vulnerability in file upload system
📋 **OWASP Compliance** - 90% OWASP TOP 10 (2021) compliance achieved
✅ **215+ Security Tests** - Comprehensive test suite with 100% pass rate

**Previous Release (v1.5):**
🎯 State Management Upgrade • 📚 Documentation Overhaul • 🏗️ Production Battle-Tested

> **Calling Contributors!** This project is actively seeking contributors to help improve code quality, documentation, and OSS best practices. Check out [CONTRIBUTING.md](docs/development/CONTRIBUTING.md)!

---

## Features

### Core Features
- **Modern Tech Stack** - React 18 + TypeScript + FastAPI + PostgreSQL
- **Lightning Fast** - Vite builds, optimized queries, and smart caching
- **SEO Optimized** - Canonical URLs, SSR for crawlers, meta tags, RSS feeds, sitemaps, and schema markup
- **Dynamic Pages** - Modular block system for building custom pages without code
- **Theme Customization** - Real-time color and typography controls with dark mode
- **Homepage Builder** - Fully customizable homepage with hero, carousel, categories, and stats sections

### Content Management
- **Rich Blog Editor** - Markdown support, image uploads, and SEO optimization
- **Category & Tag System** - Organize content with unlimited categories and tags
- **Media Library** - Image upload and management with SVG support
- **Newsletter System** - Email subscription and newsletter management
- **Logo & Favicon Upload** - Custom branding with theme-aware light/dark mode support

### Security & Performance
- **HTTP-Only Cookies** - JWT tokens never exposed to JavaScript (XSS protection)
- **CSRF Protection** - Token-based protection on all state-changing requests
- **bcrypt Password Hashing** - Industry-standard password security
- **Rate Limiting** - Brute force protection on authentication
- **SVG XSS Prevention** - Secure SVG upload validation
- **A+ Security Rating** - See our [Security Audit Report](docs/development/SECURITY_AUDIT_REPORT.md)

### Developer Experience
- **Type-Safe** - Full TypeScript coverage
- **API Documentation** - Interactive FastAPI docs at `/docs`
- **Hot Reload** - Fast development with Vite HMR
- **Clean Architecture** - Modular, maintainable codebase
- **Database Migrations** - Alembic for version-controlled schema changes

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
chmod +x deployment/setup-postgres.sh
./deployment/setup-postgres.sh
```

**Manual Setup:** See [docs/development/SETUP.md](docs/development/SETUP.md) for platform-specific instructions (Ubuntu, macOS, Windows).

#### 3. Backend Setup

```bash
cd Backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Edit .env with your database credentials
# Generate secrets: openssl rand -hex 32

# Run database migrations
alembic upgrade head

# Seed initial data
python scripts/create_admin.py
python scripts/seed_categories.py
python scripts/seed_navigation_theme.py
python scripts/seed_pages.py
python scripts/seed_sample_content.py

# Start backend server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

Backend will be running at `http://localhost:8100`

#### 4. Frontend Setup

```bash
cd Frontend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start development server
npm run dev
```

Frontend will be running at `http://localhost:5173`

#### 5. First Login

- Navigate to `http://localhost:5173/admin`
- Login with the admin credentials you created
- Start creating content!

---

## Technology Stack

**Frontend:** React 18 • TypeScript • Vite • Tailwind CSS • React Router • Zustand
**Backend:** FastAPI • SQLAlchemy • PostgreSQL • Pydantic • Alembic
**Security:** HTTP-Only Cookies • CSRF Tokens • bcrypt • Rate Limiting

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for complete tech stack details.

---

## Project Structure

> **Note:** Current directory names use capital letters (`Backend/`, `Frontend/`). These will be migrated to lowercase (`backend/`, `frontend/`) in a future update to follow OSS conventions.

```
FastReactCMS/
├── Backend/                  # Python FastAPI backend
│   ├── app/                  # Application code
│   ├── alembic/              # Database migrations
│   ├── scripts/              # Utility scripts
│   └── static/               # Static files and uploads
├── Frontend/                 # React TypeScript frontend
│   ├── src/
│   │   ├── components/       # React components
│   │   ├── pages/            # Page-level components
│   │   ├── store/            # Zustand state management
│   │   ├── services/         # API clients
│   │   └── types/            # TypeScript definitions
├── deployment/               # Deployment configs and scripts
├── docs/                     # Documentation
│   ├── ARCHITECTURE.md       # System architecture guide
│   ├── deployment/           # Deployment guides
│   ├── development/          # Contributing, setup, security
│   ├── features/             # Feature documentation
│   └── releases/             # Release notes
├── .gitignore
├── LICENSE
└── README.md
```

---

## Configuration

### Backend Environment Variables

Key variables in `Backend/.env`:

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

See `Backend/.env.example` for all options.

### Frontend Environment Variables

Key variables in `Frontend/.env`:

```env
VITE_API_URL=http://localhost:8100  # Must match backend
```

---

## Production Deployment

> **📖 Complete Deployment Guide:** [docs/deployment/DEPLOYMENT.md](docs/deployment/DEPLOYMENT.md)

### Before Deploying

1. **Generate Strong Secrets**: `openssl rand -hex 32`
2. **Update Environment Variables**: Set `COOKIE_SECURE=true`, `ENVIRONMENT=production`
3. **Enable HTTPS**: Required for secure cookies
4. **Update CORS Origins**: Add your production domain(s)
5. **Configure Database Backups**: Automate with cron or cloud services

See our [Security Audit Report](docs/development/SECURITY_AUDIT_REPORT.md) for detailed security guidance.

### Build for Production

**Frontend:**
```bash
cd Frontend
npm run build  # Output in Frontend/dist/
```

**Backend:**
```bash
cd Backend
gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8100
```

**Deployment Options:** VPS (DigitalOcean, AWS EC2) • PaaS (Heroku, Railway) • Docker • Serverless

---

## API Documentation

Interactive API documentation is available when running the backend:

- **Swagger UI**: `http://localhost:8100/docs`
- **ReDoc**: `http://localhost:8100/redoc`

**Key Endpoints:**
- `POST /auth/login` - Login with credentials
- `GET /api/v1/blog/posts` - List blog posts (paginated)
- `POST /api/v1/blog/posts` - Create post (admin)
- `GET /api/v1/pages/{slug}` - Get single page

---

## Contributing

We welcome contributions! Please see [docs/development/CONTRIBUTING.md](docs/development/CONTRIBUTING.md) for guidelines.

**Development Workflow:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Commit: `git commit -m 'Add amazing feature'`
5. Push and open a Pull Request

**Code Style:**
- Frontend: ESLint + Prettier
- Backend: Black + isort
- Commits: Conventional commit format

---

## Roadmap

### ✅ v1.5 (Current - December 15, 2025)

> **Note to the OSS Community:**
> I'm still learning best practices for open-source development! Feedback from Reddit and GitHub has been incredibly helpful. If you see areas for improvement in code standards, documentation, or project structure, please open an issue or PR. 🙏

**What's New in v1.5:**
- ✅ Zustand state management with automatic persistence
- ✅ Pydantic alias automation (eliminated 57 lines of boilerplate)
- ✅ Comprehensive documentation overhaul ([ARCHITECTURE.md](docs/ARCHITECTURE.md))
- ✅ Production hardening (battle-tested with 48-hour incident recovery)
- ✅ Cleaned documentation structure (essential docs only)

**Build Status:** ✅ All builds passing | **Security Rating:** A+ (95/100) | **Bundle Size:** 399.90 kB | **Production:** Battle-tested ✅

**Version History:**
- **v1.5 (12-15 Dec 2025)**: State management, documentation overhaul, production hardening
- **v1.4 (Dec 2025)**: Canonical URLs, SSR, favicon/logo upload, homepage customization, CSP-compliant analytics
- **v1.3 (Dec 2025)**: Newsletter system with subscriber management
- **v1.2 (Dec 2025)**: Mobile UX improvements
- **v1.1 (Dec 2025)**: Production deployment fixes
- **v1.0 (Nov 2025)**: Initial production release

### 📋 Future Enhancements (Community Driven)

FastReactCMS is designed as a **developer-friendly foundation** - not a bloated all-in-one solution.

**Potential community additions:**
- Comment system with moderation
- Advanced media library (image optimization, CDN)
- Content scheduling
- Multi-author support with roles
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
A: Yes! Open source under the MIT License. Use it for personal or commercial projects.

**Q: Can I use this in production?**
A: Absolutely! FastReactCMS is production-ready and has passed comprehensive security audits.

**Q: Do I need to know React and Python?**
A: For basic usage (creating content, customizing themes), no coding is required. For advanced customization, knowledge of React and Python/FastAPI is helpful.

**Q: Can I customize the design?**
A: Yes! The theme system allows extensive customization through the admin panel. For deeper changes, modify the React components and Tailwind CSS.

**Q: Is there a hosted version?**
A: Not currently. FastReactCMS is self-hosted, giving you complete control over your data.

**Q: What databases are supported?**
A: PostgreSQL is recommended and fully tested. SQLite works for development but is not recommended for production.

---

## Documentation & Support

### Documentation
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture guide
- **[docs/deployment/](docs/deployment/)** - Deployment guides and troubleshooting
- **[docs/development/](docs/development/)** - Contributing guidelines, setup, security audits
- **[docs/features/](docs/features/)** - Feature documentation
- **[docs/releases/](docs/releases/)** - Release notes and changelogs

### Support
- **API Docs**: Interactive docs at `/docs` when running the backend
- **Issues**: Report bugs on [GitHub Issues](https://github.com/andynaisbitt/Fast-React-CMS/issues)
- **Discussions**: Ask questions on [GitHub Discussions](https://github.com/andynaisbitt/Fast-React-CMS/discussions)
- **Contributors Welcome**: See [CONTRIBUTING.md](docs/development/CONTRIBUTING.md)

---

## License

FastReactCMS is released under the [MIT License](LICENSE).

Copyright (c) 2025 FastReactCMS Contributors

---

## Acknowledgments

FastReactCMS is built with amazing open-source technologies:

[React](https://reactjs.org/) • [FastAPI](https://fastapi.tiangolo.com/) • [Vite](https://vitejs.dev/) • [Tailwind CSS](https://tailwindcss.com/) • [PostgreSQL](https://www.postgresql.org/) • [SQLAlchemy](https://www.sqlalchemy.org/) • [Alembic](https://alembic.sqlalchemy.org/) • And many more!

---

**Ready to build something amazing?** Get started with the [Quick Start](#quick-start) guide above!

Happy blogging!
