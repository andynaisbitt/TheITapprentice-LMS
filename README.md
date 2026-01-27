# The IT Apprentice LMS

> **A modern Learning Management System for IT apprentices, students, and self-taught developers. Built with React, FastAPI, and a modular plugin architecture.**

[![Version](https://img.shields.io/badge/Version-2.9-brightgreen.svg)](https://github.com/andynaisbitt/TheITapprentice-LMS/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-18.x-61dafb.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://www.typescriptlang.org/)

---

## What is The IT Apprentice LMS?

The IT Apprentice LMS is a full-featured learning platform designed specifically for:

- **IT Apprentices** completing Level 3/4 qualifications
- **Students** learning to code
- **Self-taught developers** building their skills
- **Training providers** delivering IT education

Built on a solid CMS foundation with a **modular plugin system**, it combines content management with interactive learning features.

---

## Key Features

### Learning Management
- **Interactive Tutorials** - Step-by-step coding tutorials with progress tracking
- **Structured Courses** - Multi-lesson courses with enrollment, progress, and completion
- **Quizzes & Assessments** - Multiple question types with scoring and history
- **Skills System** - Granular skill tracking with XP per skill, levels, and leaderboards
- **Typing Game** - Multiple game modes for improving coding speed (see below)
- **XP & Leveling System** - Earn experience points and level up as you learn
- **Achievements** - Unlock badges for completing milestones
- **Activity Tracking** - Full timeline of learning progress
- **Streak System** - Stay motivated with daily learning streaks
- **Leaderboards** - XP leaderboard and skills leaderboard

### Typing Game Modes
- **Quick Brown Fox** - Classic typing test with WPM tracking
- **Infinite Rush** - Endless mode with combo multipliers and streak bonuses
- **Ghost Mode** - Race against your previous best performance
- **PvP Mode** - Real-time typing races against other players
- **Practice Mode** - Focused practice with custom word lists
- **Daily Challenges** - New challenges every day with leaderboard rankings
- **Analytics Dashboard** - Letter accuracy heatmaps, speed trends, detailed stats
- **Anti-Cheat System** - Server-side validation of game results
- **Sound Effects** - Audio feedback with configurable settings

### User Experience
- **Role-Based Dashboards** - Different views for students, tutors, and admins
- **Enhanced Profile Pages** - Stats, achievements, game history, and activity
- **Public Profiles** - View other learners' progress and achievements
- **Dark Mode** - Full dark/light theme support
- **Responsive Mobile Navigation** - Tabbed mobile drawer with swipe-to-close
- **Desktop Dropdown Menus** - Animated navigation with rich dropdowns

### Content Management (CMS Core)
- **Rich Blog Editor** - Markdown support with image uploads
- **Dynamic Pages** - Modular block system for custom pages
- **Category & Tag System** - Organize content effectively
- **Media Manager** - Upload and manage images and files
- **SEO Optimized** - Canonical URLs, meta tags, RSS feeds, sitemaps
- **Theme Customization** - Real-time color and typography controls
- **Newsletter System** - Subscriber management with email campaigns

### Admin Panel
- **Dashboard** - Overview stats and recent activity
- **User Management** - Roles, permissions, XP configuration
- **Content Management** - Blog posts, pages, categories, tags, media
- **LMS Management** - Tutorials, courses, quizzes, skills administration
- **Game Management** - Word lists, sentence pools, challenges, leaderboards
- **Plugin Manager** - Enable/disable plugins
- **System Health** - Server status monitoring
- **Activity Log** - Audit trail of admin actions
- **Analytics** - Site-wide analytics dashboard
- **Navigation Manager** - Configure header and footer navigation
- **Site Settings** - Logo, title, newsletter, widget customization

### Plugin Architecture
The LMS is built on a modular plugin system:

| Plugin | Description |
|--------|-------------|
| **Tutorials** | Interactive coding tutorials with steps, progress tracking, and categories |
| **Courses** | Structured multi-lesson courses with enrollment and completion |
| **Quizzes** | Assessments with multiple question types, scoring, and import |
| **Typing Game** | Speed typing with 6 game modes, analytics, PvP, and anti-cheat |
| **Skills** | Granular skill tracking with XP, levels, badges, and leaderboards |
| **Progress/XP** | Experience points, leveling, achievements, and streaks |

### Security & Performance
- **HTTP-Only Cookies** - JWT tokens never exposed to JavaScript
- **CSRF Protection** - Token-based protection on all requests
- **Rate Limiting** - Brute force protection
- **Google OAuth** - Social login support
- **A+ Security Rating** - Comprehensive security hardening
- **Input Validation** - Pydantic v2 schemas on all endpoints

---

## Tech Stack

**Frontend:**
- React 18 + TypeScript
- Vite (lightning-fast builds)
- Tailwind CSS
- Zustand (state management)
- Framer Motion (animations)
- React Router v6
- Lucide React (icons)

**Backend:**
- FastAPI (Python)
- SQLAlchemy + PostgreSQL
- Alembic (migrations)
- Pydantic v2

**Infrastructure:**
- SSR for SEO (crawler detection)
- Google OAuth integration
- Newsletter system
- Analytics support

---

## Quick Start

### Prerequisites

- **Python 3.10+** with pip
- **Node.js 18+** with npm
- **PostgreSQL 14+**

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/andynaisbitt/TheITapprentice-LMS.git
cd TheITapprentice-LMS
```

#### 2. Backend Setup
```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env
# Edit .env with your database credentials

# Run database migrations
alembic upgrade head

# Create admin user
python scripts/create_admin.py

# Seed initial data
python scripts/seed_categories.py
python scripts/seed_navigation_theme.py
python scripts/seed_pages.py

# Start backend server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

#### 3. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start development server
npm run dev
```

#### 4. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8100
- **API Docs**: http://localhost:8100/docs

---

## Project Structure

```
TheITapprentice-LMS/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── api/               # REST API endpoints
│   │   ├── plugins/           # Plugin modules
│   │   │   ├── tutorials/     # Tutorial system
│   │   │   ├── typing_game/   # Typing game (6 modes + analytics)
│   │   │   ├── courses/       # Course system
│   │   │   ├── quizzes/       # Quiz & assessment system
│   │   │   ├── skills/        # Skills tracking system
│   │   │   ├── progress/      # XP & achievements
│   │   │   └── shared/        # Shared XP service
│   │   ├── users/             # User management
│   │   └── core/              # Config, security
│   ├── alembic/               # Database migrations
│   └── scripts/               # Utility scripts
├── frontend/                   # React frontend
│   ├── src/
│   │   ├── components/        # Shared components
│   │   │   ├── admin/         # Admin components
│   │   │   ├── home/          # Homepage sections
│   │   │   ├── layout/        # Header, Footer, MobileNav
│   │   │   └── ui/            # Reusable UI (Toast, ConfirmDialog)
│   │   ├── pages/             # Page components
│   │   │   ├── admin/         # Admin dashboard pages
│   │   │   └── user/          # User dashboard & profile
│   │   ├── plugins/           # Plugin UI components
│   │   │   ├── tutorials/     # Tutorial UI
│   │   │   ├── typing-game/   # Typing game UI (6 modes)
│   │   │   ├── courses/       # Course UI
│   │   │   ├── quizzes/       # Quiz UI
│   │   │   ├── skills/        # Skills UI
│   │   │   └── shared/        # XP, achievements, etc.
│   │   ├── services/          # API clients
│   │   ├── store/             # Zustand stores
│   │   └── routes/            # React Router config
├── docs/                       # Documentation
│   ├── deployment/            # Deployment guides
│   ├── development/           # Development guides
│   ├── releases/              # Release notes
│   ├── security/              # Security reports
│   └── setup/                 # Setup guides (OAuth, Analytics, AdSense)
└── archive/                    # Archived planning docs
```

---

## User Roles

| Role | Access |
|------|--------|
| **Admin** | Full access, user management, content creation, all admin panels |
| **Tutor** | Create tutorials, view student progress |
| **Author** | Create and manage blog posts |
| **Apprentice** | Access learning content, track progress, play games |

---

## Configuration

### Backend Environment (.env)

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/itapprentice

# Security (generate with: openssl rand -hex 32)
SECRET_KEY=your-secret-key
CSRF_SECRET_KEY=your-csrf-secret

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret

# Production
ENVIRONMENT=development
COOKIE_SECURE=false  # true in production
```

### Frontend Environment (.env)

```env
VITE_API_URL=http://localhost:8100
VITE_GOOGLE_CLIENT_ID=your-client-id
```

---

## API Documentation

Interactive API documentation available at:

- **Swagger UI**: http://localhost:8100/docs
- **ReDoc**: http://localhost:8100/redoc

### Key Endpoints

**Authentication:**
- `POST /auth/login` - Login
- `POST /auth/register` - Register new user
- `POST /auth/google` - Google OAuth

**Progress System:**
- `GET /progress/xp/me` - Get user's XP and level
- `GET /progress/achievements` - Get user's achievements
- `GET /progress/activities/me` - Get activity timeline

**Tutorials:**
- `GET /api/v1/tutorials` - List tutorials
- `POST /api/v1/tutorials/{id}/start` - Start a tutorial
- `POST /api/v1/tutorials/{id}/steps/{step}/complete` - Complete step

**Courses:**
- `GET /api/v1/courses` - List courses
- `POST /api/v1/courses/{id}/enroll` - Enroll in a course
- `GET /api/v1/courses/{id}/progress` - Get course progress

**Quizzes:**
- `GET /api/v1/quizzes` - List quizzes
- `POST /api/v1/quizzes/{id}/submit` - Submit quiz answers
- `GET /api/v1/quizzes/history` - Get quiz history

**Skills:**
- `GET /api/v1/skills` - List all skills
- `GET /api/v1/skills/{slug}` - Get skill detail with user progress
- `GET /api/v1/skills/leaderboard` - Skills leaderboard

**Typing Game:**
- `GET /api/v1/games/typing/word-lists` - Get word lists
- `POST /api/v1/games/typing/start` - Start game session
- `POST /api/v1/games/typing/submit` - Submit game results
- `GET /api/v1/games/typing/stats/me` - Get typing stats
- `GET /api/v1/games/typing/analytics` - Get detailed analytics
- `GET /api/v1/games/typing/daily-challenge` - Get daily challenge

---

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend lint
cd frontend
npm run lint
```

### Database Migrations

```bash
cd backend

# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

---

## Deployment

See [docs/deployment/DEPLOYMENT.md](docs/deployment/DEPLOYMENT.md) for full deployment guide.

### Quick Production Checklist

1. Set `ENVIRONMENT=production`
2. Set `COOKIE_SECURE=true`
3. Generate strong secrets for `SECRET_KEY` and `CSRF_SECRET_KEY`
4. Configure HTTPS
5. Set up PostgreSQL backups
6. Configure Google OAuth for production domain

---

## Contributing

Contributions are welcome! Please see [docs/development/CONTRIBUTING.md](docs/development/CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push and open a Pull Request

---

## Roadmap

### Current (v2.9)
- Interactive tutorials with progress tracking
- Structured courses with enrollment and completion
- Quizzes and assessments with multiple question types
- Skills system with per-skill XP and leaderboards
- Typing game with 6 modes (Quick Fox, Infinite Rush, Ghost, PvP, Practice, Daily Challenge)
- Typing analytics with letter accuracy heatmaps
- Anti-cheat system for game results
- XP, achievement, and streak systems
- Enhanced admin panel with 15+ management pages
- Redesigned homepage with feature showcase
- Responsive mobile navigation

### Planned
- Certificates of completion
- Course prerequisites and learning paths
- Code playground integration
- Collaborative features

---

## License

The IT Apprentice LMS is released under the [MIT License](LICENSE).

---

## Acknowledgments

Built with:
- [React](https://reactjs.org/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Vite](https://vitejs.dev/)
- [Tailwind CSS](https://tailwindcss.com/)
- [PostgreSQL](https://www.postgresql.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [Lucide Icons](https://lucide.dev/)

Originally forked from [FastReactCMS](https://github.com/andynaisbitt/Fast-React-CMS).

---

**Ready to start learning?** Follow the [Quick Start](#quick-start) guide above!
