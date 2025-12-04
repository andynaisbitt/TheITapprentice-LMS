# BlogCMS - Setup Guide

Complete setup instructions for local development and production deployment.

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.10+** (Backend)
- **Node.js 18+** (Frontend)
- **PostgreSQL 14+** (Database)
- **Git** (Version control)

---

## 🚀 Quick Start (5 Minutes)

### Step 1: Clone and Setup

```bash
# Navigate to project
cd BlogCMS

# Create .env files
cp Backend/.env.example Backend/.env
cp Frontend/.env.example Frontend/.env
```

### Step 2: Database Setup

```bash
# Create PostgreSQL database
createdb blogcms_db

# Or using psql:
psql -U postgres
CREATE DATABASE blogcms_db;
\q
```

### Step 3: Backend Setup

```bash
cd Backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Create admin user
python scripts/create_admin.py

# Start backend server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

**Backend should now be running at:** http://localhost:8100

### Step 4: Frontend Setup

```bash
# Open a new terminal
cd Frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

**Frontend should now be running at:** http://localhost:5173

### Step 5: Login

1. Open http://localhost:5173/login
2. Use default credentials:
   - Email: `admin@blogcms.local`
   - Password: `change-this-password`
3. **IMPORTANT:** Change this password immediately!

---

## 🔧 Detailed Configuration

### Backend Configuration

Edit `Backend/.env`:

```env
# Database (REQUIRED)
DATABASE_URL=postgresql://blogcms_user:your_password@localhost/blogcms_db

# Security (REQUIRED - Generate new key!)
SECRET_KEY=your-secret-key-here

# CORS (REQUIRED - Must match frontend URL)
CORS_ORIGINS=["http://localhost:5173"]

# Cookie Settings
COOKIE_SECURE=false  # true in production with HTTPS
COOKIE_SAMESITE=lax

# Environment
ENVIRONMENT=development
DEBUG=true
```

**Generate a secure SECRET_KEY:**
```bash
openssl rand -hex 32
```

### Frontend Configuration

Edit `Frontend/.env`:

```env
# Must match backend URL exactly
VITE_API_URL=http://localhost:8100
```

**IMPORTANT:** Use `localhost`, NOT `127.0.0.1` (cookies won't work with IP addresses)

---

## 🗄️ Database Management

### Initial Setup

```bash
cd Backend

# Create all tables
alembic upgrade head

# Create admin user
python scripts/create_admin.py
```

### Creating Migrations

```bash
# After changing models in app/users/models.py or app/api/v1/services/blog/models.py
alembic revision --autogenerate -m "Description of changes"

# Apply migration
alembic upgrade head
```

### Reset Database (Development Only)

```bash
# WARNING: This deletes all data!
dropdb blogcms_db
createdb blogcms_db
alembic upgrade head
python scripts/create_admin.py
```

---

## 🎨 Frontend Development

### Available Scripts

```bash
npm run dev      # Start dev server (port 5173)
npm run build    # Build for production
npm run preview  # Preview production build
npm run lint     # Run ESLint
```

### Adding New Pages

1. Create component in `src/pages/`
2. Add route in `src/routes/routes.tsx`
3. Update navigation if needed

### API Integration

All API calls go through `src/services/api/`:

```typescript
// Example: Fetch blog posts
import { blogApi } from '@/services/api';

const posts = await blogApi.getAllPosts();
```

---

## 🛠️ Backend Development

### Available Commands

```bash
# Start server
uvicorn app.main:app --reload

# Run server on different port
uvicorn app.main:app --reload --port 8080

# API documentation (after starting server)
http://localhost:8100/docs      # Swagger UI
http://localhost:8100/redoc     # ReDoc
```

### Adding New API Endpoints

1. Create route in `app/api/v1/endpoints/blog/`
2. Update schemas in `app/api/v1/services/blog/schemas.py`
3. Add CRUD operations in `app/api/v1/services/blog/crud.py`
4. Register router in `app/main.py`

---

## 🔐 Security Checklist

### Development

- [ ] Never commit `.env` files to git
- [ ] Use `localhost` (not `127.0.0.1`) for auth cookies
- [ ] Keep `COOKIE_SECURE=false` for local development

### Production

- [ ] Generate new `SECRET_KEY` with `openssl rand -hex 32`
- [ ] Change default admin password immediately
- [ ] Set `COOKIE_SECURE=true`
- [ ] Set `DEBUG=false`
- [ ] Set `ENVIRONMENT=production`
- [ ] Use HTTPS for all traffic
- [ ] Configure firewall rules
- [ ] Enable rate limiting
- [ ] Set up database backups

---

## 🧪 Testing

### Backend Testing

```bash
cd Backend

# Install test dependencies (if needed)
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Frontend Testing

```bash
cd Frontend

# Build to check for errors
npm run build

# Lint code
npm run lint
```

---

## 📦 Production Build

### Backend

```bash
cd Backend

# Install production dependencies only
pip install -r requirements.txt --no-dev

# Set environment variables
export ENVIRONMENT=production
export DEBUG=false
export COOKIE_SECURE=true

# Run with Gunicorn (recommended)
gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8100
```

### Frontend

```bash
cd Frontend

# Build for production
npm run build

# Output will be in dist/ folder
# Serve with any static hosting (Nginx, Apache, Cloud Storage, etc.)
```

---

## 🚨 Troubleshooting

### Backend Issues

**Error: "Could not connect to database"**
- Check PostgreSQL is running: `pg_ctl status`
- Verify DATABASE_URL in `.env`
- Check database exists: `psql -l | grep blogcms`

**Error: "ModuleNotFoundError"**
- Activate virtual environment: `source venv/bin/activate`
- Reinstall dependencies: `pip install -r requirements.txt`

**Error: "CORS errors in browser"**
- Check CORS_ORIGINS matches frontend URL exactly
- Use `localhost`, not `127.0.0.1`

### Frontend Issues

**Error: "Failed to fetch"**
- Verify backend is running on port 8100
- Check VITE_API_URL in `.env`
- Open browser console for detailed errors

**Error: "Cannot read property of undefined"**
- Clear browser cache and cookies
- Check API response format matches TypeScript types

**Login not working / Cookies not being set**
- Use `localhost` for both frontend and backend (not 127.0.0.1)
- Check CORS_ORIGINS includes frontend URL
- Verify COOKIE_SECURE=false in development

### Database Issues

**Error: "relation does not exist"**
- Run migrations: `alembic upgrade head`
- Check alembic versions: `alembic current`

**Error: "password authentication failed"**
- Check PostgreSQL credentials in DATABASE_URL
- Reset PostgreSQL password if needed

---

## 📚 Additional Resources

### API Documentation
- Swagger UI: http://localhost:8100/docs
- ReDoc: http://localhost:8100/redoc

### File Structure
```
BlogCMS/
├── Backend/           # Python FastAPI backend
│   ├── app/
│   │   ├── core/      # Database, security, config
│   │   ├── auth/      # Authentication
│   │   ├── users/     # User models
│   │   └── api/v1/    # API endpoints
│   ├── scripts/       # Utility scripts
│   ├── requirements.txt
│   └── .env
├── Frontend/          # React TypeScript frontend
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/api/
│   │   └── state/
│   ├── package.json
│   └── .env
└── docs/             # Documentation
```

### Next Steps
- Read `NEXT_STEPS.md` for deployment guide
- Check `README.md` for feature overview
- Review `ACTION_PLAN.md` for customization ideas

---

**Need help?** Check the troubleshooting section above or review backend logs for detailed error messages.
