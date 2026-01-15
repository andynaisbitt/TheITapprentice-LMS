# The IT Apprentice LMS - Architecture Documentation

**Last Updated:** 2025-01-15
**Version:** 2.0
**Status:** Production

---

## System Overview

The IT Apprentice LMS is a modern, full-stack Learning Management System built on a CMS foundation with React + FastAPI. It features a modular plugin architecture for tutorials, typing games, XP/achievements, and courses.

### Core Philosophy
- **SEO-First**: Server-side rendering for crawlers, optimized meta tags, canonical URLs
- **Performance**: Code splitting, lazy loading, CDN-ready
- **Security**: CSRF protection, JWT auth, input sanitization, CSP-compliant
- **Maintainability**: TypeScript, Pydantic validation, centralized state management

---

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         NGINX                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • SSL Termination (Let's Encrypt)                   │   │
│  │  • Rate Limiting (API: 10/s, Login: 5/min)          │   │
│  │  • Static File Caching (1 year for assets)          │   │
│  │  • Crawler Detection → SSR Server                    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↓          ↓          ↓
         ┌────────────────┴──────────┴──────────┴────────────┐
         │                                                     │
    ┌────▼────┐         ┌────────▼────────┐         ┌───────▼─────┐
    │   SPA   │         │   SSR Server    │         │  API Server │
    │ (React) │         │   (Node.js)     │         │  (FastAPI)  │
    │ Port: - │         │   Port: 3001    │         │ Port: 8100  │
    └─────────┘         └─────────────────┘         └──────┬──────┘
         │                       │                          │
         │                       │                          │
         └───────────────────────┴──────────────────────────┘
                                 ↓
                        ┌────────────────┐
                        │   PostgreSQL   │
                        │   Port: 5432   │
                        └────────────────┘
```

---

## 📂 Project Structure

```
FastReactCMS/
├── Backend/          # Python/FastAPI backend (rename to backend/ in Phase 3)
│   ├── alembic/             # Database migrations
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/   # API route handlers
│   │   │   └── services/    # Business logic + schemas
│   │   ├── auth/            # Authentication (JWT, OAuth)
│   │   ├── core/            # Config, database, security
│   │   └── users/           # User models
│   ├── scripts/             # Seed data scripts
│   ├── static/              # User uploads (blog images)
│   └── requirements.txt
│
├── Frontend/         # React/TypeScript frontend (rename to frontend/ in Phase 3)
│   ├── public/              # Static assets (favicon, ads.txt)
│   ├── src/
│   │   ├── components/      # React components
│   │   │   ├── Blog/        # Blog-specific components
│   │   │   ├── Pages/       # Dynamic page blocks
│   │   │   ├── analytics/   # Google Analytics, AdSense
│   │   │   ├── home/        # Homepage sections
│   │   │   └── layout/      # Header, Footer, Layout
│   │   ├── contexts/        # React Context providers (Theme)
│   │   ├── hooks/           # Custom React hooks
│   │   ├── pages/           # Route components
│   │   │   ├── admin/       # Admin dashboard pages
│   │   │   └── blog/        # Public blog pages
│   │   ├── routes/          # React Router configuration
│   │   ├── services/api/    # API client functions
│   │   ├── state/           # Auth context
│   │   ├── store/           # Zustand stores (Phase 1 refactor)
│   │   └── utils/           # Helper functions
│   ├── server.js            # SSR server (crawler detection)
│   └── package.json
│
├── deployment/       # Deployment scripts and configs
│   ├── nginx.conf           # Production nginx config
│   ├── fastreactcms-ssr.service  # Systemd service for SSR
│   └── setup-*.sh           # Setup scripts
│
└── docs/            # Documentation
    ├── INDEX.md             # Documentation index
    ├── setup/               # Setup guides
    ├── deployment/          # Deployment guides
    ├── features/            # Feature documentation
    └── releases/            # Release notes
```

---

## 🔧 Technology Stack

### Frontend
| Technology | Version | Purpose |
|------------|---------|---------|
| **React** | 18.x | UI framework |
| **TypeScript** | 5.x | Type safety |
| **Vite** | 5.x | Build tool |
| **TailwindCSS** | 3.x | Styling |
| **Framer Motion** | 11.x | Animations |
| **React Router** | 6.x | Routing |
| **React Helmet** | 6.x | SEO meta tags |
| **Zustand** | 4.x | State management (Phase 1 refactor) |
| **Lucide React** | - | Icons |

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.10+ | Language |
| **FastAPI** | 0.109+ | Web framework |
| **Pydantic** | 2.x | Data validation + serialization |
| **SQLAlchemy** | 2.x | ORM |
| **Alembic** | 1.x | Database migrations |
| **PostgreSQL** | 14+ | Database |
| **Passlib** | - | Password hashing (bcrypt) |
| **python-jose** | - | JWT tokens |

### Infrastructure
| Technology | Purpose |
|------------|---------|
| **NGINX** | Reverse proxy, SSL, rate limiting |
| **Let's Encrypt** | SSL certificates |
| **Systemd** | Process management |
| **Google Cloud VM** | Hosting (e2-medium) |
| **Cloudflare** | CDN, DDoS protection (optional) |

---

## 🔐 Security Architecture

### Authentication Flow
```
1. User submits login credentials
   ↓
2. Backend validates against PostgreSQL (bcrypt)
   ↓
3. Generate JWT token (HS256)
   ↓
4. Set HTTP-only cookie + CSRF token
   ↓
5. Frontend stores CSRF token in localStorage
   ↓
6. All API requests include:
   - Cookie (JWT - auto-sent)
   - X-CSRF-Token header (from localStorage)
   ↓
7. Backend validates both before processing
```

### Security Features
- ✅ **CSRF Protection**: Double-submit cookie pattern
- ✅ **XSS Prevention**: HTML entity escaping in SSR
- ✅ **SQL Injection**: SQLAlchemy parameterized queries
- ✅ **Rate Limiting**: NGINX-level (10 req/s API, 5 req/min login)
- ✅ **JWT Tokens**: HS256, HTTP-only cookies, 1-day expiry
- ✅ **Password Hashing**: bcrypt with salt
- ✅ **SVG Upload Validation**: XML parsing to block dangerous tags
- ✅ **CSP Compliance**: All scripts use nonce or allowlist

### Environment Variables (Required)
```bash
# Backend/.env
SECRET_KEY=<32-char-hex>          # JWT signing
CSRF_SECRET_KEY=<32-char-hex>     # CSRF token signing
DATABASE_URL=postgresql://...      # Database connection
ADMIN_EMAIL=admin@domain.com       # Initial admin
ADMIN_PASSWORD=<strong-password>   # Initial admin password
COOKIE_SECURE=true                 # Production only
ENVIRONMENT=production             # production/development
```

---

## 📡 API Architecture

### RESTful Endpoints

#### Public API
```
GET  /api/v1/blog/posts           # List blog posts (paginated)
GET  /api/v1/blog/posts/:id       # Get single post
GET  /api/v1/blog/categories      # List categories
GET  /api/v1/site-settings         # Get site settings
GET  /api/v1/navigation           # Get navigation menu
GET  /api/v1/theme                # Get theme config
GET  /api/v1/pages/:slug          # Get dynamic page
POST /api/v1/newsletter/subscribe # Newsletter subscription
GET  /api/v1/rss.xml              # RSS feed
GET  /api/v1/sitemap.xml          # Sitemap
```

#### Admin API (Auth Required)
```
POST   /api/v1/blog/posts             # Create post
PUT    /api/v1/blog/posts/:id         # Update post
DELETE /api/v1/blog/posts/:id         # Delete post
POST   /api/v1/blog/media             # Upload image
PUT    /api/v1/site-settings           # Update settings
PUT    /api/v1/navigation             # Update nav menu
PUT    /api/v1/theme                  # Update theme
POST   /api/v1/pages                  # Create page
PUT    /api/v1/pages/:id              # Update page
DELETE /api/v1/pages/:id              # Delete page
```

### Data Flow (Example: Blog Post)

```python
# 1. HTTP Request
GET /api/v1/blog/posts/123

# 2. Route Handler (endpoints/blog/public.py)
@router.get("/posts/{post_id}")
async def get_post(post_id: int, db: Session = Depends(get_db)):
    return await blog_crud.get_post(db, post_id)

# 3. CRUD Layer (services/blog/crud.py)
def get_post(db: Session, post_id: int) -> BlogPost:
    return db.query(BlogPost).filter(BlogPost.id == post_id).first()

# 4. Pydantic Serialization (services/blog/schemas.py)
class BlogPostResponse(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,  # snake_case → camelCase
        from_attributes=True        # ORM → Pydantic
    )
    id: int
    title: str
    slug: str
    # ... (Phase 2 refactor: auto snake_case → camelCase)

# 5. JSON Response (camelCase)
{
  "id": 123,
  "title": "My Post",
  "slug": "my-post",
  "createdAt": "2025-12-12T10:00:00Z"
}
```

---

## 🎨 Frontend Architecture

### State Management (Post Phase 1 Refactor)

```typescript
// Before (Phase 0): Scattered useState hooks
const [settings, setSettings] = useState<SiteSettings>({});
const [isLoading, setIsLoading] = useState(true);
// ... duplicated across 45+ components

// After (Phase 1): Centralized Zustand store
import { useSiteSettingsStore } from '@/store';

// Option 1: Hook wrapper (backward compatible)
const { settings, isLoading } = useSiteSettings();

// Option 2: Direct store access (recommended)
const settings = useSiteSettingsStore((state) => state.settings);
const loadSettings = useSiteSettingsStore((state) => state.loadSettings);
```

### Store Structure
```typescript
// Frontend/src/store/useSiteSettingsStore.ts
interface SiteSettingsStore {
  // State
  settings: SiteSettings;
  isLoading: boolean;
  error: string | null;

  // Actions
  loadSettings: () => Promise<void>;
  updateSettings: (updates: Partial<SiteSettings>) => void;
  resetSettings: () => Promise<void>;
}

// Features:
// ✅ Redux DevTools integration
// ✅ localStorage persistence (blogcms_settings key)
// ✅ Automatic API calls
// ✅ TypeScript autocomplete
```

### Component Patterns

#### Smart vs Presentational Components
```typescript
// Smart Component (pages/admin/BlogEditor.tsx)
export const BlogEditor: React.FC = () => {
  const [post, setPost] = useState<BlogPost | null>(null);
  const { id } = useParams();

  useEffect(() => {
    // Load data, handle business logic
    loadPost(id);
  }, [id]);

  return <BlogEditorForm post={post} onSave={handleSave} />;
};

// Presentational Component (components/Blog/BlogEditorForm.tsx)
interface Props {
  post: BlogPost | null;
  onSave: (post: BlogPost) => void;
}

export const BlogEditorForm: React.FC<Props> = ({ post, onSave }) => {
  // Pure UI, no business logic
  return <form>...</form>;
};
```

---

## 🚀 Build & Deployment

### Development
```bash
# Backend
cd Backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8100

# Frontend
cd Frontend
npm install
npm run dev  # Starts on port 5173

# SSR Server (for testing crawlers)
cd Frontend
node server.js  # Starts on port 3001
```

### Production Build
```bash
# Frontend
cd Frontend
npm run build
# Output: Frontend/dist/

# Backend
cd Backend
source venv/bin/activate
gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 127.0.0.1:8100
```

### Deployment Flow
```
1. git push origin master
   ↓
2. SSH to production server
   ↓
3. git pull origin master
   ↓
4. Backend:
   - source venv/bin/activate
   - pip install -r requirements.txt
   - alembic upgrade head
   - sudo systemctl restart fastreactcms
   ↓
5. Frontend:
   - npm install
   - npm run build
   - (NGINX serves from dist/)
   ↓
6. SSR Server:
   - sudo systemctl restart fastreactcms-ssr
   ↓
7. NGINX:
   - sudo nginx -t
   - sudo systemctl reload nginx
   ↓
8. Verify:
   - curl -I https://theitapprentice.com
   - Check logs: journalctl -u fastreactcms -f
```

---

## 🔍 SEO Architecture

### Crawler Detection
```javascript
// Frontend/server.js (SSR)
const crawlerUserAgents = [
  /googlebot/i, /bingbot/i, /slurp/i,
  /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i
];

if (crawlerUserAgents.some(ua => ua.test(userAgent))) {
  // Serve SSR HTML with meta tags injected
  return renderWithMetaTags(url);
} else {
  // Serve React SPA
  return serveReactApp();
}
```

### Meta Tag Injection (SSR)
```javascript
// Fetch post data from API
const post = await fetch(`http://localhost:8100/api/v1/blog/posts/${id}`);

// Inject into HTML template
const html = indexHtml
  .replace('<title>FastReactCMS</title>',
    `<title>${escapeHtml(post.title)} | ${escapeHtml(siteTitle)}</title>`)
  .replace('<!-- META_DESCRIPTION -->',
    `<meta name="description" content="${escapeHtml(post.excerpt)}">`);

// Security: escapeHtml prevents XSS
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
```

---

## 📊 Performance Optimizations

### Frontend
- ✅ **Code Splitting**: React.lazy() + Suspense for routes
- ✅ **Lazy Loading**: Images with IntersectionObserver
- ✅ **Bundle Size**: 400 kB gzipped (main bundle)
- ✅ **Caching**: 1-year cache for static assets
- ✅ **Minification**: Vite production build
- ✅ **Tree Shaking**: Unused code eliminated
- ✅ **Image Optimization**: WebP format, responsive sizing

### Backend
- ✅ **Database Indexing**: id, slug, created_at, category_id
- ✅ **Connection Pooling**: SQLAlchemy default pool
- ✅ **Query Optimization**: N+1 query prevention with joinedload()
- ✅ **Caching**: Metadata cached in Redis (future enhancement)

### NGINX
- ✅ **Gzip Compression**: Level 6 for text/html, text/css, application/json
- ✅ **Static File Caching**: 1 year for JS/CSS/images
- ✅ **HTTP/2**: Enabled
- ✅ **Keep-Alive**: 32 connections

---

## 🧪 Testing Strategy

### Unit Tests (Future Enhancement)
```python
# Backend
pytest Backend/tests/

# Frontend
npm run test
```

### Manual Testing Checklist
- [ ] Blog post CRUD operations
- [ ] SEO meta tags (view source)
- [ ] Mobile responsiveness
- [ ] Dark/light theme toggle
- [ ] Newsletter subscription
- [ ] Admin authentication
- [ ] Image upload
- [ ] SSR for crawlers (curl with User-Agent)

---

## 📈 Monitoring & Logging

### Application Logs
```bash
# Backend
sudo journalctl -u fastreactcms -f

# SSR Server
sudo journalctl -u fastreactcms-ssr -f

# NGINX
sudo tail -f /var/log/nginx/theitapprentice.error.log
sudo tail -f /var/log/nginx/theitapprentice.access.log
```

### Key Metrics to Monitor
- **Response Time**: < 200ms (API), < 1s (page load)
- **Error Rate**: < 1% (4xx/5xx responses)
- **Database Connections**: < 50 active
- **Memory Usage**: < 2 GB (backend)
- **Disk Space**: > 20% free

---

## 🔄 Database Schema

### Core Tables

```sql
-- Blog Posts
CREATE TABLE blog_posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    content TEXT,
    excerpt TEXT,
    featured_image VARCHAR(255),
    category_id INTEGER REFERENCES categories(id),
    published BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Categories
CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    icon VARCHAR(50)
);

-- Site Settings (Single Row)
CREATE TABLE site_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,
    site_title VARCHAR(100),
    google_analytics_id VARCHAR(50),
    google_adsense_client_id VARCHAR(50),
    -- ... (50+ fields for homepage customization)
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Users (Admin)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Newsletter Subscribers
CREATE TABLE newsletter_subscribers (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    subscribed_at TIMESTAMP DEFAULT NOW(),
    unsubscribed_at TIMESTAMP NULL
);
```

---

## 🚧 Recent Refactoring (2025-12-12)

### Phase 1: Zustand State Management ✅
- Installed Zustand
- Created `Frontend/src/store/useSiteSettingsStore.ts`
- Centralized site settings state
- Redux DevTools integration
- localStorage persistence

### Phase 2: Pydantic Aliases ✅
- Added `alias_generator=to_camel` to backend schemas
- Removed 57 lines of manual snake_case → camelCase conversion
- Bundle size reduced: 402.06 kB → 399.90 kB (-2.16 kB)

### Phase 3: Directory Renaming (Pending)
- Config files updated (nginx, systemd, postgres)
- Awaiting manual rename: `Backend/` → `backend/`, `Frontend/` → `frontend/`
- See: `REFACTORING_PRODUCTION_IMPACT.md`

---

## 🤝 Contributing

### Getting Started
1. Clone repo: `git clone https://github.com/yourusername/fastreactcms.git`
2. Read `docs/development/SETUP.md`
3. Read `docs/development/CONTRIBUTING.md`
4. Create feature branch: `git checkout -b feature/your-feature`
5. Make changes
6. Test locally
7. Submit PR

### Code Style
- **Frontend**: ESLint + Prettier (auto-format on save)
- **Backend**: Black + Flake8 (PEP 8)
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, etc.)

### Architecture Decisions
- Prefer Zustand over Context API for global state
- Use Pydantic for all API schemas (auto snake_case conversion)
- Follow feature-based directory structure (not layer-based)
- Keep components small (< 300 lines)
- Extract business logic to custom hooks

---

## 📚 Additional Resources

- **API Documentation**: `/docs` (Swagger UI)
- **Deployment Guide**: `docs/deployment/DEPLOYMENT.md`
- **Security Audit**: `docs/SECURITY_AUDIT_2025-12-11.md`
- **Refactoring Plan**: `REFACTORING_PLAN.md`
- **Production Impact**: `REFACTORING_PRODUCTION_IMPACT.md`

---

**Maintained by:** The FastReactCMS Team
**License:** MIT
**Support:** https://github.com/yourusername/fastreactcms/issues
