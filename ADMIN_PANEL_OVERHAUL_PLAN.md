# Admin Panel Overhaul Plan
**Date**: January 20, 2026
**Status**: Planning Phase
**Priority**: High

---

## Executive Summary

The Admin Panel requires a comprehensive overhaul to address:
1. Missing Plugin Management UI (enable/disable courses, tutorials, games)
2. Poor admin panel organization and design
3. Tutorial system limitations (code-only steps, no categorization)
4. Feature integration issues on frontend after VM upgrade
5. Profile and Achievement system verification

---

## Current State Analysis

### Admin Panel Structure (What Exists)

| Page | Route | Status | Notes |
|------|-------|--------|-------|
| Dashboard | `/admin` | Working | 11 tool cards, but missing plugin controls |
| Blog Editor | `/admin/blog` | Working | Full CRUD |
| Blog Posts | `/admin/posts` | Working | List/filter/delete |
| Categories | `/admin/categories` | Working | Blog categories only |
| Tags | `/admin/tags` | Working | Blog tags |
| Pages | `/admin/pages` | Working | Dynamic pages |
| Navigation | `/admin/navigation` | Working | Menu management |
| Theme | `/admin/theme` | Working | Basic colors |
| Newsletter | `/admin/newsletter` | Working | Subscribers |
| Site Settings | `/admin/settings` | Working | SEO, analytics, branding |
| Users | `/admin/users` | Working | Full user management |
| **Tutorials** | `/admin/tutorials` | Partial | Exists but limited |
| **Courses** | `/admin/courses` | Missing? | Not in dashboard cards |
| **Games** | `/admin/games` | Missing | No admin interface |
| **Plugins** | `/admin/plugins` | Missing | No UI exists |

---

## Issue #1: Missing Plugin Management System

### Problem
- Backend has `PLUGINS_ENABLED` config in `/backend/app/core/config.py`:
  ```python
  PLUGINS_ENABLED = {
      "tutorials": True,
      "typing_game": True,
      "courses": True,
      "quizzes": False
  }
  ```
- **No admin UI exists** to toggle these settings
- Changes require manual environment variable editing and server restart

### Required Solution

#### Backend Changes
1. Create `/api/v1/admin/plugins` endpoints:
   - `GET /plugins` - List all plugins with enabled status
   - `PUT /plugins/{plugin_id}` - Toggle plugin enabled/disabled
   - `GET /plugins/{plugin_id}/status` - Get plugin health/stats

2. Create `plugin_settings` database table:
   ```sql
   plugin_settings (
     id VARCHAR PRIMARY KEY,  -- "tutorials", "courses", etc.
     enabled BOOLEAN DEFAULT true,
     config JSON,  -- plugin-specific settings
     installed_version VARCHAR,
     updated_at TIMESTAMP
   )
   ```

3. Migrate from env-based to DB-based plugin config

#### Frontend Changes
1. Create `PluginManager.tsx` page at `/admin/plugins`
2. UI Components:
   - Plugin cards with toggle switches
   - Plugin health status indicators
   - Plugin version display
   - Plugin-specific settings modal
   - Enable/disable confirmation dialog

---

## Issue #2: Admin Dashboard Poor Organization

### Problems
- 11 cards laid out in flat grid with no grouping
- No visual hierarchy
- Missing important features (plugins, courses admin)
- No quick stats/metrics prominent display
- Navigation requires going back to dashboard constantly

### Proposed Redesign: WordPress-Style Sidebar Navigation

Move from card-based dashboard to a **persistent left sidebar** with collapsible sections. This provides:
- Always-visible navigation
- Better organization by domain
- Scalable structure for future features
- Familiar UX pattern (WordPress, Django Admin, etc.)

#### New Admin Layout Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  HEADER BAR (slim)                                     [View Site] [User]│
├────────────────┬─────────────────────────────────────────────────────────┤
│                │                                                          │
│  ADMIN SIDEBAR │              MAIN CONTENT AREA                          │
│  ═════════════ │                                                          │
│                │  ┌────────────────────────────────────────────────────┐ │
│  ▼ Dashboard   │  │                                                    │ │
│    • Overview  │  │   Dashboard / Page Content Here                    │ │
│    • Analytics │  │                                                    │ │
│                │  │   Stats cards, recent activity, quick actions      │ │
│  ▼ Content     │  │                                                    │ │
│    • Blog      │  └────────────────────────────────────────────────────┘ │
│    • Pages     │                                                          │
│    • Media     │                                                          │
│                │                                                          │
│  ▼ LMS         │                                                          │
│    • Tutorials │                                                          │
│    • Courses   │                                                          │
│    • Games     │                                                          │
│    • Progress  │                                                          │
│                │                                                          │
│  ▼ Users       │                                                          │
│    • All Users │                                                          │
│    • Roles     │                                                          │
│    • Achieve.  │                                                          │
│                │                                                          │
│  ▼ Settings    │                                                          │
│    • General   │                                                          │
│    • Theme     │                                                          │
│    • Navigation│                                                          │
│    • Plugins   │                                                          │
│                │                                                          │
│  ────────────  │                                                          │
│  [← Back Site] │                                                          │
│                │                                                          │
└────────────────┴─────────────────────────────────────────────────────────┘
```

#### Sidebar Sections (Detailed)

**1. DASHBOARD** (Home)
```
📊 Dashboard
   ├── Overview      → /admin              (stats, quick actions)
   └── Analytics     → /admin/analytics    (site-wide metrics)
```

**2. CONTENT MANAGEMENT** (Blog & Pages)
```
📝 Content
   ├── All Posts     → /admin/posts        (list/search/filter)
   ├── New Post      → /admin/blog         (editor)
   ├── Categories    → /admin/categories   (blog categories)
   ├── Tags          → /admin/tags         (blog tags)
   ├── Pages         → /admin/pages        (static pages)
   └── Media Library → /admin/media        (images/files) [NEW]
```

**3. LEARNING MANAGEMENT SYSTEM** (LMS - Separate Section)
```
🎓 LMS
   ├── Tutorials
   │   ├── All Tutorials    → /admin/tutorials
   │   ├── New Tutorial     → /admin/tutorials/new
   │   ├── Categories       → /admin/tutorial-categories  [NEW]
   │   └── Analytics        → /admin/tutorials/analytics
   │
   ├── Courses
   │   ├── All Courses      → /admin/courses
   │   ├── New Course       → /admin/courses/new
   │   └── Enrollments      → /admin/courses/enrollments  [NEW]
   │
   ├── Typing Games
   │   ├── Word Lists       → /admin/games/word-lists     [NEW]
   │   ├── Challenges       → /admin/games/challenges     [NEW]
   │   └── Leaderboard      → /admin/games/leaderboard    [NEW]
   │
   └── Student Progress     → /admin/lms/progress         [NEW]
```

**4. USER MANAGEMENT** (Separate Section)
```
👥 Users
   ├── All Users       → /admin/users           (list/CRUD)
   ├── Roles & Perms   → /admin/users/roles     [NEW]
   ├── Achievements    → /admin/achievements    [NEW]
   ├── XP & Levels     → /admin/xp-config       [NEW]
   └── Activity Log    → /admin/activity        [NEW]
```

**5. SITE SETTINGS** (Separate Section)
```
⚙️ Settings
   ├── General         → /admin/settings        (site info, SEO)
   ├── Theme           → /admin/theme           (colors, branding)
   ├── Navigation      → /admin/navigation      (menus)
   ├── Newsletter      → /admin/newsletter      (email)
   ├── Plugins         → /admin/plugins         [NEW]
   └── System Health   → /admin/system          [NEW]
```

#### Sidebar Component Features

1. **Collapsible Sections**
   - Click header to expand/collapse
   - Remember state in localStorage
   - Visual indicator (▼/▶)

2. **Active State Highlighting**
   - Current page highlighted
   - Parent section auto-expanded

3. **Badge Counts**
   - Draft posts count
   - Pending users
   - Active alerts

4. **Responsive Behavior**
   - Desktop: Always visible (240px width)
   - Tablet: Collapsible to icons only (64px)
   - Mobile: Slide-out drawer with hamburger

5. **Quick Actions**
   - "New Post" button prominent
   - "View Site" link at bottom
   - User profile/logout dropdown

#### Dashboard Overview Page (New Design)

The `/admin` dashboard becomes a summary page:

```
┌────────────────────────────────────────────────────────────────┐
│  Good morning, Andy!                              Jan 20, 2026 │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  QUICK STATS                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ 24 Posts │ │156 Users │ │ 12 Tuts  │ │ 5 Courses│          │
│  │ +2 today │ │ +5 today │ │ 89% comp │ │ 45 enroll│          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  RECENT ACTIVITY              │  QUICK ACTIONS                 │
│  ─────────────────            │  ─────────────                 │
│  • User "john" completed      │  [+ New Post      ]            │
│    "Python Basics" tutorial   │  [+ New Tutorial  ]            │
│  • New user registered:       │  [+ New Course    ]            │
│    sarah@example.com          │  [  View Site     ]            │
│  • Post "Docker Guide"        │                                │
│    published by admin         │  SYSTEM STATUS                 │
│  • 3 new achievements         │  ─────────────                 │
│    unlocked today             │  ● API: Healthy                │
│                               │  ● DB: Connected               │
│                               │  ● Plugins: 3/4 active         │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  CONTENT NEEDING ATTENTION                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 📄 3 Draft Posts awaiting publish          [Review →]   │  │
│  │ 👤 2 Users pending verification            [Review →]   │  │
│  │ 📊 Tutorial "Git Basics" has 40% drop-off  [Analyze →]  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Issue #3: Tutorial System Limitations

### Problems Identified
1. **Step types limited to code examples** - Not all IT topics are code
2. **No tutorial categories UI** - Categories exist in DB but no management
3. **Hints only support code** - General IT tutorials need broader support

### Current Tutorial Step Model
```typescript
TutorialStep {
  step_order: number;
  title: string;
  content: string;        // Markdown - GOOD
  code_example: string;   // Optional code - LIMITING
  code_language: string;  // Only for code - LIMITING
  hints: string[];        // Array - GOOD
}
```

### Proposed Enhanced Step Model
```typescript
TutorialStep {
  step_order: number;
  title: string;
  content: string;              // Main markdown content

  // NEW: Content blocks (like courses)
  content_blocks: ContentBlock[];  // Optional rich content

  // Enhanced media support
  media_type?: "none" | "code" | "image" | "video" | "diagram" | "terminal";
  media_content?: string;       // Code, URL, or embedded content
  media_language?: string;      // For code blocks
  media_caption?: string;       // Alt text/description

  // Enhanced hints
  hints: TutorialHint[];        // Rich hint objects

  // NEW: Interactivity
  quiz_question?: QuizBlock;    // Optional knowledge check
  expected_action?: string;     // What user should do (not just code)

  // NEW: Step metadata
  step_type: "theory" | "practice" | "quiz" | "demonstration" | "exercise";
  estimated_minutes?: number;
}

TutorialHint {
  content: string;              // Hint text (markdown)
  type: "text" | "code" | "link" | "image";
  reveal_after_attempts?: number;
}

ContentBlock {
  type: "text" | "heading" | "image" | "video" | "code" | "callout" | "diagram";
  order: number;
  content: Record<string, any>;
}
```

### Tutorial Categories Management

Create `/admin/tutorial-categories` page:
- List existing categories
- Create/Edit/Delete categories
- Set category icons (Lucide icons)
- Set category colors
- Drag-drop reorder
- Assign tutorials to categories

---

## Issue #4: Frontend Feature Integration Issues

### Symptoms
- Features not showing after VM upgrade
- Tutorials visible but incomplete
- Courses/Games possibly broken

### Investigation Checklist

1. **Check API Connectivity**
   ```bash
   curl https://yoursite.com/api/v1/tutorials
   curl https://yoursite.com/api/v1/courses
   curl https://yoursite.com/api/v1/typing-game/word-lists
   ```

2. **Check Plugin Status in Backend**
   ```python
   # In backend shell
   from app.core.config import settings
   print(settings.PLUGINS_ENABLED)
   ```

3. **Check Frontend Routes**
   - `/tutorials` - Tutorial browse page
   - `/courses` - Course catalog
   - `/games/typing` - Typing game

4. **Check for JS Errors**
   - Browser console (F12)
   - Network tab for failed requests

5. **Check Environment Variables**
   - Backend `.env` has correct plugin flags
   - Frontend `.env` has correct API URL

### Likely Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Tutorials shows but empty | API returns 404 or no data | Check plugin enabled, seed data |
| Courses page 404 | Route not registered | Check routes.tsx import |
| Games not loading | Plugin disabled in backend | Enable in PLUGINS_ENABLED |
| Admin cards missing | Not added to dashboard | Add to AdminDashboard.tsx |

---

## Issue #5: Profile & Achievement System Verification

### Current Status: 85% Complete

#### What's Working
- User profile page with 6 tabs
- Achievement definitions and tracking
- XP and leveling system
- Activity logging
- Frontend components (badges, progress bars, streak counter)
- Admin achievement management

#### What Needs Verification

1. **Achievement Unlocking Flow**
   - Create test user
   - Complete a tutorial
   - Verify achievement unlocks
   - Verify XP awarded

2. **Tutorial → XP Integration**
   - Code has TODO comment: "Implement XP system integration"
   - File: `/backend/app/plugins/tutorials/routes.py`
   - Need to add: `xp_service.award_xp("tutorial_complete", user_id)`

3. **Profile Data Loading**
   - Test `/api/v1/progress/dashboard/me`
   - Verify all tabs load data
   - Check activity timeline populates

4. **Streak System**
   - Test daily login tracking
   - Verify streak increments
   - Verify streak bonuses awarded

### Integration Fixes Required

```python
# In /backend/app/plugins/tutorials/routes.py
# After marking tutorial complete:

from app.plugins.shared.xp_service import award_xp
from app.plugins.shared.achievement_service import check_and_unlock_achievements

# Award XP
await award_xp(db, user_id, "tutorial_complete", tutorial.xp_reward)

# Check achievements
await check_and_unlock_achievements(db, user_id, "tutorial_complete", {
    "tutorial_id": tutorial.id,
    "tutorial_title": tutorial.title
})
```

---

## Implementation Phases

### Phase 1: Admin Sidebar Layout (Priority: Critical - Foundation)
**This is the foundation for everything else**
1. Create `AdminLayout.tsx` wrapper component with sidebar
2. Create `AdminSidebar.tsx` collapsible navigation component
3. Create `AdminHeader.tsx` slim header bar
4. Update all admin routes to use new layout
5. Implement responsive behavior (desktop/tablet/mobile)
6. Add localStorage persistence for collapsed sections
7. Implement active state highlighting

**Files to create:**
- `/frontend/src/components/admin/layout/AdminLayout.tsx`
- `/frontend/src/components/admin/layout/AdminSidebar.tsx`
- `/frontend/src/components/admin/layout/AdminHeader.tsx`
- `/frontend/src/components/admin/layout/SidebarSection.tsx`
- `/frontend/src/components/admin/layout/SidebarItem.tsx`

### Phase 2: Dashboard Overhaul (Priority: High)
**Redesign the main dashboard as a summary hub**
1. Create new `AdminDashboard.tsx` with stats cards
2. Create `QuickStatsCard.tsx` component
3. Create `RecentActivityFeed.tsx` component
4. Create `AttentionItems.tsx` (drafts, pending users, etc.)
5. Create `SystemStatus.tsx` widget
6. Add API endpoint for aggregated admin stats

### Phase 3: LMS Section Build-out (Priority: High)
**Make Learning Management System its own powerful section**
1. **Tutorial Categories Admin** - CRUD for tutorial categories
2. **Courses Admin** - Add missing dashboard entry, enrollments view
3. **Games Admin** - Word lists management, challenges editor
4. **Student Progress** - Unified progress view across all LMS
5. **LMS Analytics** - Combined analytics dashboard

### Phase 4: User Management Section (Priority: High)
**Separate and enhance user management**
1. **Roles & Permissions** - Role management page
2. **Achievements Admin** - CRUD for achievements
3. **XP Configuration** - Level thresholds, XP rewards editor
4. **Activity Log** - Site-wide activity viewer

### Phase 5: Settings Section (Priority: High)
**Reorganize and add missing settings**
1. **Plugin Manager** - Enable/disable plugins with UI
2. **System Health** - Server status, DB connections, cache
3. Reorganize existing settings pages
4. Add missing configuration options

### Phase 6: Tutorial System Enhancement (Priority: Medium)
**Expand tutorial capabilities beyond code**
1. Extend step model for multiple content types
2. Add content block support (borrow from courses)
3. Create step type selector in editor
4. Add media support (images, videos, diagrams)
5. Add step-level quiz questions

### Phase 7: Integration & Polish (Priority: Medium)
**Wire everything together**
1. XP integration in tutorial/course completion
2. Achievement triggers across features
3. Notification system for achievements
4. Test all flows end-to-end
5. Performance optimization

---

## Files to Create/Modify

### New Files - Admin Layout System
| File | Purpose |
|------|---------|
| `/frontend/src/components/admin/layout/AdminLayout.tsx` | Main admin wrapper with sidebar |
| `/frontend/src/components/admin/layout/AdminSidebar.tsx` | Collapsible navigation sidebar |
| `/frontend/src/components/admin/layout/AdminHeader.tsx` | Slim top header bar |
| `/frontend/src/components/admin/layout/SidebarSection.tsx` | Expandable menu section |
| `/frontend/src/components/admin/layout/SidebarItem.tsx` | Individual nav item |
| `/frontend/src/hooks/useAdminSidebar.ts` | Sidebar state management hook |

### New Files - Dashboard Components
| File | Purpose |
|------|---------|
| `/frontend/src/components/admin/dashboard/QuickStatsCard.tsx` | Stat card with trend |
| `/frontend/src/components/admin/dashboard/RecentActivityFeed.tsx` | Activity timeline |
| `/frontend/src/components/admin/dashboard/AttentionItems.tsx` | Items needing review |
| `/frontend/src/components/admin/dashboard/SystemStatus.tsx` | Health indicators |

### New Files - Admin Pages
| File | Purpose |
|------|---------|
| `/frontend/src/pages/admin/PluginManager.tsx` | Plugin enable/disable UI |
| `/frontend/src/pages/admin/TutorialCategoryManager.tsx` | Tutorial categories CRUD |
| `/frontend/src/pages/admin/GamesWordListAdmin.tsx` | Typing game word lists |
| `/frontend/src/pages/admin/GamesChallengesAdmin.tsx` | Typing game challenges |
| `/frontend/src/pages/admin/AchievementsAdmin.tsx` | Achievement management |
| `/frontend/src/pages/admin/XPConfigAdmin.tsx` | XP and levels config |
| `/frontend/src/pages/admin/RolesAdmin.tsx` | User roles management |
| `/frontend/src/pages/admin/ActivityLogAdmin.tsx` | Site-wide activity log |
| `/frontend/src/pages/admin/SystemHealthAdmin.tsx` | System status page |
| `/frontend/src/pages/admin/LMSProgressAdmin.tsx` | Student progress overview |
| `/frontend/src/pages/admin/CourseEnrollmentsAdmin.tsx` | Course enrollments |

### New Files - Backend
| File | Purpose |
|------|---------|
| `/backend/app/api/v1/endpoints/admin/plugins.py` | Plugin management API |
| `/backend/app/api/v1/endpoints/admin/system.py` | System health API |
| `/backend/app/api/v1/endpoints/admin/stats.py` | Aggregated stats API |
| `/backend/alembic/versions/xxx_add_plugin_settings.py` | Plugin settings table |

### Files to Modify
| File | Changes |
|------|---------|
| `AdminDashboard.tsx` | Complete redesign as summary hub |
| `routes.tsx` | Add all new admin routes, update layout wrapper |
| `TutorialEditorPage.tsx` | Add content block support |
| `/backend/app/plugins/tutorials/routes.py` | Add XP integration |
| `/backend/app/plugins/courses/routes.py` | Add XP integration |
| `/backend/app/main.py` | Add new admin routes |

### Sidebar Navigation Structure (Data)
```typescript
// /frontend/src/config/adminNavigation.ts
export const adminNavigation = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: 'LayoutDashboard',
    items: [
      { label: 'Overview', path: '/admin', icon: 'Home' },
      { label: 'Analytics', path: '/admin/analytics', icon: 'BarChart' },
    ]
  },
  {
    id: 'content',
    label: 'Content',
    icon: 'FileText',
    items: [
      { label: 'All Posts', path: '/admin/posts', icon: 'Files' },
      { label: 'New Post', path: '/admin/blog', icon: 'FilePlus' },
      { label: 'Categories', path: '/admin/categories', icon: 'FolderTree' },
      { label: 'Tags', path: '/admin/tags', icon: 'Tags' },
      { label: 'Pages', path: '/admin/pages', icon: 'FileText' },
    ]
  },
  {
    id: 'lms',
    label: 'LMS',
    icon: 'GraduationCap',
    badge: 'tutorials + courses', // dynamic count
    items: [
      {
        label: 'Tutorials',
        icon: 'BookOpen',
        children: [
          { label: 'All Tutorials', path: '/admin/tutorials' },
          { label: 'New Tutorial', path: '/admin/tutorials/new' },
          { label: 'Categories', path: '/admin/tutorial-categories' },
          { label: 'Analytics', path: '/admin/tutorials/analytics' },
        ]
      },
      {
        label: 'Courses',
        icon: 'Library',
        children: [
          { label: 'All Courses', path: '/admin/courses' },
          { label: 'New Course', path: '/admin/courses/new' },
          { label: 'Enrollments', path: '/admin/courses/enrollments' },
        ]
      },
      {
        label: 'Typing Games',
        icon: 'Keyboard',
        children: [
          { label: 'Word Lists', path: '/admin/games/word-lists' },
          { label: 'Challenges', path: '/admin/games/challenges' },
          { label: 'Leaderboard', path: '/admin/games/leaderboard' },
        ]
      },
      { label: 'Student Progress', path: '/admin/lms/progress', icon: 'TrendingUp' },
    ]
  },
  {
    id: 'users',
    label: 'Users',
    icon: 'Users',
    items: [
      { label: 'All Users', path: '/admin/users', icon: 'Users' },
      { label: 'Roles & Permissions', path: '/admin/users/roles', icon: 'Shield' },
      { label: 'Achievements', path: '/admin/achievements', icon: 'Trophy' },
      { label: 'XP & Levels', path: '/admin/xp-config', icon: 'Zap' },
      { label: 'Activity Log', path: '/admin/activity', icon: 'Activity' },
    ]
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: 'Settings',
    items: [
      { label: 'General', path: '/admin/settings', icon: 'Settings' },
      { label: 'Theme', path: '/admin/theme', icon: 'Palette' },
      { label: 'Navigation', path: '/admin/navigation', icon: 'Menu' },
      { label: 'Newsletter', path: '/admin/newsletter', icon: 'Mail' },
      { label: 'Plugins', path: '/admin/plugins', icon: 'Puzzle' },
      { label: 'System Health', path: '/admin/system', icon: 'HeartPulse' },
    ]
  },
];
```

---

## Success Criteria

### Phase 1 - Sidebar Layout (MVP)
- [ ] Admin sidebar visible on all admin pages
- [ ] Sections collapsible with state persistence
- [ ] Active page highlighted in sidebar
- [ ] Responsive: sidebar collapses on mobile
- [ ] "View Site" link works from any admin page

### Phase 2 - Dashboard
- [ ] Quick stats load from aggregated API
- [ ] Recent activity shows real data
- [ ] Attention items link to relevant pages
- [ ] System status shows actual health

### Phase 3 - LMS Section
- [ ] Tutorial categories CRUD working
- [ ] Courses visible in sidebar and accessible
- [ ] Games admin pages functional
- [ ] Student progress shows unified view

### Phase 4 - User Management
- [ ] All users page works
- [ ] Achievements admin shows all achievements
- [ ] XP config editable
- [ ] Activity log shows site-wide activity

### Phase 5 - Settings
- [ ] Plugin manager can enable/disable plugins
- [ ] System health shows real metrics
- [ ] All existing settings still work

### Phase 6 - Tutorial Enhancement
- [ ] Steps support multiple content types (not just code)
- [ ] Categories assignable to tutorials
- [ ] Media uploads working

### Phase 7 - Integration
- [ ] XP awarded on tutorial completion
- [ ] XP awarded on course completion
- [ ] Achievements unlock automatically
- [ ] Notifications show on unlock

---

## Notes

- Backend plugin system is well-architected, just needs UI
- Achievement system is 85% done, needs integration triggers
- Tutorial step model can borrow from Courses content block system
- Consider merging tutorial/course editors to share components
- System health monitoring would be valuable addition
- **Sidebar is the foundation** - everything else builds on top of it

---

## Quick Reference: Admin Routes

| Section | Route | Status |
|---------|-------|--------|
| **Dashboard** | `/admin` | Existing - needs redesign |
| **Dashboard** | `/admin/analytics` | NEW |
| **Content** | `/admin/posts` | Existing |
| **Content** | `/admin/blog` | Existing |
| **Content** | `/admin/categories` | Existing |
| **Content** | `/admin/tags` | Existing |
| **Content** | `/admin/pages` | Existing |
| **LMS** | `/admin/tutorials` | Existing |
| **LMS** | `/admin/tutorials/new` | Existing |
| **LMS** | `/admin/tutorial-categories` | NEW |
| **LMS** | `/admin/tutorials/analytics` | Existing |
| **LMS** | `/admin/courses` | Existing - missing from UI |
| **LMS** | `/admin/courses/new` | Existing |
| **LMS** | `/admin/courses/enrollments` | NEW |
| **LMS** | `/admin/games/word-lists` | NEW |
| **LMS** | `/admin/games/challenges` | NEW |
| **LMS** | `/admin/games/leaderboard` | NEW |
| **LMS** | `/admin/lms/progress` | NEW |
| **Users** | `/admin/users` | Existing |
| **Users** | `/admin/users/roles` | NEW |
| **Users** | `/admin/achievements` | NEW |
| **Users** | `/admin/xp-config` | NEW |
| **Users** | `/admin/activity` | NEW |
| **Settings** | `/admin/settings` | Existing |
| **Settings** | `/admin/theme` | Existing |
| **Settings** | `/admin/navigation` | Existing |
| **Settings** | `/admin/newsletter` | Existing |
| **Settings** | `/admin/plugins` | NEW |
| **Settings** | `/admin/system` | NEW |

**Total Routes**: 28 (15 existing, 13 new)

---

**Document Status**: Ready for Review
**Next Step**: User approval before implementation
**Recommended Start**: Phase 1 (Sidebar Layout) - foundation for everything
