# Skill System Migration Plan

**Source:** `C:\Gitlab Projects\ITAppBetaV1\` (The IT Apprentice Beta)
**Target:** `C:\Gitlab Projects\BlogCMS\` (FastReactCMS / LMS)
**Date:** 2026-01-26

---

## Current Status (Updated 2026-01-26)

### Migration Progress

| Phase | Status | Notes |
|-------|--------|-------|
| **Phase 1: Backend Foundation** | ✅ Complete | Models, schemas, service, CRUD, seed script, migration created |
| **Phase 2: Backend API** | ✅ Complete | Public routes, admin routes registered in main.py |
| **Phase 3: Integration Hooks** | ✅ Complete | Integrated into tutorials, courses, quizzes, typing game |
| **Phase 4: Frontend Core** | ✅ Complete | Types, API service, pages (Dashboard, Detail, Leaderboard) |
| **Phase 5: Frontend Components** | ✅ Complete | SkillBadge, SkillProgressBar, SkillsWidget, SkillXPToast |
| **Phase 6: Polish** | ✅ Complete | Admin navigation added, toasts with animations |

### Backend Skill System Status

- ✅ `/api/v1/skills/` - List all skills (working)
- ✅ `/api/v1/skills/utils/xp-calculator?level=50` - XP formula working (101,333 XP for Level 50, Expert tier)
- ✅ `/api/v1/skills/leaderboards/global` - Leaderboard working (empty - no user data yet)
- ✅ Plugin registered in `main.py` with conditional loading
- ✅ `PLUGIN_SKILLS_ENABLED` setting in `config.py` (default: False)
- ⚠️ Set `PLUGIN_SKILLS_ENABLED=true` in `.env` to enable

### Completed Work

1. ✅ **Integration Hooks (Phase 3)**: Skill XP awards added to:
   - `tutorials/routes.py` - Tutorial completion
   - `courses/routes.py` - Course completion
   - `quizzes/routes.py` - Quiz submission (passing score)
   - `typing_game/routes.py` - Game submission (v1 and v2)

2. ✅ **Frontend Plugin (Phase 4)**: Created `frontend/src/plugins/skills/`:
   - `types/index.ts` - TypeScript types for skills
   - `services/skillsApi.ts` - API client with snake_case -> camelCase transforms
   - `pages/SkillsDashboard.tsx` - Main skills overview with grid by category
   - `pages/SkillDetailPage.tsx` - Individual skill progress and XP history
   - `pages/SkillsLeaderboard.tsx` - Global IT Level rankings
   - Routes added: `/skills`, `/skills/:slug`, `/skills/leaderboard`

3. ✅ **Frontend Components (Phase 5)**:
   - `SkillBadge.tsx` - Compact skill level display with tier color
   - `SkillProgressBar.tsx` - Animated XP progress bar
   - `SkillsWidget.tsx` - Dashboard widget showing IT Level & top skills
   - `SkillXPToast.tsx` - Animated notification for XP gains with level up alerts

4. ✅ **Admin Navigation (Phase 6)**:
   - Added Skills section to LMS in `adminNavigation.ts`
   - Shows when `skills` plugin is enabled

### To Enable Skills Plugin

1. Add to `.env`:
   ```
   PLUGIN_SKILLS_ENABLED=true
   ```

2. Run database migration:
   ```bash
   cd backend
   alembic upgrade head
   ```

3. Seed the 12 IT skills:
   ```bash
   python -m app.plugins.skills.seed
   ```

4. Restart the backend server

5. Add "Skills" link to public navigation via Admin > Settings > Navigation

---

## Admin Dashboard Issues Analysis (2026-01-26)

Investigation of reported admin panel issues revealed the following:

### Issues Found & Fixed

| Issue | Root Cause | Status |
|-------|-----------|--------|
| Newsletter fails to load subscribers | Used raw `fetch()` instead of `apiClient`, causing requests to wrong port | ✅ Fixed |

### Issues Requiring Backend Check

The following admin pages may fail if the **backend is not running** or **user is not authenticated as admin**:

| Page | API Endpoint | Notes |
|------|-------------|-------|
| Dashboard Overview | `/api/v1/admin/stats/dashboard` | Requires admin auth |
| Plugins Manager | `/api/v1/admin/plugins` | Requires admin auth |
| Navigation Manager | `/api/v1/admin/navigation` | Uses `apiClient` correctly |
| Theme Settings | `/api/v1/admin/theme` | Uses `apiClient` correctly |
| Activity Log | `/api/v1/admin/activities` | Requires admin auth |
| User Management | `/api/v1/admin/users` | Requires admin auth |

### LMS Components in Admin

LMS sections in admin navigation are **conditionally shown** based on plugin status:

```typescript
// From adminNavigation.ts
{
  label: 'Tutorials',
  requiresPlugin: 'tutorials',  // Only shows if tutorials plugin enabled
  children: [...]
}
```

The `PluginsContext` fetches plugin status from `/api/v1/admin/plugins`. If this fails:
- Non-admin users: Silent failure, empty plugins array (LMS nav hidden)
- Backend down: All LMS nav items hidden

### Troubleshooting Checklist

1. **Ensure backend is running** on port 8100: `cd backend && uvicorn app.main:app --reload --port 8100`
2. **Verify admin authentication**: Login with admin credentials
3. **Check browser console** for specific error messages
4. **Verify CORS settings**: Frontend origin must be in `CORS_ORIGINS` list
5. **Check `.env` file**: Ensure all required variables are set

---

## 0. Exploration Findings (2026-01-26)

This section documents specific code patterns and integration points discovered during codebase exploration.

### 0.1 XP Service Pattern (`backend/app/plugins/shared/xp_service.py`)

The existing `xp_service` is a singleton with these key methods:

```python
# Import pattern
from app.plugins.shared.xp_service import xp_service

# Award XP (used in tutorials, courses, quizzes)
xp_result = xp_service.award_xp(
    db=db,
    user_id=current_user.id,
    action="tutorial_complete",       # Key from REWARDS dict
    multiplier=1.0,                    # Optional multiplier
    reason=f"Completed: {tutorial.title}"
)

# Response structure
{
    "xp_awarded": int,
    "total_xp": int,
    "old_level": int,
    "new_level": int,
    "level_up": bool,
    "action": str,
    "reason": str
}
```

**XP Config rewards defined in `XPConfig.REWARDS`** (lines 28-63):
- `tutorial_step_complete`: 10 XP
- `tutorial_complete`: 100 XP
- `typing_game_complete`: 20 XP
- `typing_game_wpm_50/80/100`: 30/60/100 XP bonuses

**Skill XP should be awarded AFTER global XP**, using same session/user pattern.

### 0.2 Tutorial Completion Hook (`backend/app/plugins/tutorials/routes.py`)

**Location: `complete_tutorial_step` endpoint (lines 202-388)**

Key integration point at line ~290-370 where tutorial completes:

```python
# After this existing code (line 287):
tutorial_completed = progress.status == "completed"

# ADD SKILL XP HOOK HERE (before achievement_service.check_and_unlock_achievements):
if tutorial_completed and progress.completed_at:
    # >>> NEW: Award skill XP <<<
    if tutorial.related_skills:
        from app.plugins.skills.service import award_skill_xp
        for skill_slug in tutorial.related_skills:
            await award_skill_xp(
                db=db, user_id=current_user.id, skill_slug=skill_slug,
                xp_amount=tutorial.xp_reward or 100,
                source_type="tutorial", source_id=str(tutorial_id),
                source_metadata={"difficulty": tutorial.difficulty}
            )
```

**Existing services imported** (lines 22-26):
- `from app.plugins.shared.xp_service import xp_service`
- `from app.plugins.shared.achievement_service import achievement_service`
- `from app.plugins.shared.challenge_service import challenge_service`

### 0.3 Course Completion Hook (`backend/app/plugins/courses/routes.py`)

**Location: `update_my_module_progress` endpoint (lines 283-343)**

Key integration point at line ~325-342 where course completes:

```python
# After module progress update (line 317):
# Refresh enrollment to get updated state
db.refresh(enrollment)

# Check course complete at line 326:
"course_complete": enrollment.is_complete and not was_course_complete,

# >>> ADD SKILL XP HOOK when course_complete is True <<<
if enrollment.is_complete and not was_course_complete:
    course = crud.get_course(db, course_id)
    if course and course.related_skills:
        from app.plugins.skills.service import award_skill_xp
        for skill_slug in course.related_skills:
            await award_skill_xp(
                db=db, user_id=current_user.id, skill_slug=skill_slug,
                xp_amount=course.xp_reward or 250,
                source_type="course", source_id=str(course_id),
                source_metadata={"course_title": course.title, "level": str(course.level)}
            )
```

**Note**: Courses already have `related_skills` JSON field (used at lines 93-94):
```python
if course.related_skills is None:
    course.related_skills = ["problem-solving"]
```

### 0.4 Quiz Submission Hook (`backend/app/plugins/quizzes/routes.py`)

**Location: `submit_quiz_attempt` endpoint (lines 211-310)**

Key integration point at lines 234-276 where quiz is graded:

```python
# After this existing code (line 252):
attempt.xp_awarded = xp_awarded
db.commit()

# >>> ADD SKILL XP HOOK <<<
# NOTE: Quiz model needs `related_skills` column added (see Migration)
if quiz.related_skills:
    from app.plugins.skills.service import award_skill_xp
    for skill_slug in quiz.related_skills:
        await award_skill_xp(
            db=db, user_id=current_user.id, skill_slug=skill_slug,
            xp_amount=xp_awarded,  # Scale by quiz score
            source_type="quiz", source_id=str(quiz_id),
            source_metadata={"score": attempt.percentage, "passed": attempt.passed}
        )
```

**Existing achievement/challenge tracking** (lines 254-275):
```python
achievement_service.check_and_unlock_achievements(...)
challenge_service.increment_progress(db, user_id, ChallengeType.QUIZ, amount=1)
```

### 0.5 Typing Game Hook (`backend/app/plugins/typing_game/routes.py`)

**Location 1: `submit_game` endpoint (lines 134-163)**
**Location 2: `submit_game_v2` endpoint (lines 928-1002) - Enhanced with anti-cheat**

V2 is the primary integration point (lines 968-1001):

```python
# After metrics calculation (line 960):
session, metrics = result

# >>> ADD SKILL XP HOOK <<<
# Communication skill always, plus word_list.related_skills
skill_slugs = ["communication"]
if session.word_list_id:
    word_list = crud.get_word_list(db, session.word_list_id)
    if word_list and word_list.related_skills:
        skill_slugs.extend(word_list.related_skills)

from app.plugins.skills.service import award_skill_xp, calculate_typing_skill_xp
for skill_slug in set(skill_slugs):
    await award_skill_xp(
        db=db, user_id=current_user.id, skill_slug=skill_slug,
        xp_amount=calculate_typing_skill_xp(metrics["metrics"]["wpm"], metrics["metrics"]["accuracy"]),
        source_type="typing_game", source_id=str(session.id),
        source_metadata={"wpm": metrics["metrics"]["wpm"], "accuracy": metrics["metrics"]["accuracy"]}
    )
```

**Word list already has `related_skills`** (line 121):
```python
related_skills = word_list.related_skills or []
```

### 0.6 Achievement Service Integration (`backend/app/plugins/shared/achievement_service.py`)

Existing achievement check pattern:
```python
unlocked = achievement_service.check_and_unlock_achievements(
    db=db,
    user_id=current_user.id,
    action="tutorial_complete",  # or "quiz_complete"
    context={
        "tutorial_id": tutorial_id,
        "difficulty": tutorial.difficulty
    }
)
```

**Add new skill-related achievement triggers**:
- `action="skill_level_up"` with context `{"skill_slug": "...", "new_level": 50}`
- `action="skill_tier_up"` with context `{"skill_slug": "...", "new_tier": "master"}`

### 0.7 Plugin Configuration Pattern (`backend/app/core/config.py`)

From `config.py` lines 85-95:
```python
# Plugin toggles (line ~90)
PLUGINS_ENABLED: Dict[str, bool] = {
    "courses": True,
    "tutorials": True,
    "quizzes": True,
    "typing_game": True,
    "achievements": True,
    "skills": False,  # <<< ADD THIS, default disabled
}
```

### 0.8 Router Registration Pattern (`backend/app/main.py`)

From `main.py` lines 80-175, pattern for plugin registration:
```python
# Skills plugin registration (add around line 150)
if settings.PLUGINS_ENABLED.get("skills", False):
    from app.plugins.skills.routes import router as skills_router
    from app.plugins.skills.admin_routes import router as skills_admin_router
    app.include_router(skills_router, prefix="/api/v1/skills", tags=["Skills"])
    app.include_router(skills_admin_router, prefix="/api/v1/admin/skills", tags=["Skills Admin"])
```

### 0.9 Frontend API Client Pattern (`frontend/src/api/client.ts`)

```typescript
import { apiClient } from '@/api/client';

// GET example
const response = await apiClient.get('/skills/me/overview');

// POST example
const result = await apiClient.post('/admin/skills/', skillData);
```

### 0.10 Admin Navigation Pattern (`frontend/src/config/adminNavigation.ts`)

Follow existing LMS section pattern:
```typescript
{
  id: 'skills',
  label: 'Skills',
  icon: TrophyIcon,
  requiresPlugin: 'skills',
  children: [
    { id: 'skills-list', label: 'All Skills', path: '/admin/skills' },
    { id: 'skills-analytics', label: 'Analytics', path: '/admin/skills/analytics' },
  ]
}
```

---

## 1. Overview

Migrate the OSRS-style skill progression system from ITAppBetaV1 into BlogCMS as a new `skills` plugin. The system tracks 12 IT skills (Networking, Security, Programming, etc.) with XP-based leveling (1-99), tiered progression, leaderboards, and automatic XP awards when users complete courses, tutorials, quizzes, or typing game sessions.

### What Already Exists in BlogCMS

| System | Status | Skill-Related Fields | Integration Hook Location |
|--------|--------|---------------------|--------------------------|
| Courses | Has `related_skills` (JSON array), `xp_reward` | Display only, default `["problem-solving"]` | `routes.py:325-342` in `update_my_module_progress` |
| Tutorials | Has `related_skills` (JSON), `xp_reward` | Display only | `routes.py:290-370` in `complete_tutorial_step` |
| Quizzes | Has `xp_reward`, `xp_perfect` | **No `related_skills` field yet** (needs migration) | `routes.py:234-276` in `submit_quiz_attempt` |
| Typing Game | Has `related_skills` (JSON) on word lists | Display only | `routes.py:968-1001` in `submit_game_v2` |
| XP Service | Centralized singleton in `shared/xp_service.py` | Flat XP/level (lines 138-207) | Award skill XP **after** global XP |
| Achievements | Full system in `shared/achievement_service.py` | No skill-level triggers | Add `skill_level_up`, `skill_tier_up` actions |
| Daily Challenges | Template-based with streak tracking | Could target skill XP | Add `skill_xp_earn` challenge type |

### What ITAppBetaV1 Has (Source)

- **12 core skills** with OSRS XP formula (exponential curve to level 99)
- **6 tier system**: Novice, Apprentice, Journeyman, Expert, Master, Grandmaster
- **UserSkill** tracking with milestone timestamps (level 10/30/50/75/99)
- **SkillXPLog** audit trail of every XP gain
- **Category-to-skills mapping** for automatic XP distribution
- **Leaderboards**: global (total level) and per-skill
- **Admin analytics**: user counts, XP distribution, activity logs
- **Frontend**: Dashboard, detail pages, progression graphs, skill badges on content cards
- **SkillSelector** admin component for assigning skills to content

---

## 2. Architecture Decisions

### 2.1 Plugin Structure (Follow BlogCMS Conventions)

```
backend/app/plugins/skills/
    __init__.py
    models.py          # Skill, UserSkill, SkillXPLog
    schemas.py         # Pydantic request/response models
    crud.py            # Database operations
    routes.py          # Public + protected API endpoints
    admin_routes.py    # Admin-only endpoints
    service.py         # XP formula, tier calc, award logic
    seed.py            # Seed the 12 default skills

frontend/src/plugins/skills/
    types/index.ts
    services/skillsApi.ts
    components/
        SkillCard.tsx
        SkillBadges.tsx
        SkillProgressBar.tsx
        ProgressionGraph.tsx
        SkillSelector.tsx       # Admin: assign skills to content
        TierBadge.tsx
    pages/
        SkillsDashboard.tsx
        SkillDetailPage.tsx
        SkillLeaderboardPage.tsx
    pages/admin/
        SkillManagerPage.tsx    # CRUD skills + analytics
    hooks/
        useSkills.ts
```

### 2.2 Relationship with Existing XP Service

**Approach: Parallel systems, not replacement.**

The existing `xp_service.py` handles overall user level (flat XP). The skills system adds per-skill XP on top. When a user completes content:

1. `xp_service.award_xp()` awards global XP (existing behavior, unchanged)
2. `skill_service.award_skill_xp()` awards XP to each related skill (new)

This avoids breaking the existing XP/level system while adding the skill dimension.

### 2.3 XP Formula

Use the OSRS formula from ITAppBetaV1 directly:

```python
def calculate_xp_for_level(level: int) -> int:
    """XP required to reach a given level (1-99)."""
    total = 0
    for lvl in range(1, level):
        total += int(lvl + 300 * (2 ** (lvl / 7)))
    return total // 4
```

Key milestones: Level 10 = 1,154 XP | Level 50 = 101,333 XP | Level 99 = 13,034,431 XP

### 2.4 Total Level & IT Level (OSRS-Style Dual Levels)

OSRS uses two distinct aggregate levels. We replicate both:

| Concept | OSRS | IT Equivalent |
|---------|------|---------------|
| **Total Level** | Sum of ALL 24 skill levels (max 2,277) | Sum of all 12 skill levels (max 1,188) |
| **Combat Level** | Weighted formula from 7 combat skills (max 126) | **IT Level** — weighted formula from core skills (max 126) |

Total Level rewards being well-rounded (train everything). IT Level rewards depth and specialization (pick a career path and go deep), just like Combat Level rewards focused combat builds.

#### How OSRS Combat Level Works

```
Base    = 0.25 x (Defence + Hitpoints + floor(Prayer / 2))
Melee   = 0.325 x (Attack + Strength)
Ranged  = 0.325 x floor(Ranged x 1.5)
Magic   = 0.325 x floor(Magic x 1.5)

Combat Level = floor(Base + max(Melee, Ranged, Magic))
```

Three key mechanics:
1. **Foundation skills** always contribute (Defence, Hitpoints, Prayer)
2. **Specialization paths** compete — only the HIGHEST path counts (Melee vs Ranged vs Magic)
3. A focused build can hit max level without training the other paths

#### IT Skill Mapping

**Foundation Skills** (always contribute — like Defence/Hitpoints/Prayer):

| IT Skill | OSRS Analogy | Rationale |
|----------|-------------|-----------|
| Problem Solving | Hitpoints | You literally cannot do IT without it — essential in every role |
| Communication | Defence | Protects you in every situation — docs, emails, tickets, standups |
| Project Management | Prayer | Valuable support skill, but secondary to core competency (halved) |

**Specialization Paths** (only the highest counts — like Melee/Ranged/Magic):

| Path | Skills | Real-World Career |
|------|--------|-------------------|
| **Systems & Infrastructure** | Networking + Systems Administration + Hardware & Support | Network Engineer, SysAdmin, IT Support |
| **Software Development** | Programming + Web Development + Databases | Full-Stack Dev, Backend Dev, DBA |
| **Cloud & Security Operations** | Cloud Computing + DevOps + Security | Cloud Engineer, DevSecOps, Security Analyst |

Every one of the 12 skills is accounted for: 3 foundation + 3 paths x 3 skills = 12.

#### IT Level Formula

```python
def calculate_it_level(skill_levels: dict[str, int]) -> int:
    """
    Calculate IT Level (1-126) from individual skill levels.
    Mirrors OSRS Combat Level formula structure.
    """
    # Foundation (always contributes)
    base = 0.25 * (
        skill_levels["problem-solving"]
        + skill_levels["communication"]
        + math.floor(skill_levels["project-management"] / 2)
    )

    # Specialization paths (only highest counts)
    systems = 0.325 * (
        skill_levels["networking"]
        + skill_levels["systems-administration"]
        + skill_levels["hardware-support"]
    ) / 1.5

    development = 0.325 * (
        skill_levels["programming"]
        + skill_levels["web-development"]
        + skill_levels["databases"]
    ) / 1.5

    cloud_security = 0.325 * (
        skill_levels["cloud-computing"]
        + skill_levels["devops"]
        + skill_levels["security"]
    ) / 1.5

    return math.floor(base + max(systems, development, cloud_security))
```

#### Formula Verification

**Maximum IT Level (all skills 99):**
```
Base           = 0.25 x (99 + 99 + 49)         = 0.25 x 247  = 61.75
Any path       = 0.325 x (99 + 99 + 99) / 1.5  = 0.325 x 198 = 64.35
IT Level       = floor(61.75 + 64.35)           = floor(126.1) = 126  ✓
```

**Minimum IT Level (all skills 1):**
```
Base           = 0.25 x (1 + 1 + 0)             = 0.5
Any path       = 0.325 x (1 + 1 + 1) / 1.5      = 0.65
IT Level       = floor(0.5 + 0.65)               = floor(1.15) = 1
```

**Specialist — maxed one path, foundation 99, other paths untouched (level 1):**
```
Base           = 61.75
Best path      = 64.35
Other paths    = 0.65 each (irrelevant, only max counts)
IT Level       = floor(61.75 + 64.35)            = 126  ✓
```

A developer who maxes Programming, Web Dev, and Databases reaches the same IT Level 126 as a network engineer who maxes Networking, SysAdmin, and Hardware. Both career paths are equally valid.

**Generalist — all skills at level 50:**
```
Base           = 0.25 x (50 + 50 + 25)           = 31.25
All paths      = 0.325 x (50 + 50 + 50) / 1.5    = 32.5
IT Level       = floor(31.25 + 32.5)              = 63
```

A generalist at 50 across the board is IT Level 63 — exactly half of max. They'd need to push deeper into one path to climb higher. This mirrors real IT careers: generalists are valuable, but senior roles reward specialization.

#### Where IT Level Appears

- **User profile card** — IT Level shown prominently (like combat level next to your name in OSRS)
- **Leaderboard** — can rank by IT Level or Total Level (separate tabs)
- **Skill dashboard** — shows IT Level, Total Level, and detected specialization path
- **Content cards** — show the author's/instructor's IT Level for credibility

#### Detected Specialization

Based on which path contributes to IT Level, the system labels the user's build:

| Highest Path | Label | Icon |
|-------------|-------|------|
| Systems & Infrastructure | Infrastructure Specialist | Server rack |
| Software Development | Development Specialist | Code brackets |
| Cloud & Security Operations | Cloud & Security Specialist | Shield + cloud |
| Paths tied (within 5%) | Versatile IT Professional | Star |

This label updates automatically as skills change — no manual selection needed.

### 2.5 Tier System

| Tier | Levels | Color | Hex |
|------|--------|-------|-----|
| Novice | 1-9 | Gray | #9CA3AF |
| Apprentice | 10-29 | Green | #10B981 |
| Journeyman | 30-49 | Blue | #3B82F6 |
| Expert | 50-69 | Purple | #A855F7 |
| Master | 70-89 | Gold | #F59E0B |
| Grandmaster | 90-99 | Cyan | #06B6D4 |

---

## 3. Database Schema

### 3.1 New Tables

#### `skills`

| Column | Type | Notes |
|--------|------|-------|
| id | Integer, PK | Auto-increment |
| name | String(100), unique | e.g. "Networking" |
| slug | String(100), unique, indexed | e.g. "networking" |
| description | Text | Detailed description |
| icon | String(10) | Emoji icon |
| category | String(50) | "technical" or "soft" |
| display_order | Integer | UI sort order |
| is_active | Boolean, default True | Soft delete |
| created_at | DateTime(tz) | |
| updated_at | DateTime(tz) | |

#### `user_skills`

| Column | Type | Notes |
|--------|------|-------|
| id | Integer, PK | |
| user_id | FK(users.id), indexed | |
| skill_id | FK(skills.id), indexed | |
| current_xp | Integer, default 0 | Total accumulated XP |
| current_level | Integer, default 1 | Calculated from XP |
| total_activities_completed | Integer, default 0 | |
| last_activity_at | DateTime, nullable | |
| level_10_achieved_at | DateTime, nullable | Milestone timestamps |
| level_30_achieved_at | DateTime, nullable | |
| level_50_achieved_at | DateTime, nullable | |
| level_75_achieved_at | DateTime, nullable | |
| level_99_achieved_at | DateTime, nullable | |
| created_at | DateTime(tz) | |
| updated_at | DateTime(tz) | |
| **Unique constraint** | (user_id, skill_id) | |

#### `skill_xp_logs`

| Column | Type | Notes |
|--------|------|-------|
| id | Integer, PK | |
| user_id | FK(users.id), indexed | |
| skill_id | FK(skills.id), indexed | |
| xp_gained | Integer | Amount awarded |
| source_type | String(50), indexed | "quiz", "tutorial", "course", "typing_game", "achievement" |
| source_id | String(100), nullable | ID of content that awarded XP |
| source_metadata | JSON, nullable | Score, difficulty, etc. |
| level_before | Integer | Level before this award |
| level_after | Integer | Level after (detects level-ups) |
| earned_at | DateTime, indexed | |

### 3.2 Schema Modifications to Existing Tables

#### `quizzes` table (add column)

| Column | Type | Notes |
|--------|------|-------|
| related_skills | JSON, default `["problem-solving"]` | Array of skill slugs |

The `courses`, `tutorials`, and `typing_word_lists` tables already have `related_skills` JSON columns. Quizzes need this added.

### 3.3 Alembic Migration

Create `backend/alembic/versions/v2_8_add_skill_system_tables.py`:
- Create `skills`, `user_skills`, `skill_xp_logs` tables
- Add `related_skills` column to `quizzes` table
- Add indexes on user_id, skill_id, source_type, earned_at

---

## 4. Backend Implementation

### 4.1 Models (`plugins/skills/models.py`)

Port directly from ITAppBetaV1 `Backend/app/api/v1/services/skills/models.py`. Adapt imports to use BlogCMS's `Base` and `db` patterns (check `backend/app/db/base.py`).

### 4.2 Schemas (`plugins/skills/schemas.py`)

Port from ITAppBetaV1 `Backend/app/api/v1/services/skills/schemas.py`. Key schemas:

- `SkillResponse` - Public skill info
- `SkillCreate` / `SkillUpdate` - Admin CRUD
- `UserSkillProgress` - User's progress on one skill (includes tier, tier_color, xp_progress_percentage)
- `UserSkillsOverview` - All skills with totals (total_level, it_level, specialization, average_level, skills_at_99)
- `SkillXPGainResponse` - Response after awarding XP (level_up, new_tier, achievements)
- `SkillLeaderboardEntry` / `SkillLeaderboard` - Leaderboard data
- `GlobalLeaderboardEntry` - Total-level ranking

### 4.3 Service (`plugins/skills/service.py`)

Port from ITAppBetaV1 `Backend/app/api/v1/services/skills/service.py`. Core functions:

```python
# XP Formula
calculate_xp_for_level(level: int) -> int
calculate_level_from_xp(xp: int) -> int
calculate_xp_to_next_level(current_xp, current_level) -> int
calculate_xp_progress_percentage(current_xp, current_level) -> float
get_skill_tier(level: int) -> tuple[str, str]

# IT Level (Combat Level equivalent) - see section 2.4
calculate_it_level(skill_levels: dict[str, int]) -> int
get_specialization(skill_levels: dict[str, int]) -> tuple[str, str]  # (path, label)

# Path definitions (constants)
FOUNDATION_SKILLS = ["problem-solving", "communication", "project-management"]
SYSTEMS_PATH = ["networking", "systems-administration", "hardware-support"]
DEVELOPMENT_PATH = ["programming", "web-development", "databases"]
CLOUD_SECURITY_PATH = ["cloud-computing", "devops", "security"]

# Category Mapping - maps content categories to skill slugs
CATEGORY_TO_SKILLS_MAP = {
    "networking": ["networking", "problem-solving"],
    "security": ["security", "problem-solving"],
    "python": ["programming", "problem-solving"],
    "web-development": ["web-development", "programming"],
    "cloud": ["cloud-computing", "systems-administration"],
    ...
}

# Core Award Function
async def award_skill_xp(
    db, user_id, skill_slug, xp_amount,
    source_type, source_id=None, source_metadata=None
) -> SkillXPGainResponse

# Achievement Checks
async def check_skill_achievements(db, user_id, skill_slug, new_level, total_level)
```

### 4.4 Routes (`plugins/skills/routes.py`)

**Public endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/skills/` | List all active skills |
| GET | `/api/v1/skills/{skill_id}` | Get skill by ID |
| GET | `/api/v1/skills/slug/{slug}` | Get skill by slug |
| GET | `/api/v1/skills/utils/xp-calculator` | Calculate XP for level |
| GET | `/api/v1/skills/utils/tiers` | Get tier definitions |

**Protected endpoints (requires auth):**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/skills/me/overview` | User's full skills overview |
| GET | `/api/v1/skills/me/{slug}` | Progress on single skill |
| GET | `/api/v1/skills/me/{slug}/history` | Recent XP activity |
| GET | `/api/v1/skills/me/{slug}/progression` | XP graph data (7-365 days) |

**Leaderboard endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/skills/leaderboards/global` | Global leaderboard (total level) |
| GET | `/api/v1/skills/{slug}/leaderboard` | Per-skill leaderboard |

### 4.5 Admin Routes (`plugins/skills/admin_routes.py`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/skills/` | Create skill |
| PUT | `/api/v1/admin/skills/{skill_id}` | Update skill |
| DELETE | `/api/v1/admin/skills/{skill_id}` | Delete skill (with safety check) |
| GET | `/api/v1/admin/skills/analytics/overview` | System-wide analytics |
| GET | `/api/v1/admin/skills/analytics/{slug}` | Per-skill analytics |
| GET | `/api/v1/admin/skills/analytics/xp-logs/recent` | Recent XP activity log |

### 4.6 Seed Script (`plugins/skills/seed.py`)

Port from ITAppBetaV1 `Backend/scripts/seed_skills.py`. Seeds the 12 default skills:

1. Networking, Security, Programming, Systems Administration
2. Cloud Computing, Databases, DevOps, Web Development
3. Hardware & Support, Communication, Problem Solving, Project Management

### 4.7 Plugin Registration (`backend/app/main.py`)

Add to the plugin loading block:

```python
if settings.PLUGINS_ENABLED.get("skills", False):
    from app.plugins.skills.routes import router as skills_router
    from app.plugins.skills.admin_routes import router as skills_admin_router
    app.include_router(skills_router, prefix="/api/v1/skills", tags=["Skills"])
    app.include_router(skills_admin_router, prefix="/api/v1/admin/skills", tags=["Skills Admin"])
```

---

## 5. Integration Points (Hooking Into Existing Systems)

### 5.1 Course Completion -> Skill XP

**File to modify:** `backend/app/plugins/courses/routes.py` (or wherever course completion is handled)

When a course module/section is completed:

```python
from app.plugins.skills.service import award_skill_xp, CATEGORY_TO_SKILLS_MAP

# After marking course complete and awarding global XP:
if course.related_skills:
    for skill_slug in course.related_skills:
        await award_skill_xp(
            db=db, user_id=user_id, skill_slug=skill_slug,
            xp_amount=course.xp_reward or 250,
            source_type="course", source_id=str(course.id),
            source_metadata={"course_title": course.title, "level": course.level}
        )
```

### 5.2 Tutorial Completion -> Skill XP

**File to modify:** `backend/app/plugins/tutorials/routes.py`

When all tutorial steps are completed:

```python
if tutorial.related_skills:
    for skill_slug in tutorial.related_skills:
        await award_skill_xp(
            db=db, user_id=user_id, skill_slug=skill_slug,
            xp_amount=tutorial.xp_reward or 100,
            source_type="tutorial", source_id=str(tutorial.id),
            source_metadata={"tutorial_title": tutorial.title, "difficulty": tutorial.difficulty}
        )
```

### 5.3 Quiz Completion -> Skill XP

**File to modify:** `backend/app/plugins/quizzes/routes.py`

After quiz submission and scoring:

```python
# XP scales with score
xp_amount = quiz.xp_reward if score >= quiz.passing_score else quiz.xp_reward // 4
if score == 100:
    xp_amount = quiz.xp_perfect or int(quiz.xp_reward * 1.5)

if quiz.related_skills:
    for skill_slug in quiz.related_skills:
        await award_skill_xp(
            db=db, user_id=user_id, skill_slug=skill_slug,
            xp_amount=xp_amount, source_type="quiz",
            source_id=str(quiz.id),
            source_metadata={"score": score, "difficulty": quiz.difficulty}
        )
```

### 5.4 Typing Game -> Skill XP

**File to modify:** `backend/app/plugins/typing_game/routes.py`

After game session ends:

```python
# Communication skill always, plus word list related skills
skill_slugs = ["communication"]
if word_list and word_list.related_skills:
    skill_slugs.extend(word_list.related_skills)

for skill_slug in set(skill_slugs):
    await award_skill_xp(
        db=db, user_id=user_id, skill_slug=skill_slug,
        xp_amount=calculate_typing_skill_xp(wpm, accuracy),
        source_type="typing_game", source_id=str(session.id),
        source_metadata={"wpm": wpm, "accuracy": accuracy}
    )
```

### 5.5 Achievement System Integration

**File to modify:** `backend/app/plugins/shared/achievement_service.py`

Add new unlock condition types:

```python
# New condition types for skills
{"type": "skill_level", "skill": "networking", "level": 50}
{"type": "skill_tier", "skill": "any", "tier": "master"}
{"type": "total_level", "value": 500}
{"type": "skills_at_99", "count": 1}
```

When skill XP is awarded and a level-up occurs, call:

```python
await check_skill_achievements(db, user_id, skill_slug, new_level, total_level)
```

### 5.6 Daily Challenges Integration

Add new challenge types to the daily challenge system:

```python
# New challenge types
"skill_xp_earn"      # Earn X skill XP in any skill
"skill_level_up"     # Level up any skill
"skill_specific_xp"  # Earn X XP in a specific skill
```

---

## 6. Frontend Implementation

### 6.1 Types (`plugins/skills/types/index.ts`)

```typescript
export interface Skill {
  id: number;
  name: string;
  slug: string;
  description: string;
  icon: string;
  category: 'technical' | 'soft';
  display_order: number;
  is_active: boolean;
}

export interface UserSkillProgress {
  skill_id: number;
  skill_name: string;
  skill_slug: string;
  skill_icon: string;
  skill_category: string;
  current_xp: number;
  current_level: number;
  xp_to_next_level: number;
  xp_progress_percentage: number;
  total_activities_completed: number;
  last_activity_at: string | null;
  tier: string;
  tier_color: string;
  level_10_achieved: boolean;
  level_30_achieved: boolean;
  level_50_achieved: boolean;
  level_75_achieved: boolean;
  level_99_achieved: boolean;
}

export interface UserSkillsOverview {
  skills: UserSkillProgress[];
  total_level: number;        // Sum of all 12 skill levels (max 1188)
  max_total_level: number;    // 1188
  it_level: number;           // Combat Level equivalent (max 126)
  max_it_level: number;       // 126
  specialization: string;     // "Infrastructure Specialist" | "Development Specialist" | etc.
  specialization_path: string; // "systems" | "development" | "cloud_security" | "versatile"
  average_level: number;
  skills_at_99: number;
  skills_at_50_plus: number;
}

export type SkillTier = 'Novice' | 'Apprentice' | 'Journeyman'
                      | 'Expert' | 'Master' | 'Grandmaster';

export interface SkillXPGainResponse {
  skill_slug: string;
  xp_gained: number;
  total_xp: number;
  old_level: number;
  new_level: number;
  level_up: boolean;
  new_tier: string | null;
  tier_changed: boolean;
  achievements_unlocked: string[];
}

export interface SkillLeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  avatar_url: string | null;
  skill_level: number;
  skill_xp: number;
  total_activities: number;
}

export interface GlobalLeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  avatar_url: string | null;
  it_level: number;           // Combat Level equivalent (1-126)
  total_level: number;        // Sum of all skills (max 1188)
  total_xp: number;
  specialization: string;     // Detected career path label
  skills_at_99: number;
}
```

### 6.2 API Service (`plugins/skills/services/skillsApi.ts`)

Use the existing `apiClient` from `frontend/src/api/client.ts`:

```typescript
import { apiClient } from '@/api/client';

// Public
export const getAllSkills = () => apiClient.get('/skills/');
export const getSkillBySlug = (slug: string) => apiClient.get(`/skills/slug/${slug}`);

// Protected
export const getUserSkillsOverview = () => apiClient.get('/skills/me/overview');
export const getUserSkillProgress = (slug: string) => apiClient.get(`/skills/me/${slug}`);
export const getUserSkillHistory = (slug: string, limit = 20) =>
  apiClient.get(`/skills/me/${slug}/history?limit=${limit}`);
export const getUserSkillProgression = (slug: string, days = 30) =>
  apiClient.get(`/skills/me/${slug}/progression?days=${days}`);

// Leaderboards
export const getGlobalLeaderboard = (limit = 100) =>
  apiClient.get(`/skills/leaderboards/global?limit=${limit}`);
export const getSkillLeaderboard = (slug: string, limit = 100) =>
  apiClient.get(`/skills/${slug}/leaderboard?limit=${limit}`);

// Admin
export const adminCreateSkill = (data: SkillCreate) => apiClient.post('/admin/skills/', data);
export const adminUpdateSkill = (id: number, data: SkillUpdate) =>
  apiClient.put(`/admin/skills/${id}`, data);
export const adminDeleteSkill = (id: number) => apiClient.delete(`/admin/skills/${id}`);
export const adminGetAnalyticsOverview = () =>
  apiClient.get('/admin/skills/analytics/overview');
export const adminGetSkillAnalytics = (slug: string) =>
  apiClient.get(`/admin/skills/analytics/${slug}`);
export const adminGetRecentXPLogs = (limit = 50) =>
  apiClient.get(`/admin/skills/analytics/xp-logs/recent?limit=${limit}`);
```

### 6.3 Pages

#### SkillsDashboard (`pages/SkillsDashboard.tsx`)
- **IT Level** displayed prominently at top (large number, 1-126) with specialization label
- **Total Level** shown alongside (sum of all 12 skills, max 1,188)
- Stats row: IT Level / Total Level / Average Level / Skills at 50+ / Skills at 99
- Specialization path indicator (highlights which 3 skills are driving your IT Level)
- Grid of all 12 skills with progress bars, grouped by Foundation / Systems / Development / Cloud & Security
- Category filter (All / Foundation / Systems & Infrastructure / Software Development / Cloud & Security)
- Clickable cards linking to skill detail pages
- Link to global leaderboard

#### SkillDetailPage (`pages/SkillDetailPage.tsx`)
- Skill icon, name, tier badge, level, XP progress bar
- Milestone markers (10, 30, 50, 75, 99) with achieved/locked states
- Tabs:
  - **Activity** - Recent XP gains with source type icons
  - **Progression** - Line chart of XP over time (7/30/90/365 day selector)
  - **Leaderboard** - Top users for this skill with current user rank

#### SkillLeaderboardPage (`pages/SkillLeaderboardPage.tsx`)
- **Three ranking modes** (tabs):
  - **IT Level** — ranked by IT Level (1-126), shows specialization badge (default view)
  - **Total Level** — ranked by sum of all skills (max 1,188), rewards well-roundedness
  - **Per-Skill** — dropdown to pick a specific skill, ranked by that skill's level/XP
- User rank highlight with "You" indicator
- Specialization icon shown next to each user's name

#### SkillManagerPage (`pages/admin/SkillManagerPage.tsx`)
- Table of all skills with edit/delete
- Create new skill form
- Analytics dashboard:
  - Total users with skill progress
  - Total XP awarded
  - XP by source type breakdown (pie/bar chart)
  - Most popular skills
  - Recent XP activity log (table with filters)
  - Per-skill analytics (user count, avg level, level distribution)

### 6.4 Reusable Components

#### SkillBadges
Small colored pills showing related skills on course/tutorial/quiz cards. Port from ITAppBetaV1 `src/components/Skills/SkillBadges.tsx`.

#### SkillSelector (Admin)
Multi-select dropdown for admins to assign skills when creating/editing courses, tutorials, quizzes. Port from ITAppBetaV1 `src/components/Admin/SkillSelector.tsx`. Integrate into:
- Course editor (`frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx`)
- Tutorial editor (`frontend/src/plugins/tutorials/pages/admin/TutorialEditorPage.tsx`)
- Quiz editor (`frontend/src/plugins/quizzes/pages/admin/QuizEditorPage.tsx`)
- Typing game word list admin

#### ProgressionGraph
XP progression line chart with time range selector. Port from ITAppBetaV1 `src/components/Skills/ProgressionGraph.tsx`. Uses Recharts (check if already in BlogCMS dependencies, otherwise install).

#### TierBadge
Compact badge showing tier name with tier color. Used on skill cards and leaderboard entries.

#### SkillProgressBar
Progress bar from current level to next level, showing XP fraction and percentage.

### 6.5 Routes (`frontend/src/routes/routes.tsx`)

Add to the routes configuration:

```typescript
// Public skill pages (protected - requires login)
{ path: '/skills', component: SkillsDashboard, requiresAuth: true }
{ path: '/skills/leaderboard', component: SkillLeaderboardPage, requiresAuth: true }
{ path: '/skills/:slug', component: SkillDetailPage, requiresAuth: true }

// Admin skill pages
{ path: '/admin/skills', component: SkillManagerPage, requiresAdmin: true }
```

### 6.6 Admin Navigation (`frontend/src/config/adminNavigation.ts`)

Add to the `lms` section:

```typescript
{
  label: 'Skills',
  icon: 'Trophy',  // or appropriate icon
  requiresPlugin: 'skills',
  children: [
    { label: 'All Skills', path: '/admin/skills' },
    { label: 'Analytics', path: '/admin/skills?tab=analytics' },
  ]
}
```

### 6.7 Header/Navigation

Add a "Skills" link to the main site navigation in `frontend/src/components/layout/Header.tsx`, conditionally shown when the skills plugin is enabled.

---

## 7. Implementation Order

### Phase 1: Backend Foundation
1. Create alembic migration for `skills`, `user_skills`, `skill_xp_logs` tables
2. Add `related_skills` column to `quizzes` table
3. Create `plugins/skills/models.py`
4. Create `plugins/skills/schemas.py`
5. Create `plugins/skills/service.py` (XP formula, tier calc, award logic)
6. Create `plugins/skills/crud.py`
7. Create `plugins/skills/seed.py` and run it
8. Register plugin in `main.py` and `.env` / settings

### Phase 2: Backend API
9. Create `plugins/skills/routes.py` (public + protected endpoints)
10. Create `plugins/skills/admin_routes.py`
11. Test all endpoints with manual API calls

### Phase 3: Integration Hooks
12. Hook course completion -> `award_skill_xp()`
13. Hook tutorial completion -> `award_skill_xp()`
14. Hook quiz submission -> `award_skill_xp()`
15. Hook typing game session -> `award_skill_xp()`
16. Add skill-level achievement conditions to `achievement_service.py`

### Phase 4: Frontend Core
17. Create `plugins/skills/types/index.ts`
18. Create `plugins/skills/services/skillsApi.ts`
19. Create `SkillsDashboard.tsx`
20. Create `SkillDetailPage.tsx` (with activity, progression, leaderboard tabs)
21. Create `SkillLeaderboardPage.tsx`
22. Add routes to `routes.tsx`
23. Add "Skills" to site navigation

### Phase 5: Frontend Components & Admin
24. Create `SkillBadges.tsx` and add to course/tutorial/quiz cards
25. Create `SkillSelector.tsx` and add to content editor pages
26. Create `SkillManagerPage.tsx` (admin)
27. Add skills section to `adminNavigation.ts`
28. Create `ProgressionGraph.tsx` (check/add Recharts dependency)
29. Create `TierBadge.tsx`, `SkillProgressBar.tsx`

### Phase 6: Polish
30. Add skill level-up notification/toast on XP award
31. Add skill progress widget to user profile/dashboard
32. Verify daily challenge integration
33. Test full flow: complete content -> XP awarded -> level up -> achievement unlocked

---

## 8. Files to Create

| # | File | Source Reference |
|---|------|-----------------|
| 1 | `backend/alembic/versions/v2_8_add_skill_system_tables.py` | New migration |
| 2 | `backend/app/plugins/skills/__init__.py` | Empty |
| 3 | `backend/app/plugins/skills/models.py` | ITApp `services/skills/models.py` |
| 4 | `backend/app/plugins/skills/schemas.py` | ITApp `services/skills/schemas.py` |
| 5 | `backend/app/plugins/skills/service.py` | ITApp `services/skills/service.py` |
| 6 | `backend/app/plugins/skills/crud.py` | New, following BlogCMS patterns |
| 7 | `backend/app/plugins/skills/routes.py` | ITApp `endpoints/skills/skills.py` |
| 8 | `backend/app/plugins/skills/admin_routes.py` | ITApp `endpoints/skills/admin.py` |
| 9 | `backend/app/plugins/skills/seed.py` | ITApp `scripts/seed_skills.py` |
| 10 | `frontend/src/plugins/skills/types/index.ts` | ITApp `services/api/skills.api.ts` |
| 11 | `frontend/src/plugins/skills/services/skillsApi.ts` | ITApp `services/api/skills.api.ts` |
| 12 | `frontend/src/plugins/skills/pages/SkillsDashboard.tsx` | ITApp `pages/Skills/SkillsDashboard.tsx` |
| 13 | `frontend/src/plugins/skills/pages/SkillDetailPage.tsx` | ITApp `pages/Skills/SkillDetail.tsx` |
| 14 | `frontend/src/plugins/skills/pages/SkillLeaderboardPage.tsx` | ITApp `pages/Skills/GlobalLeaderboard.tsx` |
| 15 | `frontend/src/plugins/skills/pages/admin/SkillManagerPage.tsx` | ITApp `pages/admin/SkillsAdmin.tsx` |
| 16 | `frontend/src/plugins/skills/components/SkillCard.tsx` | New |
| 17 | `frontend/src/plugins/skills/components/SkillBadges.tsx` | ITApp `components/Skills/SkillBadges.tsx` |
| 18 | `frontend/src/plugins/skills/components/SkillProgressBar.tsx` | New |
| 19 | `frontend/src/plugins/skills/components/ProgressionGraph.tsx` | ITApp `components/Skills/ProgressionGraph.tsx` |
| 20 | `frontend/src/plugins/skills/components/SkillSelector.tsx` | ITApp `components/Admin/SkillSelector.tsx` |
| 21 | `frontend/src/plugins/skills/components/TierBadge.tsx` | New |
| 22 | `frontend/src/plugins/skills/hooks/useSkills.ts` | New |

## 9. Files to Modify

| # | File | Change |
|---|------|--------|
| 1 | `backend/app/main.py` | Register skills plugin routes |
| 2 | `backend/app/core/config.py` (or `.env`) | Add `skills` to PLUGINS_ENABLED |
| 3 | `backend/app/plugins/courses/routes.py` | Add skill XP hook on completion |
| 4 | `backend/app/plugins/tutorials/routes.py` | Add skill XP hook on completion |
| 5 | `backend/app/plugins/quizzes/routes.py` | Add skill XP hook on submission |
| 6 | `backend/app/plugins/typing_game/routes.py` | Add skill XP hook on session end |
| 7 | `backend/app/plugins/shared/achievement_service.py` | Add skill-level condition types |
| 8 | `frontend/src/routes/routes.tsx` | Add skill routes |
| 9 | `frontend/src/config/adminNavigation.ts` | Add Skills admin nav items |
| 10 | `frontend/src/components/layout/Header.tsx` | Add Skills nav link |
| 11 | `frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx` | Add SkillSelector |
| 12 | `frontend/src/plugins/quizzes/pages/admin/QuizEditorPage.tsx` | Add SkillSelector |

### 9.1 Exact Line Numbers for Integration Hooks (from Exploration)

| File | Line Number | Change Description |
|------|-------------|-------------------|
| `backend/app/plugins/tutorials/routes.py` | ~291-295 | Import and call `award_skill_xp()` after `tutorial_completed` check |
| `backend/app/plugins/courses/routes.py` | ~331-342 | Import and call `award_skill_xp()` after course completion detected |
| `backend/app/plugins/quizzes/routes.py` | ~253-260 | Import and call `award_skill_xp()` after `xp_awarded` assignment |
| `backend/app/plugins/typing_game/routes.py` | ~971-985 | Import and call `award_skill_xp()` in `submit_game_v2` after metrics |
| `backend/app/plugins/shared/xp_service.py` | ~63 | Add `"skill_xp_earn": 0` placeholder to `REWARDS` dict |
| `backend/app/core/config.py` | ~90 | Add `"skills": False` to `PLUGINS_ENABLED` dict |
| `backend/app/main.py` | ~150 | Add skills plugin router registration block |

---

## 10. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| XP formula mismatch between global XP and skill XP confuses users | Medium | Clearly separate "Account Level" from "Skill Levels" in UI |
| Performance on leaderboard queries with many users | Low | Add DB indexes, paginate results, cache with TTL |
| `related_skills` JSON arrays become inconsistent with actual skill slugs | Medium | Validate slugs against skills table on save; admin SkillSelector uses live data |
| Large `skill_xp_logs` table over time | Low | Add archival strategy or retention policy after 1 year |
| Skill plugin disabled but content still has `related_skills` fields | Low | Guard all skill XP calls with plugin-enabled check; fields are harmless when unused |

---

## 11. Testing Checklist

- [ ] Seed script creates all 12 skills correctly
- [ ] `GET /api/v1/skills/` returns all active skills
- [ ] `GET /api/v1/skills/me/overview` returns 12 skills at level 1 for new user
- [ ] Completing a tutorial awards skill XP to related skills
- [ ] Completing a course awards skill XP to related skills
- [ ] Submitting a quiz awards skill XP scaled by score
- [ ] Typing game session awards Communication XP
- [ ] Level-up is correctly detected and returned in response
- [ ] Tier changes at correct level boundaries
- [ ] Milestone timestamps are set on first reaching levels 10/30/50/75/99
- [ ] Global leaderboard returns users sorted by total level
- [ ] Per-skill leaderboard returns users sorted by skill XP
- [ ] Admin can create, update, and delete skills
- [ ] Admin analytics show correct user counts and XP totals
- [ ] SkillSelector component loads skills and saves selections
- [ ] SkillBadges display correctly on content cards
- [ ] SkillsDashboard shows all skills with correct progress
- [ ] SkillDetailPage shows history, progression graph, and leaderboard
- [ ] Skill level-up triggers achievement check
- [ ] IT Level calculates correctly (all skills 1 = IT Level 1, all skills 99 = IT Level 126)
- [ ] IT Level updates when any contributing skill levels up
- [ ] Specialization label detects correct path based on highest path score
- [ ] Specialization shows "Versatile IT Professional" when paths are within 5%
- [ ] Leaderboard supports ranking by IT Level, Total Level, and per-skill
- [ ] User profile displays IT Level prominently with specialization label
- [ ] Plugin can be disabled without errors in other plugins
