# BlogCMS Implementation Plan
## Seeding, Placeholder Removal, Content Creation & Homepage Redesign

**Created:** 2026-01-27
**Status:** Planning Complete - Ready for Implementation

---

## Overview

This plan covers 7 phases of work for the BlogCMS project:
1. Running existing seed scripts + creating a master seed orchestrator
2. Creating quiz seed data for beginners
3. Creating achievement seed data
4. Fixing admin pages with fake data (3 pages)
5. Wiring the course content block editor
6. Improving seed content for IT beginners
7. Homepage redesign (Learning Paths widget + Daily Challenge improvements)

Each phase is **independently deployable**. Earlier phases unblock later ones.

---

## Phase 1: Run Existing Seeds + Master Seed Script

**Goal:** Get skills and typing word lists seeded on production, create a master seed runner.
**Effort:** Small - existing scripts just need orchestration.

### 1A. Create Master Seed Script - DONE

**New file:** `backend/scripts/seed_all.py` - CREATED

```python
#!/usr/bin/env python3
"""
Master seed script for BlogCMS.
Run with: python scripts/seed_all.py [--all | --skills | --word-lists | --courses | --tutorials | --quizzes | --achievements]
"""
import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SessionLocal


def seed_skills(db):
    """Seed 12 IT skills."""
    from app.plugins.skills.seed import seed_skills as _seed_skills
    _seed_skills(db)
    print("✓ Skills seeded (12 skills)")


def seed_word_lists():
    """Seed 9 typing word lists."""
    from scripts.seed_word_lists import seed_word_lists as _seed_word_lists
    _seed_word_lists()
    print("✓ Word lists seeded (9 lists)")


def seed_courses(db):
    """Seed sample courses."""
    from app.plugins.courses.seed_data import create_sample_courses
    create_sample_courses(db)
    print("✓ Courses seeded")


def seed_tutorials():
    """Seed tutorials and categories."""
    from app.plugins.tutorials.seed_data import main as seed_tutorials_main
    seed_tutorials_main()
    print("✓ Tutorials seeded (3 tutorials + 4 categories)")


def seed_quizzes(db):
    """Seed beginner quizzes."""
    from app.plugins.quizzes.seed_data import seed_quizzes as _seed_quizzes
    _seed_quizzes(db)
    print("✓ Quizzes seeded")


def seed_achievements(db):
    """Seed achievement definitions."""
    from app.plugins.shared.seed_achievements import seed_achievements as _seed_achievements
    _seed_achievements(db)
    print("✓ Achievements seeded")


def main():
    parser = argparse.ArgumentParser(description="Seed BlogCMS database")
    parser.add_argument("--all", action="store_true", help="Run all seeds")
    parser.add_argument("--skills", action="store_true", help="Seed skills")
    parser.add_argument("--word-lists", action="store_true", help="Seed typing word lists")
    parser.add_argument("--courses", action="store_true", help="Seed courses")
    parser.add_argument("--tutorials", action="store_true", help="Seed tutorials")
    parser.add_argument("--quizzes", action="store_true", help="Seed quizzes")
    parser.add_argument("--achievements", action="store_true", help="Seed achievements")

    args = parser.parse_args()

    # If no args provided, show help
    if not any([args.all, args.skills, args.word_lists, args.courses,
                args.tutorials, args.quizzes, args.achievements]):
        parser.print_help()
        return

    db = SessionLocal()
    results = {"success": [], "failed": []}

    try:
        if args.all or args.skills:
            try:
                seed_skills(db)
                results["success"].append("skills")
            except Exception as e:
                print(f"✗ Skills failed: {e}")
                results["failed"].append("skills")

        if args.all or args.word_lists:
            try:
                seed_word_lists()
                results["success"].append("word_lists")
            except Exception as e:
                print(f"✗ Word lists failed: {e}")
                results["failed"].append("word_lists")

        if args.all or args.courses:
            try:
                seed_courses(db)
                results["success"].append("courses")
            except Exception as e:
                print(f"✗ Courses failed: {e}")
                results["failed"].append("courses")

        if args.all or args.tutorials:
            try:
                seed_tutorials()
                results["success"].append("tutorials")
            except Exception as e:
                print(f"✗ Tutorials failed: {e}")
                results["failed"].append("tutorials")

        if args.all or args.quizzes:
            try:
                seed_quizzes(db)
                results["success"].append("quizzes")
            except Exception as e:
                print(f"✗ Quizzes failed: {e}")
                results["failed"].append("quizzes")

        if args.all or args.achievements:
            try:
                seed_achievements(db)
                results["success"].append("achievements")
            except Exception as e:
                print(f"✗ Achievements failed: {e}")
                results["failed"].append("achievements")

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Database error: {e}")
    finally:
        db.close()

    # Summary
    print("\n" + "="*40)
    print("SEED SUMMARY")
    print("="*40)
    print(f"✓ Success: {', '.join(results['success']) or 'None'}")
    print(f"✗ Failed: {', '.join(results['failed']) or 'None'}")


if __name__ == "__main__":
    main()
```

### 1B. Run Existing Seeds on Production

Execute in order:
```bash
cd backend
python -m app.plugins.skills.seed           # 12 IT skills
python scripts/seed_word_lists.py           # 9 word lists
python -m app.plugins.courses.seed_data     # 2 sample courses
python -m app.plugins.tutorials.seed_data   # 3 tutorials + 4 categories
```

### Files Involved
| File | Action |
|------|--------|
| `backend/scripts/seed_all.py` | **CREATE** |
| `backend/app/plugins/skills/seed.py` | Existing, no changes |
| `backend/scripts/seed_word_lists.py` | Existing, no changes |
| `backend/app/plugins/courses/seed_data.py` | Existing, no changes |
| `backend/app/plugins/tutorials/seed_data.py` | Existing, no changes |

---

## Phase 2: Create Quiz Seed Script - DONE

**Goal:** Create beginner-friendly IT quizzes.
**Effort:** Medium - requires writing quiz content.

**New file:** `backend/app/plugins/quizzes/seed_data.py` - CREATED (5 quizzes, 46 questions)

### Quiz Definitions

| Quiz | Category | Difficulty | Questions | XP | Skills |
|------|----------|------------|-----------|----|----|
| IT Basics Quiz | IT Fundamentals | easy | 10 | 50/100 | hardware-support, problem-solving |
| Networking Fundamentals | Networking | easy | 10 | 50/100 | networking |
| Cybersecurity Basics | Security | medium | 8 | 75/150 | security |
| Python Basics Quiz | Programming | easy | 10 | 50/100 | programming |
| Help Desk & Support | IT Support | easy | 8 | 50/100 | hardware-support, communication |

### Quiz 1: IT Basics Quiz - Sample Questions

```python
{
    "id": "it-basics-quiz",
    "title": "IT Basics Quiz",
    "description": "Test your knowledge of fundamental IT concepts",
    "category": "IT Fundamentals",
    "difficulty": "easy",
    "status": "published",
    "is_featured": True,
    "xp_reward": 50,
    "xp_reward_perfect": 100,
    "passing_score": 70,
    "time_limit_minutes": 15,
    "related_skills": ["hardware-support", "problem-solving"],
    "questions": [
        {
            "question_type": "MULTIPLE_CHOICE",
            "question_text": "What does CPU stand for?",
            "options": [
                {"id": "a", "text": "Central Processing Unit", "is_correct": True},
                {"id": "b", "text": "Computer Personal Unit", "is_correct": False},
                {"id": "c", "text": "Central Power Unit", "is_correct": False},
                {"id": "d", "text": "Core Processing Utility", "is_correct": False}
            ],
            "correct_answer": "a",
            "explanation": "CPU stands for Central Processing Unit - it's the 'brain' of the computer.",
            "points": 10,
            "order_index": 1
        },
        {
            "question_type": "TRUE_FALSE",
            "question_text": "RAM is a type of permanent storage.",
            "options": [
                {"id": "true", "text": "True", "is_correct": False},
                {"id": "false", "text": "False", "is_correct": True}
            ],
            "correct_answer": "false",
            "explanation": "RAM (Random Access Memory) is volatile - it loses data when power is off.",
            "points": 10,
            "order_index": 2
        },
        # ... 8 more questions covering:
        # - Input vs output devices
        # - File extensions (.exe, .pdf, .docx)
        # - Basic troubleshooting steps
        # - Operating system functions
        # - Storage types (HDD vs SSD)
        # - What is a browser
        # - Keyboard shortcuts (Ctrl+C, Ctrl+V)
        # - What is an IP address (basic)
    ]
}
```

### Files Involved
| File | Action |
|------|--------|
| `backend/app/plugins/quizzes/seed_data.py` | **CREATE** |
| `backend/scripts/seed_all.py` | MODIFY - add quiz seed |

---

## Phase 3: Create Achievement Seed Script - DONE

**Goal:** Seed beginner-friendly achievement definitions.
**Effort:** Small-Medium

**New file:** `backend/app/plugins/shared/seed_achievements.py` - CREATED (16 achievements)

### Achievement Definitions

| ID | Name | Category | Rarity | Requirement | XP |
|----|------|----------|--------|-------------|-----|
| first-tutorial-complete | First Steps | TUTORIALS | COMMON | Complete 1 tutorial | 25 |
| five-tutorials-complete | Eager Learner | TUTORIALS | UNCOMMON | Complete 5 tutorials | 75 |
| ten-tutorials-complete | Knowledge Seeker | TUTORIALS | RARE | Complete 10 tutorials | 150 |
| first-course-enroll | Student Enrolled | COURSES | COMMON | Enroll in 1 course | 15 |
| first-course-complete | Graduate | COURSES | UNCOMMON | Complete 1 course | 100 |
| three-courses-complete | Scholar | COURSES | RARE | Complete 3 courses | 200 |
| first-typing-game | Key Tapper | TYPING | COMMON | Complete 1 typing game | 15 |
| typing-50wpm | Speed Typist | TYPING | UNCOMMON | Reach 50 WPM | 50 |
| typing-100wpm | Lightning Fingers | TYPING | EPIC | Reach 100 WPM | 200 |
| typing-10-games | Practice Makes Perfect | TYPING | UNCOMMON | Play 10 typing games | 50 |
| streak-3-days | Getting Started | STREAK | COMMON | 3-day streak | 25 |
| streak-7-days | Dedicated Learner | STREAK | UNCOMMON | 7-day streak | 75 |
| streak-30-days | Unstoppable | STREAK | EPIC | 30-day streak | 300 |
| first-quiz-pass | Quiz Whiz | SPECIAL | COMMON | Pass 1 quiz | 25 |
| perfect-quiz | Perfect Score | SPECIAL | RARE | Score 100% on quiz | 150 |
| level-10 | Rising Star | SPECIAL | RARE | Reach level 10 | 200 |

### Files Involved
| File | Action |
|------|--------|
| `backend/app/plugins/shared/seed_achievements.py` | **CREATE** |
| `backend/scripts/seed_all.py` | MODIFY - add achievement seed |

---

## Phase 4: Fix Admin Pages - Replace Fake Data - DONE

**Goal:** Wire three admin pages to real backend data.
**Effort:** Medium

### 4A. Fix LMSProgressPage (Easiest) - DONE

**Backend:** Already exists at `GET /api/v1/admin/stats/lms/progress`

**File:** `frontend/src/pages/admin/LMSProgressPage.tsx` - UPDATED to use real API

**Changes:**
```typescript
// Replace lines 57-63 mock data with:
const loadStudentProgress = async () => {
  setIsLoading(true);
  try {
    const response = await apiClient.get('/api/v1/admin/stats/lms/progress');
    setStudents(response.data.students);
    // Optionally use response.data.totals directly
  } catch (error) {
    toast.error('Failed to load student progress');
    console.error(error);
  } finally {
    setIsLoading(false);
  }
};
```

### 4B. Fix GameLeaderboardAdmin (Needs New Endpoint) - DONE

**Backend - Add endpoint to:** `backend/app/plugins/typing_game/routes.py` - ADDED admin leaderboard endpoint
**Frontend file:** `frontend/src/pages/admin/GameLeaderboardAdmin.tsx` - UPDATED to use real API

```python
@router.get("/admin/leaderboard")
async def get_admin_leaderboard(
    sort: str = Query("best_wpm"),
    period: str = Query("all"),
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin-only leaderboard with extra user info."""
    from datetime import datetime, timedelta
    from sqlalchemy import func

    # Period filter
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    period_filters = {
        "today": TypingGameSession.created_at >= today_start,
        "week": TypingGameSession.created_at >= today_start - timedelta(days=7),
        "month": TypingGameSession.created_at >= today_start - timedelta(days=30),
        "all": True
    }

    # Query with user join
    query = db.query(
        UserTypingStats,
        User.email,
        User.display_name,
        User.total_points.label("total_xp")
    ).join(User, UserTypingStats.user_id == User.id)

    # Sort
    sort_columns = {
        "best_wpm": UserTypingStats.best_wpm.desc(),
        "avg_wpm": UserTypingStats.average_wpm.desc(),
        "games_played": UserTypingStats.total_games_completed.desc()
    }
    query = query.order_by(sort_columns.get(sort, UserTypingStats.best_wpm.desc()))

    results = query.limit(limit).all()

    # Build response with suspicious flag
    entries = []
    for stats, email, display_name, total_xp in results:
        is_suspicious = stats.best_wpm > 180 and stats.total_games_completed < 10
        entries.append({
            "id": stats.user_id,
            "username": display_name,
            "email": email,
            "best_wpm": stats.best_wpm,
            "avg_wpm": stats.average_wpm,
            "games_played": stats.total_games_completed,
            "total_xp": total_xp or 0,
            "is_suspicious": is_suspicious
        })

    # Stats
    stats = {
        "total_players": db.query(UserTypingStats).filter(
            UserTypingStats.total_games_completed > 0
        ).count(),
        "games_played_today": db.query(TypingGameSession).filter(
            TypingGameSession.created_at >= today_start,
            TypingGameSession.is_completed == True
        ).count(),
        "avg_wpm_global": db.query(func.avg(UserTypingStats.average_wpm)).scalar() or 0,
        "top_wpm_today": db.query(func.max(TypingGameSession.wpm)).filter(
            TypingGameSession.created_at >= today_start
        ).scalar() or 0
    }

    return {"entries": entries, "stats": stats}
```

**Frontend:** `frontend/src/pages/admin/GameLeaderboardAdmin.tsx`

Replace lines 57-86 in `loadLeaderboard`:
```typescript
const loadLeaderboard = async () => {
  setIsLoading(true);
  try {
    const response = await apiClient.get('/api/v1/games/typing/admin/leaderboard', {
      params: { sort: sortBy, period }
    });
    setLeaderboard(response.data.entries);
    setStats(response.data.stats);
  } catch (error) {
    toast.error('Failed to load leaderboard');
  } finally {
    setIsLoading(false);
  }
};
```

### 4C. Fix RolesAdmin (Needs Simple Endpoint) - DONE

**Backend - Add to:** `backend/app/api/v1/endpoints/admin/stats.py` - ADDED role counts endpoint
**Frontend file:** `frontend/src/pages/admin/RolesAdmin.tsx` - UPDATED to use real API and real role names

```python
@router.get("/users/role-counts")
async def get_user_role_counts(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get user counts by role."""
    from sqlalchemy import func
    counts = db.query(User.role, func.count(User.id)).group_by(User.role).all()
    return {role.value: count for role, count in counts}
```

**Frontend:** `frontend/src/pages/admin/RolesAdmin.tsx`

1. Update `DEFAULT_ROLES` to use real role IDs (APPRENTICE, SUPPORTER, CONTRIBUTOR, MENTOR, TUTOR, AUTHOR, ADMIN)
2. Replace mock data load:
```typescript
const loadRoles = async () => {
  try {
    const counts = await apiClient.get('/api/v1/admin/stats/users/role-counts');
    const updatedRoles = DEFAULT_ROLES.map(role => ({
      ...role,
      user_count: counts.data[role.id.toUpperCase()] || 0
    }));
    setRoles(updatedRoles);
  } catch (error) {
    console.error('Failed to load role counts:', error);
  }
};
```

### Files Involved
| File | Action |
|------|--------|
| `frontend/src/pages/admin/LMSProgressPage.tsx` | MODIFY |
| `backend/app/plugins/typing_game/routes.py` | MODIFY - add admin endpoint |
| `frontend/src/pages/admin/GameLeaderboardAdmin.tsx` | MODIFY |
| `backend/app/api/v1/endpoints/admin/stats.py` | MODIFY - add role counts |
| `frontend/src/pages/admin/RolesAdmin.tsx` | MODIFY |

---

## Phase 5: Wire Course Content Block Editor - DONE

**Goal:** Replace "Coming Soon" placeholder with actual content block editor.
**Effort:** Medium

**File:** `frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx` - UPDATED

The builder components **already exist** at `frontend/src/plugins/courses/components/builder/`:
- `SectionContentEditor.tsx` - Full section editor
- `ContentBlockEditor.tsx` - Individual block editor
- `BlockPalette.tsx` - Block type selector
- `DragDropContext.tsx` - Drag-and-drop reordering
- `RichTextEditor.tsx` - Rich text editing

### Changes Needed

1. **Import SectionContentEditor:**
```typescript
import { SectionContentEditor } from '../../components/builder/SectionContentEditor';
```

2. **Add state for editing:**
```typescript
const [editingSection, setEditingSection] = useState<{
  moduleId: string;
  section: ModuleSection;
} | null>(null);
```

3. **Replace "Coming Soon" banner (lines 357-361):**
- Make each section row clickable
- On click, open `SectionContentEditor` in a modal

4. **Add editor modal:**
```tsx
{editingSection && (
  <Modal isOpen onClose={() => setEditingSection(null)} size="xl">
    <SectionContentEditor
      section={editingSection.section}
      onSave={(updatedSection) => handleSaveSection(editingSection.moduleId, updatedSection)}
      onClose={() => setEditingSection(null)}
    />
  </Modal>
)}
```

5. **Implement handleSaveSection:**
```typescript
const handleSaveSection = async (moduleId: string, section: ModuleSection) => {
  try {
    await apiClient.put(`/api/v1/courses/modules/${moduleId}/sections/${section.id}`, {
      content_blocks: section.content_blocks
    });
    toast.success('Section saved');
    setEditingSection(null);
    // Refresh course data
    await loadCourse();
  } catch (error) {
    toast.error('Failed to save section');
  }
};
```

### Files Involved
| File | Action |
|------|--------|
| `frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx` | MODIFY |
| `frontend/src/plugins/courses/components/builder/SectionContentEditor.tsx` | Existing, minor adjustments |

---

## Phase 6: Improve Seed Content for Beginners - DONE

**Goal:** Replace developer-focused content with IT beginner content.
**Effort:** Medium - content writing

**Updated Files:**
- `backend/app/plugins/tutorials/seed_data.py` - 4 IT-focused tutorials with 5 steps each
- `backend/app/plugins/courses/seed_data.py` - 4 courses total (2 existing + 2 new)

### 6A. Update Tutorial Seed

**File:** `backend/app/plugins/tutorials/seed_data.py`

#### New Categories
| Old | New | Slug | Icon | Color |
|-----|-----|------|------|-------|
| Web Development | IT Fundamentals | it-fundamentals | computer | #3B82F6 |
| Programming | Programming | programming | code | #10B981 |
| DevOps | Hardware & Networking | hardware-networking | server | #F59E0B |
| Data Science | IT Support | it-support | headphones | #8B5CF6 |

#### New Tutorials
| Old Tutorial | New Tutorial | Category |
|--------------|--------------|----------|
| Getting Started with React Hooks | Understanding Computers: A Beginner's Guide | IT Fundamentals |
| Docker Basics | Your First Day in IT: Help Desk Essentials | IT Support |
| Python for Beginners | (keep) | Programming |
| (new) | Introduction to Networking | Hardware & Networking |

#### "Understanding Computers" Tutorial Steps:
1. What is a Computer? - Basic definition, input-process-output
2. Hardware Components - CPU, RAM, storage, motherboard
3. Operating Systems - Windows, macOS, Linux basics
4. Files and Folders - File management fundamentals
5. Basic Troubleshooting - Common issues and first steps

#### "Help Desk Essentials" Tutorial Steps:
1. What is IT Support? - Role overview
2. The Ticketing System - How tickets flow
3. Common Issues - Password resets, connectivity, slow PCs
4. Professional Communication - Writing good ticket responses
5. When to Escalate - Knowing your limits

### 6B. Expand Course Seed

**File:** `backend/app/plugins/courses/seed_data.py`

#### New Courses
| Course | Category | Level | Modules | XP | Hours |
|--------|----------|-------|---------|-----|-------|
| Windows Basics for IT Professionals | Operating Systems | beginner | 3 | 300 | 6 |
| Introduction to Cybersecurity | Security | beginner | 3 | 350 | 5 |

#### "Windows Basics" Modules:
1. Navigating Windows - Desktop, Start menu, taskbar, settings
2. User Account Management - Local users, permissions, password policies
3. File System Basics - NTFS, permissions, folder structures

#### "Intro to Cybersecurity" Modules:
1. Password Security - Strong passwords, password managers, 2FA
2. Recognizing Threats - Phishing, malware, social engineering
3. Safe Browsing - HTTPS, downloads, updates

### Files Involved
| File | Action |
|------|--------|
| `backend/app/plugins/tutorials/seed_data.py` | MODIFY |
| `backend/app/plugins/courses/seed_data.py` | MODIFY |

---

## Phase 7: Homepage Redesign - DONE

**Goal:** Transform Learning Paths widget + improve Daily Challenge.
**Effort:** Large

**Completed:**
- `frontend/src/components/home/LearningPathsShowcase.tsx` - CREATED (unified content with tabs)
- `frontend/src/pages/BlogHome.tsx` - UPDATED to use LearningPathsShowcase

### 7A. Redesign TutorialPathsShowcase -> LearningPathsShowcase

**Files:**
- Rename/create: `frontend/src/components/home/LearningPathsShowcase.tsx`
- Update: `frontend/src/pages/BlogHome.tsx`

#### Current State
- Fetches only from `getTutorialCategories()` and `getTutorials()` APIs
- Shows 6 tutorial categories with featured tutorials in each

#### New Design

**Tab Bar:**
```
[ All (15) ] [ Courses (4) ] [ Tutorials (6) ] [ Quizzes (5) ]
```

**Data Fetching:**
```typescript
// Fetch all three content types in parallel
const [tutorials, courses, quizzes] = await Promise.all([
  getTutorials({ is_published: true, limit: 6 }),
  coursesApi.getCourses({ status: 'published', limit: 6 }),
  quizzesApi.getQuizzes({ status: 'published', limit: 6 })
]);
```

**Unified Card Design:**
```
┌────────────────────────────────────┐
│ [COURSE]              ⭐ Featured  │  ← Type badge + featured star
├────────────────────────────────────┤
│ 📚 IT Fundamentals                 │  ← Category icon + name
├────────────────────────────────────┤
│ Understanding Windows Basics       │  ← Title
│ Learn the fundamentals of...       │  ← Short description
├────────────────────────────────────┤
│ 🟢 Beginner  ⏱️ 6h  ⭐ 300 XP     │  ← Difficulty, time, XP
└────────────────────────────────────┘
```

**Type-Specific Colors:**
- Courses: Blue (#3B82F6)
- Tutorials: Purple (#8B5CF6)
- Quizzes: Amber (#F59E0B)

**Responsive Layout:**
- Desktop: 3-column grid
- Tablet: 2-column grid
- Mobile: Horizontal scroll (snap)

### 7B. Improve DailyChallengeBanner

**File:** `frontend/src/components/home/DailyChallengeBanner.tsx`

**Current Issues:**
- Takes up too much vertical space
- Individual challenge cards are too detailed
- Not very gamified feeling

**New Design:**

**Compact Layout:**
```
┌──────────────────────────────────────────────────────────────────┐
│ 🔥 Daily Challenges          [2/3 Done] [████████░░] +150 XP    │
├──────────────────────────────────────────────────────────────────┤
│ ✅ Complete Tutorial  │ 🔄 Pass Quiz (70%+)  │ ⏳ Type 50 WPM   │
│    +50 XP  [Claimed]  │    +50 XP  [Start]   │    +50 XP [12h]  │
└──────────────────────────────────────────────────────────────────┘
```

**Changes:**
1. Single-row header with progress bar
2. Horizontal challenge chips instead of full cards
3. Inline claim/start buttons
4. Streak bonus shown in corner: "🔥 5 day streak (+10%)"
5. Collapse to mini-banner after all challenges claimed

### Files Involved
| File | Action |
|------|--------|
| `frontend/src/components/home/LearningPathsShowcase.tsx` | **CREATE** (or rename from TutorialPathsShowcase) |
| `frontend/src/components/home/TutorialPathsShowcase.tsx` | DELETE (after creating replacement) |
| `frontend/src/pages/BlogHome.tsx` | MODIFY - update import |
| `frontend/src/components/home/DailyChallengeBanner.tsx` | MODIFY |

---

## Implementation Order

```
Phase 1 ─────────────────────────────────────────────────────►
  (Master seed script + run existing seeds)
       │
       ▼
Phase 2 ──────────────────────►  Phase 3 ────────────────────►
  (Quiz seed script)               (Achievement seed script)
       │                                │
       └────────────┬───────────────────┘
                    ▼
Phase 4 ──────────────────────────────────────────────────────►
  (Fix 3 admin pages - can run in parallel with Phase 5)
                    │
Phase 5 ────────────┼─────────────────────────────────────────►
  (Course content editor - can run in parallel with Phase 4)
                    │
                    ▼
Phase 6 ──────────────────────────────────────────────────────►
  (Improve seed content - benefits from master seed script)
                    │
                    ▼
Phase 7 ──────────────────────────────────────────────────────►
  (Homepage redesign - benefits from having real content)
```

**Parallel Work Opportunities:**
- Phases 2 & 3 can run in parallel (both are seed scripts)
- Phases 4 & 5 can run in parallel (different pages/systems)
- Phase 6 requires Phase 1 (master seed script)
- Phase 7 benefits from Phase 6 (real content to display)

---

## Critical Files Summary

| File | Phase | Priority | Action |
|------|-------|----------|--------|
| `backend/scripts/seed_all.py` | 1 | HIGH | CREATE |
| `backend/app/plugins/quizzes/seed_data.py` | 2 | HIGH | CREATE |
| `backend/app/plugins/shared/seed_achievements.py` | 3 | MEDIUM | CREATE |
| `backend/app/plugins/typing_game/routes.py` | 4B | MEDIUM | MODIFY |
| `backend/app/api/v1/endpoints/admin/stats.py` | 4C | MEDIUM | MODIFY |
| `frontend/src/pages/admin/LMSProgressPage.tsx` | 4A | MEDIUM | MODIFY |
| `frontend/src/pages/admin/GameLeaderboardAdmin.tsx` | 4B | MEDIUM | MODIFY |
| `frontend/src/pages/admin/RolesAdmin.tsx` | 4C | LOW | MODIFY |
| `frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx` | 5 | MEDIUM | MODIFY |
| `backend/app/plugins/tutorials/seed_data.py` | 6 | MEDIUM | MODIFY |
| `backend/app/plugins/courses/seed_data.py` | 6 | MEDIUM | MODIFY |
| `frontend/src/components/home/LearningPathsShowcase.tsx` | 7 | LOW | CREATE |
| `frontend/src/components/home/DailyChallengeBanner.tsx` | 7 | LOW | MODIFY |

---

## Verification Checklist

### Phase 1
- [ ] `seed_all.py` created and runnable
- [ ] `python scripts/seed_all.py --all` completes without errors
- [ ] Database contains 12 skills
- [ ] Database contains 9 word lists
- [ ] Database contains sample courses
- [ ] Database contains tutorials and categories

### Phase 2
- [ ] `seed_data.py` created in quizzes plugin
- [ ] 5 quizzes seeded with 8-10 questions each
- [ ] Quizzes visible in admin panel
- [ ] Quizzes playable in frontend

### Phase 3
- [ ] 16 achievements seeded
- [ ] Achievements visible in admin panel
- [ ] Achievement progress tracks correctly

### Phase 4
- [ ] LMSProgressPage shows real student data
- [ ] GameLeaderboardAdmin shows real leaderboard
- [ ] RolesAdmin shows real user counts per role

### Phase 5
- [ ] Course section editor opens when clicking section
- [ ] Can add/edit/remove content blocks
- [ ] Changes save to database
- [ ] Content displays correctly in course player

### Phase 6
- [ ] Tutorial categories updated to IT-focused
- [ ] 4 IT beginner tutorials created
- [ ] 2 additional beginner courses created
- [ ] Content appropriate for IT apprentices

### Phase 7
- [ ] LearningPathsShowcase displays mixed content
- [ ] Tab filtering works correctly
- [ ] Mobile horizontal scroll works
- [ ] DailyChallengeBanner is more compact
- [ ] All animations smooth

---

## Notes

- **Backend runs on:** FastAPI with SQLAlchemy
- **Frontend runs on:** React + TypeScript + Vite + Tailwind
- **Database:** PostgreSQL (production), SQLite (dev)
- **Auth:** JWT tokens with role-based access (UserRole enum)
- **API prefix:** `/api/v1/`
