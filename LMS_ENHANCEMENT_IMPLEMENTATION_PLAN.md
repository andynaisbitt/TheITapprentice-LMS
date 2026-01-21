# LMS Enhancement Implementation Plan
**Date**: January 21, 2026
**Status**: ✅ 100% Complete
**Priority**: High
**Last Updated**: January 21, 2026

---

## Executive Summary

This plan outlines the implementation of:
1. **Daily Challenges System** - Port from ITAppBetaV1
2. **Learning Streaks with Freeze Tokens** - Enhanced streak system
3. **Homepage Marketing Components** - 6 lightweight components to promote LMS plugins

---

## Current State Analysis

### XP System Status: ✅ FULLY IMPLEMENTED

| Component | Status | Location |
|-----------|--------|----------|
| XP Service | ✅ Working | `backend/app/plugins/shared/xp_service.py` |
| Achievement Service | ✅ Working | `backend/app/plugins/shared/achievement_service.py` |
| Tutorial XP Integration | ✅ Working | Awards 10 XP/step, 100 XP/completion |
| Course XP Integration | ✅ Working | Awards 75 XP/module, 250 XP/course |
| Typing Game XP | ✅ Working | WPM/accuracy bonuses |
| Streak Tracking | ⚠️ Basic | No freeze tokens, no daily challenges |
| Leaderboard | ✅ Working | `/progress/xp/leaderboard` |

### What's Missing

| Feature | Priority | Effort | Impact |
|---------|----------|--------|--------|
| Daily Challenges | HIGH | HIGH | Daily engagement driver |
| Streak Freeze Tokens | HIGH | MEDIUM | Retention mechanism |
| Homepage Marketing Components | HIGH | MEDIUM | Plugin discovery |

---

## Phase 1: Daily Challenges System

### 1.1 Database Models

**New File**: `backend/app/plugins/shared/challenges/models.py`

```python
# Tables to create:
# 1. daily_challenge_templates - Admin-created challenge definitions
# 2. daily_challenges - Actual daily challenges (generated at midnight)
# 3. user_challenge_progress - User progress on challenges
```

**Challenge Types**:
| Type | Description | Example |
|------|-------------|---------|
| `quiz` | Complete N quizzes | "Complete 2 quizzes" |
| `tutorial` | Complete N tutorials | "Complete 1 tutorial" |
| `course_section` | Complete N course sections | "Complete 3 lessons" |
| `typing_game` | Play N typing games | "Play 2 typing games" |
| `typing_wpm` | Achieve N WPM | "Reach 50 WPM" |
| `xp_earn` | Earn N XP | "Earn 100 XP today" |
| `login_streak` | Maintain streak | "Login for 3rd day" |

**Difficulty Levels**:
| Difficulty | XP Reward | Target Multiplier |
|------------|-----------|-------------------|
| Easy | 25-50 XP | 1-2 items |
| Medium | 50-100 XP | 3-5 items |
| Hard | 100-200 XP | 5-10 items |

### 1.2 API Endpoints

**New File**: `backend/app/plugins/shared/challenges/routes.py`

```
GET  /challenges/daily              - Get today's challenges for current user
GET  /challenges/daily/history      - Get past challenge completions
POST /challenges/daily/{id}/claim   - Claim completed challenge reward
GET  /challenges/streak             - Get challenge streak info

ADMIN:
GET  /admin/challenges/templates    - List all challenge templates
POST /admin/challenges/templates    - Create challenge template
PUT  /admin/challenges/templates/{id} - Update template
DELETE /admin/challenges/templates/{id} - Delete template
POST /admin/challenges/generate     - Manually generate today's challenges
```

### 1.3 Challenge Generation Logic

**Daily Generation** (runs at midnight UTC):
1. Select 3 challenges from templates (1 easy, 1 medium, 1 hard)
2. Randomize within difficulty
3. Create `daily_challenges` entries for the day
4. All users share the same daily challenges

### 1.4 Frontend Components

| Component | Purpose |
|-----------|---------|
| `DailyChallengesWidget.tsx` | Shows today's challenges with progress |
| `ChallengeCard.tsx` | Individual challenge with progress bar |
| `ChallengeClaimModal.tsx` | Celebration on completion |
| `ChallengeHistoryPage.tsx` | Past completions calendar |

---

## Phase 2: Enhanced Streak System

### 2.1 Streak Freeze Tokens

**Enhance User Model** (add fields):
```python
# In users/models.py
freeze_tokens: int = 2          # Free tokens on signup
freeze_tokens_used: int = 0     # Total used
last_freeze_used: datetime      # Prevent spam
streak_protected_until: datetime # Freeze active until
```

**Streak Logic Enhancement**:
```python
# In xp_service.py check_and_update_streak():
1. Check if streak would break (>48 hours)
2. If user has freeze_tokens > 0:
   - Offer to use freeze token
   - Protect streak for 24 hours
3. Award XP bonuses based on streak tier
```

**Streak Bonus Tiers** (from ITAppBetaV1):
| Streak Days | XP Multiplier |
|-------------|---------------|
| 0-2 days | +0% |
| 3-6 days | +10% |
| 7-29 days | +20% |
| 30-59 days | +50% |
| 60-89 days | +75% |
| 90+ days | +100% |

### 2.2 Frontend Components

| Component | Purpose |
|-----------|---------|
| `StreakDisplay.tsx` | Enhanced streak with bonus tier |
| `FreezeTokenModal.tsx` | Use freeze token dialog |
| `StreakBrokenModal.tsx` | Streak lost notification |

---

## Phase 3: Homepage Marketing Components

### 3.1 Components to Build

| # | Component | Purpose | Data Source |
|---|-----------|---------|-------------|
| 1 | `FeaturedCoursesCarousel.tsx` | Showcase top courses | `/api/v1/courses/featured` |
| 2 | `TypingChallengeCTA.tsx` | Drive game engagement | `/api/v1/typing-game/stats` |
| 3 | `QuickQuizWidget.tsx` | Low-barrier quiz entry | `/api/v1/quizzes/popular` |
| 4 | `TutorialPathsShowcase.tsx` | Show learning paths | `/api/v1/tutorials/paths` |
| 5 | `LeaderboardPreview.tsx` | Social proof widget | `/api/v1/progress/xp/leaderboard` |
| 6 | `DailyChallengeBanner.tsx` | Challenge CTA | `/api/v1/challenges/daily` |

### 3.2 Homepage Integration

**File**: `frontend/src/pages/BlogHome.tsx`

Add new sections (configurable via site settings):
```typescript
// New site settings fields:
show_featured_courses: boolean
show_typing_challenge: boolean
show_quick_quiz: boolean
show_tutorial_paths: boolean
show_leaderboard_preview: boolean
show_daily_challenge_banner: boolean
```

### 3.3 API Endpoints Needed

| Endpoint | Purpose | New? |
|----------|---------|------|
| `GET /courses/featured` | Top 5 featured courses | NEW |
| `GET /typing-game/stats/homepage` | Players online, today's top | NEW |
| `GET /quizzes/popular` | Top 4 popular quizzes | NEW |
| `GET /tutorials/paths` | Tutorial collections | NEW |
| `GET /progress/xp/leaderboard` | Top 5 users | EXISTS |
| `GET /challenges/daily` | Today's challenges | NEW (Phase 1) |

---

## Implementation Order

### Week 1: Foundation

#### Day 1-2: Daily Challenges Backend
- [ ] Create challenge models and migrations
- [ ] Create challenge service with generation logic
- [ ] Create API endpoints
- [ ] Add cron job for midnight generation

#### Day 3-4: Daily Challenges Frontend
- [ ] DailyChallengesWidget component
- [ ] ChallengeCard with progress
- [ ] Claim reward modal
- [ ] Integration with dashboard

#### Day 5: Streak Enhancement
- [ ] Add freeze token fields to User model
- [ ] Enhance streak checking logic
- [ ] Create freeze token API endpoints
- [ ] Frontend freeze token modal

### Week 2: Homepage Components

#### Day 1: Backend APIs
- [ ] Featured courses endpoint
- [ ] Typing game homepage stats
- [ ] Popular quizzes endpoint
- [ ] Tutorial paths endpoint

#### Day 2-3: Marketing Components
- [ ] FeaturedCoursesCarousel
- [ ] TypingChallengeCTA
- [ ] QuickQuizWidget
- [ ] TutorialPathsShowcase

#### Day 4-5: Integration & Polish
- [ ] LeaderboardPreview
- [ ] DailyChallengeBanner
- [ ] Site settings for visibility
- [ ] Homepage integration
- [ ] Testing and fixes

---

## File Creation Checklist

### Backend Files

#### Daily Challenges System
- [x] ~~`backend/app/plugins/shared/challenges/__init__.py`~~ → Integrated into `shared/models.py`
- [x] ~~`backend/app/plugins/shared/challenges/models.py`~~ → `backend/app/plugins/shared/models.py` (added models)
- [x] ~~`backend/app/plugins/shared/challenges/schemas.py`~~ → `backend/app/plugins/shared/schemas.py` (added schemas)
- [x] ~~`backend/app/plugins/shared/challenges/service.py`~~ → `backend/app/plugins/shared/challenge_service.py`
- [x] ~~`backend/app/plugins/shared/challenges/routes.py`~~ → `backend/app/plugins/shared/routes.py` (added routes)
- [x] `backend/alembic/versions/v2_5_add_daily_challenges.py`

#### Homepage APIs
- [x] ~~`backend/app/api/v1/endpoints/homepage.py`~~ → `backend/app/plugins/shared/routes.py` (`/progress/stats/homepage`)

### Frontend Files

#### Daily Challenges
- [x] ~~`frontend/src/plugins/shared/components/challenges/DailyChallengesWidget.tsx`~~ → `frontend/src/components/home/DailyChallengeBanner.tsx`
- [x] ~~`frontend/src/plugins/shared/components/challenges/ChallengeCard.tsx`~~ → Inline in DailyChallengeBanner.tsx
- [ ] `frontend/src/plugins/shared/components/challenges/ChallengeClaimModal.tsx` → Inline claim (LOW priority)
- [x] `frontend/src/plugins/shared/services/challengesApi.ts`

#### Streak Enhancement
- [x] `frontend/src/plugins/shared/components/StreakFreezeModal.tsx`

#### Homepage Components
- [x] `frontend/src/components/home/FeaturedCoursesCarousel.tsx`
- [x] `frontend/src/components/home/TypingChallengeCTA.tsx`
- [x] `frontend/src/components/home/QuickQuizWidget.tsx`
- [x] `frontend/src/components/home/TutorialPathsShowcase.tsx`
- [x] `frontend/src/components/home/LeaderboardPreview.tsx`
- [x] `frontend/src/components/home/DailyChallengeBanner.tsx`
- [x] `frontend/src/components/home/HomepageStatsWidget.tsx` → **BONUS**
- [x] `frontend/src/components/home/index.ts` → **BONUS** (exports)

---

## Database Schema

### daily_challenge_templates
```sql
CREATE TABLE daily_challenge_templates (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    challenge_type VARCHAR(50) NOT NULL,  -- quiz, tutorial, typing_game, etc.
    difficulty VARCHAR(20) NOT NULL,       -- easy, medium, hard
    target_count INT NOT NULL DEFAULT 1,
    base_xp_reward INT NOT NULL DEFAULT 50,
    is_active BOOLEAN DEFAULT TRUE,
    icon VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### daily_challenges
```sql
CREATE TABLE daily_challenges (
    id VARCHAR(36) PRIMARY KEY,
    template_id VARCHAR(36) REFERENCES daily_challenge_templates(id),
    challenge_date DATE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    challenge_type VARCHAR(50) NOT NULL,
    difficulty VARCHAR(20) NOT NULL,
    target_count INT NOT NULL,
    xp_reward INT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(template_id, challenge_date)
);
```

### user_challenge_progress
```sql
CREATE TABLE user_challenge_progress (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT REFERENCES users(id),
    challenge_id VARCHAR(36) REFERENCES daily_challenges(id),
    current_progress INT DEFAULT 0,
    is_completed BOOLEAN DEFAULT FALSE,
    is_claimed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP,
    claimed_at TIMESTAMP,
    xp_earned INT,
    streak_bonus_percent INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, challenge_id)
);
```

---

## Success Criteria

### Phase 1: Daily Challenges
- [x] 3 challenges generate daily at midnight UTC (APScheduler cron job)
- [x] Progress tracks automatically from learning activities
- [x] Users can claim rewards with celebration animation
- [x] Challenge streak tracks consecutive days completing all challenges
- [x] Admin can create/edit/disable challenge templates (`DailyChallengesAdmin.tsx`)

### Phase 2: Streak Enhancement
- [x] Users start with 2 freeze tokens
- [x] Freeze token modal appears when streak at risk (`StreakFreezeModal.tsx`)
- [x] Using freeze protects streak for 24 hours
- [x] Streak bonus XP applies to all activities
- [x] Clear visual indicator of current bonus tier

### Phase 3: Homepage Components
- [x] Each component loads data from API
- [x] Components visible based on site settings (7 new visibility toggles)
- [x] Responsive design (mobile/tablet/desktop)
- [x] Animations with Framer Motion
- [x] Direct links to relevant pages

---

## Technical Notes

### Challenge Progress Tracking

Progress is incremented automatically when:
- Tutorial step/completion → `tutorial` challenges
- Quiz completion → `quiz` challenges
- Course section completion → `course_section` challenges
- Typing game completion → `typing_game` challenges
- XP awarded → `xp_earn` challenges

**Implementation**: Add hooks to existing completion routes to call `challenge_service.increment_progress()`.

### Cron Job for Daily Generation

**Option A**: Celery Beat task
```python
@celery.task
def generate_daily_challenges():
    # Run at 00:00 UTC
    challenge_service.generate_for_date(date.today())
```

**Option B**: FastAPI BackgroundTasks + APScheduler
```python
scheduler.add_job(generate_daily_challenges, 'cron', hour=0, minute=0)
```

### Site Settings Extension

Add to `SiteSettings` model:
```python
# Homepage LMS Sections
show_featured_courses = Column(Boolean, default=True)
show_typing_challenge = Column(Boolean, default=True)
show_quick_quiz = Column(Boolean, default=True)
show_tutorial_paths = Column(Boolean, default=True)
show_leaderboard_preview = Column(Boolean, default=True)
show_daily_challenge_banner = Column(Boolean, default=True)

# Section ordering
homepage_section_order = Column(JSON, default=[
    "hero", "daily_challenge", "featured_courses",
    "typing_challenge", "carousel", "categories",
    "quick_quiz", "tutorial_paths", "recent_posts",
    "leaderboard"
])
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Challenge generation fails | Manual trigger endpoint + admin notification |
| Streak calculations off | Comprehensive logging + timezone handling |
| Homepage overload | Lazy loading + skeleton states |
| API performance | Caching with Redis/memory |

---

## Document Status

**Status**: ✅ 100% Implemented
**Completed**: All planned features have been implemented

---

## Progress Tracking

### ✅ Completed

#### Phase 1: Daily Challenges Backend
- [x] XP system analysis
- [x] Gap analysis vs ITAppBetaV1
- [x] Implementation plan document
- [x] Daily Challenge models (`DailyChallengeTemplate`, `DailyChallenge`, `UserChallengeProgress`, `UserChallengeStreak`)
- [x] Migration file (`v2_5_add_daily_challenges.py`)
- [x] Challenge service (`challenge_service.py`) with generation logic
- [x] Challenge API routes (all endpoints in `shared/routes.py`)
- [x] Challenge progress wiring in completion routes:
  - [x] Tutorials: `tutorials/routes.py`
  - [x] Quizzes: `quizzes/routes.py`
  - [x] Courses: `courses/crud.py`
  - [x] Typing Game: `typing_game/crud.py`

#### Phase 2: Streak System
- [x] Freeze tokens in `UserChallengeStreak` model
- [x] Streak bonus tiers in `ChallengeConfig`
- [x] Freeze token API endpoint (`/challenges/streak/freeze`)
- [x] Streak info displayed in DailyChallengeBanner

#### Phase 3: Homepage Marketing Components
- [x] `FeaturedCoursesCarousel.tsx` - Featured courses with progress
- [x] `TypingChallengeCTA.tsx` - Typing game promotion
- [x] `QuickQuizWidget.tsx` - Featured quizzes
- [x] `LeaderboardPreview.tsx` - Top 5 learners
- [x] `DailyChallengeBanner.tsx` - Today's challenges with claim
- [x] `HomepageStatsWidget.tsx` - Platform stats (BONUS)
- [x] Homepage stats API (`/progress/stats/homepage`) (BONUS)
- [x] Frontend API service (`challengesApi.ts`)
- [x] Homepage integration (`BlogHome.tsx`)
- [x] Component exports (`home/index.ts`)

### ✅ All Gaps Resolved

| Item | Status | Resolution |
|------|--------|------------|
| `TutorialPathsShowcase.tsx` | ✅ Done | Created `frontend/src/components/home/TutorialPathsShowcase.tsx` |
| Site settings for LMS visibility | ✅ Done | Added 7 visibility toggles to SiteSettings model + migration |
| Admin Challenge Templates UI | ✅ Done | Created `frontend/src/pages/admin/DailyChallengesAdmin.tsx` |
| Cron job for midnight generation | ✅ Done | Created `backend/app/core/scheduler.py` with APScheduler |
| Separate `StreakFreezeModal.tsx` | ✅ Done | Created `frontend/src/plugins/shared/components/StreakFreezeModal.tsx` |
| Separate `ChallengeClaimModal.tsx` | N/A | Inline claim provides good UX |
| Challenge history calendar page | ✅ Done | Created `frontend/src/pages/user/ChallengeHistoryPage.tsx` |

### Implementation Complete
All planned features have been implemented and are ready for testing.
