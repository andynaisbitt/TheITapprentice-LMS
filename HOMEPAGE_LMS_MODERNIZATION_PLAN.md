# Homepage LMS Modernization Plan

## Overview
This plan outlines the redesign of the Site Settings admin panel and homepage to better showcase LMS features. Currently, **7 LMS widgets exist** but are **not configurable** through the admin interface.

---

## Current State

### Existing Site Settings Tabs
1. **Homepage** - Hero section only (title, subtitle, badge, CTAs, stats)
2. **Homepage Layout** - Blog widgets only (carousel, categories, recent posts)
3. **SEO & Domain**
4. **Branding & Logo**
5. **Analytics & Ads**
6. **Social Media**
7. **Contact Info**
8. **Email & Newsletter**

### Missing from Admin: LMS Widget Controls
These widgets exist in code but have **no admin UI**:
- Featured Courses Carousel
- Typing Challenge CTA
- Quick Quiz Widget
- Tutorial Paths Showcase
- Leaderboard Preview
- Daily Challenge Banner
- Homepage Stats Widget

---

## Proposed Changes

### Phase 1: Reorganize Tabs

**New Tab Structure:**
1. **Homepage Content** (merged)
   - Hero section settings
   - Stats section settings

2. **Blog Sections** (formerly "Layout")
   - Featured Carousel (toggle + settings)
   - Categories Showcase (toggle + settings)
   - Recent Posts Grid (toggle + settings)

3. **LMS Widgets** (NEW)
   - Featured Courses (toggle + settings)
   - Typing Challenge CTA (toggle + settings)
   - Quick Quiz Widget (toggle + settings)
   - Tutorial Paths (toggle + settings)
   - Leaderboard Preview (toggle + settings)
   - Daily Challenges (toggle + settings)
   - Community Stats (toggle + settings)

4. **Section Order** (NEW - drag & drop)
   - Visual reordering of homepage sections

5. **SEO & Domain** (existing)
6. **Branding & Logo** (existing)
7. **Analytics & Ads** (existing)
8. **Social Media** (existing)

### Phase 2: Add LMS Widget Settings

#### 2.1 Featured Courses Widget
```typescript
showFeaturedCourses: boolean       // Toggle visibility
featuredCoursesTitle: string       // "Featured Courses"
featuredCoursesSubtitle: string    // "Start your learning journey"
featuredCoursesLimit: number       // 3-8 courses
featuredCoursesShowPremium: boolean // Show premium badge
```

#### 2.2 Typing Challenge CTA
```typescript
showTypingChallenge: boolean       // Toggle visibility
typingChallengeTitle: string       // "Test Your Typing Speed"
typingChallengeShowStats: boolean  // Show WPM/Accuracy badges
typingChallengeShowPvP: boolean    // Show PvP button
```

#### 2.3 Quick Quiz Widget
```typescript
showQuickQuiz: boolean             // Toggle visibility
quickQuizTitle: string             // "Quick Quiz"
quickQuizSubtitle: string          // "Test your knowledge"
quickQuizLimit: number             // 2-6 quizzes
```

#### 2.4 Tutorial Paths Showcase
```typescript
showTutorialPaths: boolean         // Toggle visibility
tutorialPathsTitle: string         // "Learning Paths"
tutorialPathsSubtitle: string      // "Structured tutorials..."
tutorialPathsCategoriesLimit: number // 2-6 categories
tutorialPathsTutorialsPerCategory: number // 2-4 per category
```

#### 2.5 Leaderboard Preview
```typescript
showLeaderboardPreview: boolean    // Toggle visibility
leaderboardTitle: string           // "Top Learners"
leaderboardLimit: number           // 3-10 users
leaderboardShowStreak: boolean     // Show streak count
```

#### 2.6 Daily Challenge Banner
```typescript
showDailyChallengeBanner: boolean  // Toggle visibility
dailyChallengeGuestMessage: string // CTA for guests
dailyChallengeShowStreak: boolean  // Show streak bonus
```

#### 2.7 Homepage Stats Widget
```typescript
showHomepageStats: boolean         // Toggle visibility
homepageStatsTitle: string         // "Community Progress"
homepageStatsShowActiveToday: boolean // Show "X active today"
homepageStatsLayout: 'grid' | 'row' // Card layout
```

### Phase 3: Section Ordering System

Add ability to reorder homepage sections via drag & drop:

```typescript
homepageSectionOrder: string[]  // Array of section IDs in display order
```

Default order:
1. `hero`
2. `daily-challenges`
3. `featured-carousel`
4. `featured-courses`
5. `categories`
6. `typing-challenge`
7. `tutorial-paths`
8. `recent-posts`
9. `quick-quiz`
10. `leaderboard`
11. `community-stats`

---

## Implementation Tasks

### Backend Changes
- [ ] Add new fields to `SiteSettings` model
- [ ] Update `site_settings` schema with LMS widget fields
- [ ] Create migration for new columns
- [ ] Update site-settings API endpoints

### Frontend Changes

#### Store Updates
- [ ] Update `useSiteSettingsStore.ts` with all new fields
- [ ] Add defaults for LMS widget settings
- [ ] Add `sectionOrder` array field

#### SiteSettings.tsx Restructure
- [ ] Reorganize tabs into new structure
- [ ] Create "LMS Widgets" tab with all 7 widget controls
- [ ] Add section ordering UI (drag & drop or up/down buttons)
- [ ] Add preview thumbnails for each section

#### BlogHome.tsx Updates
- [ ] Read section order from settings
- [ ] Render sections in configurable order
- [ ] Pass custom titles/subtitles to each widget

### New Widget Customizations
- [ ] Update each LMS widget to accept custom props
- [ ] Add fallbacks for missing settings

---

## UI Design for LMS Widgets Tab

```
┌─────────────────────────────────────────────────────────────┐
│  📚 LMS Widgets                                             │
│  Configure learning management widgets on your homepage     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 🎓 Featured Courses                        [Toggle] │   │
│  │ ─────────────────────────────────────────────────── │   │
│  │ Title: [Featured Courses...................]        │   │
│  │ Subtitle: [Start your learning journey.....]        │   │
│  │ Number of courses: [4] (3-8)                        │   │
│  │ □ Show premium badge                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ⌨️ Typing Challenge                        [Toggle] │   │
│  │ ─────────────────────────────────────────────────── │   │
│  │ Title: [Test Your Typing Speed.............]        │   │
│  │ □ Show speed/accuracy badges                        │   │
│  │ □ Show PvP battle button                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 🧠 Quick Quiz Widget                       [Toggle] │   │
│  │ ─────────────────────────────────────────────────── │   │
│  │ Title: [Quick Quiz..........................]       │   │
│  │ Subtitle: [Test your knowledge.............]        │   │
│  │ Number of quizzes: [4] (2-6)                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ... (Tutorial Paths, Leaderboard, Daily Challenges,       │
│       Community Stats sections follow same pattern)        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Files to Modify

### Backend
- `backend/app/api/v1/services/site_settings/models.py`
- `backend/app/api/v1/services/site_settings/schemas.py`
- `backend/alembic/versions/` (new migration)

### Frontend
- `frontend/src/pages/admin/SiteSettings.tsx` (major refactor)
- `frontend/src/store/useSiteSettingsStore.ts`
- `frontend/src/hooks/useSiteSettings.ts`
- `frontend/src/pages/BlogHome.tsx`
- `frontend/src/components/home/FeaturedCoursesCarousel.tsx`
- `frontend/src/components/home/TypingChallengeCTA.tsx`
- `frontend/src/components/home/QuickQuizWidget.tsx`
- `frontend/src/components/home/TutorialPathsShowcase.tsx`
- `frontend/src/components/home/LeaderboardPreview.tsx`
- `frontend/src/components/home/DailyChallengeBanner.tsx`
- `frontend/src/components/home/HomepageStatsWidget.tsx`

---

## Priority Order

1. **High Priority** - Basic visibility toggles for all LMS widgets
2. **Medium Priority** - Custom titles/subtitles for each section
3. **Medium Priority** - Limits and additional options per widget
4. **Low Priority** - Drag & drop section reordering
5. **Low Priority** - Live preview of homepage

---

## Success Criteria

- [ ] All 7 LMS widgets can be toggled on/off from admin panel
- [ ] Each widget has customizable title/subtitle
- [ ] Each widget has relevant configuration options (limits, features)
- [ ] Settings persist to database and load correctly
- [ ] Homepage renders sections based on saved settings
- [ ] Clear documentation for each setting

---

## Estimated Effort

| Task | Complexity | Est. Time |
|------|------------|-----------|
| Backend schema updates | Low | 1-2 hours |
| Backend migration | Low | 30 min |
| Store updates | Low | 1 hour |
| SiteSettings.tsx refactor | High | 4-6 hours |
| Widget prop updates | Medium | 2-3 hours |
| BlogHome.tsx ordering | Medium | 2 hours |
| Testing & fixes | Medium | 2-3 hours |
| **Total** | | **12-18 hours** |

---

## Next Steps

1. Review and approve this plan
2. Start with backend schema changes
3. Update frontend store and types
4. Refactor SiteSettings.tsx
5. Update widgets to accept custom props
6. Test end-to-end flow
