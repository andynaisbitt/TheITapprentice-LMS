# ITAppBetaV1 Component Inventory for Plugin System

**Purpose**: Detailed inventory of components from ITAppBetaV1 ready to port to BlogCMS
**Created**: 2026-01-11
**Source**: `C:\Gitlab Projects\ITAppBetaV1`
**Destination**: `C:\Gitlab Projects\BlogCMS`

---

## 📦 Priority 1: Tutorials System

### Frontend Components

**Location**: `ITAppBetaV1/src/pages/tutorials/`

#### TutorialsList.tsx (~500 lines)
**What it does**:
- Browse all tutorials with search/filtering
- Category filter (Programming, DevOps, Cloud, Security, etc.)
- Difficulty filter (Beginner, Intermediate, Advanced)
- Search by title/description
- Tutorial cards with:
  - XP reward badge
  - Skill badges
  - Duration estimate
  - Difficulty badge
  - Category badge
  - Completion status

**Key features**:
```tsx
- tutorialsApi.getTutorials({ difficulty, category, limit })
- tutorialsApi.searchTutorials(query)
- tutorialsApi.getCategories()
- XPBadge component (shows +50 XP, +100 XP)
- SkillBadges component (Python, Docker, Git, etc.)
- CategoryBadge component (color-coded categories)
```

**Dependencies**:
- `services/api/tutorials.api.ts`
- `components/XP/XPBadge.tsx`
- `components/Skills/SkillBadges.tsx`
- `components/Common/CategoryBadge.tsx`
- framer-motion (animations)
- lucide-react (icons)

**Port strategy**:
1. Copy to `BlogCMS/frontend/src/plugins/tutorials/pages/TutorialsList.tsx`
2. Update API path: `/api/v1/tutorials` (remove `/services/`)
3. Add plugin check: `usePlugin('tutorials')`
4. Port XPBadge, SkillBadges, CategoryBadge to shared components

---

#### TutorialViewer.tsx (~700 lines)
**What it does**:
- Step-by-step tutorial viewer
- Progress tracking (mark steps complete)
- Code syntax highlighting
- Interactive code examples
- Next/Previous navigation
- Sidebar with step list
- Completion celebration modal
- XP award on completion

**Key features**:
```tsx
- tutorialsApi.getTutorialBySlug(slug)
- tutorialsApi.completeStep(tutorialId, stepId)
- tutorialsApi.completeTutorial(tutorialId)
- Code block with syntax highlighting
- Step completion checkmarks
- Progress bar
- Confetti animation on completion
- XP reward notification
```

**Dependencies**:
- `services/api/tutorials.api.ts`
- `react-syntax-highlighter` (code highlighting)
- `canvas-confetti` (celebration effect)
- framer-motion
- lucide-react

**Port strategy**:
1. Copy to `BlogCMS/frontend/src/plugins/tutorials/pages/TutorialViewer.tsx`
2. Install `react-syntax-highlighter` and `canvas-confetti`
3. Update API calls
4. Add plugin check
5. Integrate with BlogCMS progress tracking (if exists)

---

### API Client

**Location**: `ITAppBetaV1/src/services/api/tutorials.api.ts` (~200 lines)

```typescript
export interface TutorialListResponse {
  id: number;
  title: string;
  slug: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimated_time_minutes: number;
  xp_reward: number;
  is_published: boolean;
  category_id: number;
  category: TutorialCategory;
  related_skills: Skill[];
  created_at: string;
  completion_status?: {
    completed: boolean;
    progress_percentage: number;
    completed_steps: number;
    total_steps: number;
  };
}

export const tutorialsApi = {
  getTutorials: (params?: TutorialFilters) => Promise<TutorialListResponse[]>;
  getTutorialBySlug: (slug: string) => Promise<TutorialDetailResponse>;
  getCategories: () => Promise<TutorialCategory[]>;
  completeStep: (tutorialId: number, stepId: number) => Promise<void>;
  completeTutorial: (tutorialId: number) => Promise<CompletionResponse>;
  searchTutorials: (query: string) => Promise<TutorialListResponse[]>;
  getUserProgress: (tutorialId: number) => Promise<ProgressResponse>;
}
```

**Port strategy**:
1. Copy to `BlogCMS/frontend/src/plugins/tutorials/services/tutorials.api.ts`
2. Update base URL to use BlogCMS API pattern
3. Import from shared API client

---

### Backend Services

**Location**: `ITAppBetaV1/Backend/app/api/v1/services/tutorials/`

#### models.py (~300 lines)
```python
class Tutorial(Base):
    __tablename__ = "tutorials"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    slug = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    difficulty = Column(String)  # beginner, intermediate, advanced
    estimated_time_minutes = Column(Integer)
    xp_reward = Column(Integer, default=100)
    is_published = Column(Boolean, default=False)
    category_id = Column(Integer, ForeignKey("tutorial_categories.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)

    # Relationships
    category = relationship("TutorialCategory", back_populates="tutorials")
    steps = relationship("TutorialStep", back_populates="tutorial", cascade="all, delete-orphan")
    progress = relationship("TutorialProgress", back_populates="tutorial")

class TutorialStep(Base):
    __tablename__ = "tutorial_steps"

    id = Column(Integer, primary_key=True, index=True)
    tutorial_id = Column(Integer, ForeignKey("tutorials.id"), nullable=False)
    order = Column(Integer, nullable=False)
    title = Column(String, nullable=False)
    content = Column(Text)  # Markdown/HTML content
    code_example = Column(Text)  # Optional code block
    code_language = Column(String)  # python, javascript, bash, etc.
    hints = Column(JSON)  # Array of hint strings

    # Relationships
    tutorial = relationship("Tutorial", back_populates="steps")

class TutorialCategory(Base):
    __tablename__ = "tutorial_categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    slug = Column(String, unique=True, nullable=False)
    icon = Column(String)  # Lucide icon name
    color = Column(String)  # Hex color
    description = Column(Text)

    # Relationships
    tutorials = relationship("Tutorial", back_populates="category")

class TutorialProgress(Base):
    __tablename__ = "tutorial_progress"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    tutorial_id = Column(Integer, ForeignKey("tutorials.id"), nullable=False)
    step_id = Column(Integer, ForeignKey("tutorial_steps.id"))
    completed = Column(Boolean, default=False)
    completed_at = Column(DateTime)
    started_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")
    tutorial = relationship("Tutorial", back_populates="progress")
    step = relationship("TutorialStep")
```

**Port strategy**:
1. Copy to `BlogCMS/backend/app/plugins/tutorials/models.py`
2. Update imports to use BlogCMS User model
3. Create Alembic migration

---

#### routes.py (~400 lines)
```python
router = APIRouter(prefix="/tutorials", tags=["tutorials"])

@router.get("", response_model=List[TutorialListResponse])
async def get_tutorials(
    difficulty: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """Get all published tutorials with optional filters"""
    query = db.query(Tutorial).filter(Tutorial.is_published == True)

    if difficulty:
        query = query.filter(Tutorial.difficulty == difficulty)

    if category:
        query = query.join(TutorialCategory).filter(TutorialCategory.slug == category)

    tutorials = query.limit(limit).all()

    # Enrich with user progress if authenticated
    if current_user:
        for tutorial in tutorials:
            progress = get_tutorial_progress(db, current_user.id, tutorial.id)
            tutorial.completion_status = progress

    return tutorials

@router.get("/{slug}", response_model=TutorialDetailResponse)
async def get_tutorial_by_slug(
    slug: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """Get tutorial details with steps"""
    tutorial = db.query(Tutorial).filter(Tutorial.slug == slug).first()
    if not tutorial:
        raise HTTPException(status_code=404, detail="Tutorial not found")

    # Get user progress
    if current_user:
        tutorial.user_progress = get_tutorial_progress(db, current_user.id, tutorial.id)

    return tutorial

@router.post("/{tutorial_id}/steps/{step_id}/complete")
async def complete_step(
    tutorial_id: int,
    step_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark tutorial step as complete"""
    # Create or update progress record
    progress = db.query(TutorialProgress).filter(
        TutorialProgress.user_id == current_user.id,
        TutorialProgress.tutorial_id == tutorial_id,
        TutorialProgress.step_id == step_id
    ).first()

    if not progress:
        progress = TutorialProgress(
            user_id=current_user.id,
            tutorial_id=tutorial_id,
            step_id=step_id,
            completed=True,
            completed_at=datetime.utcnow()
        )
        db.add(progress)
    else:
        progress.completed = True
        progress.completed_at = datetime.utcnow()

    db.commit()
    return {"message": "Step completed"}

@router.post("/{tutorial_id}/complete")
async def complete_tutorial(
    tutorial_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark entire tutorial as complete and award XP"""
    tutorial = db.query(Tutorial).filter(Tutorial.id == tutorial_id).first()
    if not tutorial:
        raise HTTPException(status_code=404, detail="Tutorial not found")

    # Mark tutorial progress as complete
    progress = db.query(TutorialProgress).filter(
        TutorialProgress.user_id == current_user.id,
        TutorialProgress.tutorial_id == tutorial_id
    ).first()

    if not progress:
        progress = TutorialProgress(
            user_id=current_user.id,
            tutorial_id=tutorial_id,
            completed=True,
            completed_at=datetime.utcnow()
        )
        db.add(progress)
    else:
        progress.completed = True
        progress.completed_at = datetime.utcnow()

    # Award XP
    award_xp(db, current_user.id, tutorial.xp_reward, f"Completed tutorial: {tutorial.title}")

    db.commit()

    return {
        "message": "Tutorial completed!",
        "xp_awarded": tutorial.xp_reward,
        "tutorial_title": tutorial.title
    }

# Admin routes
@router.post("/admin/create", dependencies=[Depends(require_admin)])
async def create_tutorial(data: TutorialCreate, db: Session = Depends(get_db)):
    """Create new tutorial (admin only)"""
    # ... implementation
```

**Port strategy**:
1. Copy to `BlogCMS/backend/app/plugins/tutorials/routes.py`
2. Update imports
3. Add plugin enabled check
4. Mount in main.py conditionally

---

## 📦 Priority 2: Typing Game System

### Frontend Components

**Location**: `ITAppBetaV1/src/components/Games/TypingGame/`

#### QuickBrownFoxGameV3.tsx (~600 lines)
**What it does**:
- 3 progressive rounds (Warmup, 20s challenge, 10s insane mode)
- Real-time WPM/accuracy tracking
- Animated cyber fox character
- API integration for XP awards
- Round results with stats
- Celebration confetti on completion

**Key features**:
```tsx
interface RoundConfig {
  roundNumber: number;
  name: string;
  timeLimit: number | null;
  description: string;
}

const ROUND_CONFIG = [
  { roundNumber: 1, name: 'Warmup Round', timeLimit: null, description: 'Get familiar!' },
  { roundNumber: 2, name: 'Speed Challenge', timeLimit: 20, description: 'Complete in 20s!' },
  { roundNumber: 3, name: 'INSANE MODE', timeLimit: 10, description: 'Complete in 10s or FAIL!' }
];

// Features:
- useQuickBrownFoxAPI() hook for session management
- Character animation (idle, trotting, running, jumping)
- Timer countdown with visual alerts
- WPM calculation (real-time)
- Accuracy calculation (correct chars / total chars)
- Word-by-word input validation
- Round transition modals
- Completion modal with total stats
```

**Dependencies**:
- `hooks/useQuickBrownFoxAPI.ts`
- `TypingEngine/modals/` (GameStartModal, RoundTransitionModal, GameCompleteModal)
- framer-motion (animations)
- canvas-confetti (celebration)

**Port strategy**:
1. Copy to `BlogCMS/frontend/src/plugins/typing-game/components/QuickBrownFoxGame.tsx`
2. Copy modal components from TypingEngine
3. Update API hooks
4. Add plugin check

---

#### PVP Components (~7 files)

**Location**: `ITAppBetaV1/src/components/Games/PVP/`

Files:
- `MatchTimer.tsx` (~200 lines) - Countdown timer for PVP rounds
- `RoundResults.tsx` (~350 lines) - Compare player stats after each round
- `PowerupInventory.tsx` (~250 lines) - Powerup selection and usage
- `PowerupEffects.tsx` (~300 lines) - Visual effects for powerups
- `WordByWordDisplay.tsx` (~200 lines) - Side-by-side typing display
- `ForfeitModal.tsx` (~150 lines) - Confirm forfeit dialog
- `RoundPreview.tsx` (~250 lines) - Show round details before start

**What they do**:
- Real-time multiplayer typing battles
- Round-based gameplay (best of 3)
- Powerups system (freeze opponent, double XP, etc.)
- Live opponent progress tracking
- Victory/defeat animations
- Match history tracking

**Port strategy**:
1. Copy entire PVP folder to `BlogCMS/frontend/src/plugins/typing-game/components/PVP/`
2. Update WebSocket connection (if needed)
3. Add matchmaking API integration

---

### API Client

**Location**: `ITAppBetaV1/src/components/Games/TypingGame/hooks/useQuickBrownFoxAPI.ts`

```typescript
export const useQuickBrownFoxAPI = () => {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [checksum, setChecksum] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const startSession = async () => {
    const response = await gamesApi.startTypingSession();
    setSessionId(response.session_id);
    setChecksum(response.checksum);
    return response;
  };

  const submitSession = async (roundResults: RoundResult[]) => {
    if (!sessionId || !checksum) {
      throw new Error('No active session');
    }

    const response = await gamesApi.submitTypingScore({
      session_id: sessionId,
      checksum: checksum,
      rounds: roundResults,
      total_wpm: calculateAverageWPM(roundResults),
      total_accuracy: calculateAverageAccuracy(roundResults),
      completed: allRoundsPassed(roundResults)
    });

    return response; // { xp_awarded, new_level, achievements }
  };

  return { startSession, submitSession, isLoading };
};
```

**Port strategy**:
1. Copy to `BlogCMS/frontend/src/plugins/typing-game/hooks/useTypingGameAPI.ts`
2. Update API endpoints

---

### Backend Services

**Location**: `ITAppBetaV1/Backend/app/api/v1/services/games/`

#### models.py (~400 lines)
```python
class GameSession(Base):
    __tablename__ = "game_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    game_type = Column(String, nullable=False)  # quick_brown_fox, pvp_typing, etc.
    checksum = Column(String, nullable=False)  # Anti-cheat verification
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime)
    is_valid = Column(Boolean, default=True)

    # Relationships
    user = relationship("User")
    scores = relationship("GameScore", back_populates="session", cascade="all, delete-orphan")

class GameScore(Base):
    __tablename__ = "game_scores"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("game_sessions.id"), nullable=False)
    round_number = Column(Integer, nullable=False)
    wpm = Column(Float, nullable=False)
    accuracy = Column(Float, nullable=False)
    errors = Column(Integer, default=0)
    time_taken = Column(Float)  # Seconds
    passed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    session = relationship("GameSession", back_populates="scores")

class PVPMatch(Base):
    __tablename__ = "pvp_matches"

    id = Column(Integer, primary_key=True, index=True)
    match_id = Column(String, unique=True, index=True)
    player1_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    player2_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    winner_id = Column(Integer, ForeignKey("users.id"))
    match_type = Column(String, default="quick_brown_fox_pvp")
    status = Column(String, default="active")  # active, completed, forfeited
    created_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime)

    # Relationships
    player1 = relationship("User", foreign_keys=[player1_id])
    player2 = relationship("User", foreign_keys=[player2_id])
    winner = relationship("User", foreign_keys=[winner_id])
    rounds = relationship("PVPRound", back_populates="match")

class GameLeaderboard(Base):
    __tablename__ = "game_leaderboard"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    game_type = Column(String, nullable=False)
    best_wpm = Column(Float, default=0)
    best_accuracy = Column(Float, default=0)
    total_games = Column(Integer, default=0)
    total_wins = Column(Integer, default=0)  # For PVP
    current_streak = Column(Integer, default=0)
    last_played = Column(DateTime)

    # Relationships
    user = relationship("User")
```

**Port strategy**:
1. Copy to `BlogCMS/backend/app/plugins/typing_game/models.py`
2. Create Alembic migration

---

#### routes.py (~500 lines)
```python
router = APIRouter(prefix="/games/typing", tags=["typing_game"])

@router.post("/start-session")
async def start_typing_session(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start new typing game session"""
    session_id = str(uuid.uuid4())

    # Generate checksum for anti-cheat
    checksum_data = f"{session_id}:{current_user.id}:{datetime.utcnow().isoformat()}"
    checksum = hashlib.sha256(checksum_data.encode()).hexdigest()

    session = GameSession(
        session_id=session_id,
        user_id=current_user.id,
        game_type="quick_brown_fox",
        checksum=checksum
    )
    db.add(session)
    db.commit()

    return {"session_id": session_id, "checksum": checksum}

@router.post("/submit-score")
async def submit_typing_score(
    data: GameScoreSubmit,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit game score and award XP"""
    # Verify session exists
    session = db.query(GameSession).filter(
        GameSession.session_id == data.session_id,
        GameSession.user_id == current_user.id
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Verify checksum (anti-cheat)
    if session.checksum != data.checksum:
        session.is_valid = False
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid checksum")

    # Store round scores
    for round_data in data.rounds:
        score = GameScore(
            session_id=session.id,
            round_number=round_data.round_number,
            wpm=round_data.wpm,
            accuracy=round_data.accuracy,
            errors=round_data.errors,
            time_taken=round_data.time,
            passed=round_data.passed
        )
        db.add(score)

    # Calculate XP based on performance
    xp_awarded = calculate_typing_xp(data.total_wpm, data.total_accuracy, data.completed)

    # Award XP
    award_xp(db, current_user.id, xp_awarded, "Typing game completion")

    # Update leaderboard
    update_leaderboard(db, current_user.id, data.total_wpm, data.total_accuracy)

    # Check for achievements
    achievements = check_typing_achievements(db, current_user.id, data)

    session.ended_at = datetime.utcnow()
    db.commit()

    return {
        "xp_awarded": xp_awarded,
        "achievements": achievements,
        "new_high_score": is_new_high_score(db, current_user.id, data.total_wpm)
    }

@router.get("/leaderboard")
async def get_leaderboard(
    game_type: str = "quick_brown_fox",
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get top players by WPM"""
    leaderboard = db.query(GameLeaderboard, User).join(User).filter(
        GameLeaderboard.game_type == game_type
    ).order_by(GameLeaderboard.best_wpm.desc()).limit(limit).all()

    return [
        {
            "rank": idx + 1,
            "username": user.username,
            "best_wpm": lb.best_wpm,
            "best_accuracy": lb.best_accuracy,
            "total_games": lb.total_games
        }
        for idx, (lb, user) in enumerate(leaderboard)
    ]

# PVP Routes
@router.post("/pvp/find-match")
async def find_pvp_match(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Find PVP opponent"""
    # Simple matchmaking: find waiting player or create new match
    waiting_match = db.query(PVPMatch).filter(
        PVPMatch.status == "waiting",
        PVPMatch.player1_id != current_user.id
    ).first()

    if waiting_match:
        # Join existing match
        waiting_match.player2_id = current_user.id
        waiting_match.status = "active"
        db.commit()
        return {"match_id": waiting_match.match_id, "opponent": waiting_match.player1.username}
    else:
        # Create new match
        match_id = str(uuid.uuid4())
        match = PVPMatch(
            match_id=match_id,
            player1_id=current_user.id,
            status="waiting"
        )
        db.add(match)
        db.commit()
        return {"match_id": match_id, "status": "waiting"}
```

**Port strategy**:
1. Copy to `BlogCMS/backend/app/plugins/typing_game/routes.py`
2. Update imports
3. Add XP system integration (if not exists, create basic version)
4. Mount in main.py conditionally

---

## 📦 Shared Components to Port

### XP System

**Location**: `ITAppBetaV1/src/components/XP/`

Files:
- `XPBadge.tsx` - Display XP rewards (+50 XP, +100 XP)
- `XPProgress.tsx` - Progress bar showing level progress
- `LevelBadge.tsx` - Display user level with styling

**Port strategy**:
1. Copy to `BlogCMS/frontend/src/components/shared/XP/`
2. Used by both tutorials and typing game plugins

---

### Skills System

**Location**: `ITAppBetaV1/src/components/Skills/`

Files:
- `SkillBadges.tsx` - Display skill tags (Python, Docker, Git, etc.)
- `SkillProgress.tsx` - Skill level progress
- `SkillTree.tsx` - Visual skill tree (complex, maybe later)

**Port strategy**:
1. Copy SkillBadges.tsx to `BlogCMS/frontend/src/components/shared/Skills/`
2. Used by tutorials plugin

---

## 📋 Database Tables Needed

### Tutorials Plugin Tables
```sql
-- tutorials
CREATE TABLE tutorials (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    difficulty VARCHAR(50),  -- beginner, intermediate, advanced
    estimated_time_minutes INTEGER,
    xp_reward INTEGER DEFAULT 100,
    is_published BOOLEAN DEFAULT false,
    category_id INTEGER REFERENCES tutorial_categories(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);

-- tutorial_steps
CREATE TABLE tutorial_steps (
    id SERIAL PRIMARY KEY,
    tutorial_id INTEGER REFERENCES tutorials(id) ON DELETE CASCADE,
    "order" INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    code_example TEXT,
    code_language VARCHAR(50),
    hints JSON,
    created_at TIMESTAMP DEFAULT NOW()
);

-- tutorial_categories
CREATE TABLE tutorial_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    icon VARCHAR(50),
    color VARCHAR(7),  -- Hex color
    description TEXT
);

-- tutorial_progress
CREATE TABLE tutorial_progress (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    tutorial_id INTEGER REFERENCES tutorials(id) ON DELETE CASCADE,
    step_id INTEGER REFERENCES tutorial_steps(id) ON DELETE CASCADE,
    completed BOOLEAN DEFAULT false,
    completed_at TIMESTAMP,
    started_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, tutorial_id, step_id)
);
```

### Typing Game Plugin Tables
```sql
-- game_sessions
CREATE TABLE game_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    game_type VARCHAR(50) NOT NULL,
    checksum VARCHAR(255) NOT NULL,
    started_at TIMESTAMP DEFAULT NOW(),
    ended_at TIMESTAMP,
    is_valid BOOLEAN DEFAULT true
);

-- game_scores
CREATE TABLE game_scores (
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES game_sessions(id) ON DELETE CASCADE,
    round_number INTEGER NOT NULL,
    wpm FLOAT NOT NULL,
    accuracy FLOAT NOT NULL,
    errors INTEGER DEFAULT 0,
    time_taken FLOAT,
    passed BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

-- pvp_matches
CREATE TABLE pvp_matches (
    id SERIAL PRIMARY KEY,
    match_id VARCHAR(255) UNIQUE NOT NULL,
    player1_id INTEGER REFERENCES users(id),
    player2_id INTEGER REFERENCES users(id),
    winner_id INTEGER REFERENCES users(id),
    match_type VARCHAR(50) DEFAULT 'quick_brown_fox_pvp',
    status VARCHAR(50) DEFAULT 'active',  -- active, completed, forfeited, waiting
    created_at TIMESTAMP DEFAULT NOW(),
    ended_at TIMESTAMP
);

-- game_leaderboard
CREATE TABLE game_leaderboard (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    game_type VARCHAR(50) NOT NULL,
    best_wpm FLOAT DEFAULT 0,
    best_accuracy FLOAT DEFAULT 0,
    total_games INTEGER DEFAULT 0,
    total_wins INTEGER DEFAULT 0,
    current_streak INTEGER DEFAULT 0,
    last_played TIMESTAMP,
    UNIQUE(user_id, game_type)
);
```

---

## 🔑 Key Dependencies to Install

### Frontend
```bash
cd "C:\Gitlab Projects\BlogCMS\frontend"

# For tutorials
npm install react-syntax-highlighter @types/react-syntax-highlighter
npm install canvas-confetti @types/canvas-confetti

# Already installed (should have)
# - framer-motion
# - lucide-react
# - react-router-dom
```

### Backend
```bash
cd "C:\Gitlab Projects\BlogCMS\backend"

# Should already have:
# - fastapi
# - sqlalchemy
# - psycopg2
# - pydantic
# - python-jose (for JWT)
```

---

## 📦 Files Ready to Copy (Summary)

### Tutorials Plugin (~2,000 lines total)
**Frontend**:
- ✅ `pages/tutorials/TutorialsList.tsx` (500 lines)
- ✅ `pages/tutorials/TutorialViewer.tsx` (700 lines)
- ✅ `services/api/tutorials.api.ts` (200 lines)
- ✅ `components/XP/XPBadge.tsx` (100 lines)
- ✅ `components/Skills/SkillBadges.tsx` (150 lines)
- ✅ `components/Common/CategoryBadge.tsx` (100 lines)

**Backend**:
- ✅ `services/tutorials/models.py` (300 lines)
- ✅ `services/tutorials/routes.py` (400 lines)
- ✅ `services/tutorials/schemas.py` (200 lines)
- ✅ `services/tutorials/crud.py` (200 lines)

### Typing Game Plugin (~3,500 lines total)
**Frontend**:
- ✅ `components/Games/TypingGame/QuickBrownFoxGameV3.tsx` (600 lines)
- ✅ `components/Games/TypingEngine/` (modals, ~600 lines)
- ✅ `components/Games/PVP/` (7 files, ~1,700 lines)
- ✅ `hooks/useQuickBrownFoxAPI.ts` (200 lines)
- ✅ `services/api/games.api.ts` (200 lines)

**Backend**:
- ✅ `services/games/models.py` (400 lines)
- ✅ `services/games/routes.py` (500 lines)
- ✅ `services/games/schemas.py` (200 lines)
- ✅ `services/games/scoring.py` (150 lines)
- ✅ `services/games/pvp_matchmaking.py` (200 lines)

**Total lines to port**: ~5,500 lines of well-tested code 🚀

---

**Status**: ✅ INVENTORY COMPLETE
**Next Step**: Begin porting tutorials plugin (Week 1)
**Last Updated**: 2026-01-11
