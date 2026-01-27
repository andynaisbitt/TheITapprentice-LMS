# Course Content Editor - Known Issues & Limitations

**Document Created**: 2026-01-27
**Purpose**: Track remaining issues with the course content block editor before comprehensive content seeding.

---

## Critical Issues

### 1. Rich Text Editor Not Functional
**Status**: Broken
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: The text block editor uses a basic `<textarea>` element instead of a proper rich text editor. This means:
- No bold, italic, or underline formatting
- No bullet points or numbered lists
- No links or embedded media
- No headings within text blocks
- Plain text only - no markdown rendering in editor

**Impact**: Content creators cannot format text properly, making the editor unsuitable for production use.

**Workaround**: Seed content directly via database/script with pre-formatted text.

**Recommended Fix**: Integrate a proper rich text editor such as:
- TipTap (recommended - headless, React-friendly)
- Slate.js
- Lexical (Meta's editor)
- React-Quill

---

### 2. No Block Reordering (Drag & Drop)
**Status**: Missing Feature
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: Content blocks cannot be reordered after creation. Users must delete and recreate blocks to change order.

**Impact**: Poor UX for content creation and editing.

**Recommended Fix**: Implement drag-and-drop using:
- `@dnd-kit/core` (recommended)
- `react-beautiful-dnd`
- `react-sortable-hoc`

---

### 3. Image Block Upload Missing
**Status**: Partially Implemented
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: Image blocks only accept URLs. There's no file upload functionality for local images.

**Impact**: Users must host images externally before adding them to courses.

**Recommended Fix**:
- Add file upload to backend (`/api/courses/upload-image`)
- Integrate with S3 or local storage
- Add drag-and-drop upload zone in editor

---

### 4. Video Block - URL Only
**Status**: Limitation
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: Video blocks only support YouTube/Vimeo embed URLs. No support for:
- Direct video file uploads
- Self-hosted video URLs
- Video preview in editor

**Impact**: Limited video hosting options.

**Recommended Fix**:
- Add video file upload support
- Add preview player in editor
- Support more video platforms (Wistia, Loom, etc.)

---

## Medium Priority Issues

### 5. Code Block - No Syntax Highlighting in Editor
**Status**: Partial
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: Code blocks use plain `<textarea>` in editor. Syntax highlighting only appears in the player view.

**Impact**: Difficult to write and review code in the editor.

**Recommended Fix**: Use Monaco Editor or CodeMirror in edit mode.

---

### 6. No Preview Mode
**Status**: Missing Feature
**Location**: `frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx`

**Problem**: No way to preview how content will look to students without publishing the course.

**Impact**: Content creators must publish to see final result.

**Recommended Fix**: Add "Preview" button that renders content using `CoursePlayer` styles.

---

### 7. Timeline Block - Limited Editing
**Status**: Basic Implementation
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: Timeline events are difficult to edit. Adding/removing/reordering events is clunky.

**Recommended Fix**: Improve timeline event editor UI with:
- Inline editing
- Drag-and-drop reordering
- Better visual feedback

---

### 8. Interactive Block - No Actual Interactivity
**Status**: Placeholder
**Location**: `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx`

**Problem**: The "interactive" block type exists but has minimal functionality. It's essentially a text block with a different icon.

**Recommended Fix**: Define what "interactive" means and implement:
- Interactive diagrams
- Clickable hotspots
- Embedded simulations

---

## Low Priority Issues

### 9. No Undo/Redo
**Status**: Missing Feature

**Problem**: No way to undo accidental deletions or changes.

**Recommended Fix**: Implement state history with undo/redo stack.

---

### 10. Auto-save Not Working Reliably
**Status**: Intermittent

**Problem**: Changes sometimes lost if user navigates away quickly.

**Recommended Fix**:
- Add debounced auto-save
- Show "Saving..." indicator
- Warn before navigation with unsaved changes

---

### 11. Callout Block - Limited Variants
**Status**: Works but Limited

**Problem**: Only 4 callout types (info, warning, tip, note). Could use more variety.

**Suggested Additions**:
- `success` (green)
- `error` (red)
- `quote` (styled blockquote)
- `example` (code-like styling)

---

## Quiz Block Issues (Partially Fixed)

### 12. Quiz Grading - Code Challenge Not Graded
**Status**: Limitation
**Location**: `frontend/src/plugins/courses/pages/public/CoursePlayer.tsx`

**Problem**: The `code_challenge` question type cannot be automatically graded. It requires manual review or code execution environment.

**Current Behaviour**: Code challenges are always marked as "correct" to allow progression.

**Recommended Fix**:
- Integrate with code execution sandbox (Judge0, Sphere Engine)
- Or mark as "practice only" with no grading

---

### 13. Quiz - No Randomisation
**Status**: Missing Feature

**Problem**: Questions always appear in the same order. No option to randomise.

**Recommended Fix**: Add `randomize: boolean` option to quiz blocks.

---

### 14. Quiz - No Time Limits
**Status**: Missing Feature

**Problem**: No way to set time limits on quizzes.

**Recommended Fix**: Add optional `time_limit_minutes` field.

---

## Recommendations for Content Seeding

Given the current state of the editor, **direct database seeding is recommended** for production content:

1. **Use seed scripts** (`seed_data.py`) to insert courses with proper formatting
2. **Store formatted content** as plain text with markdown-style notation
3. **Test content in CoursePlayer** which renders content correctly
4. **Avoid using the editor** for complex content until rich text is implemented

---

## Priority Roadmap

| Priority | Issue | Effort |
|----------|-------|--------|
| High | Rich Text Editor | Large |
| High | Block Reordering | Medium |
| Medium | Image Upload | Medium |
| Medium | Preview Mode | Small |
| Medium | Code Editor Syntax | Medium |
| Low | Undo/Redo | Medium |
| Low | Auto-save | Small |

---

## Files Involved

- `frontend/src/plugins/courses/components/builder/ContentBlockEditor.tsx` - Main editor component
- `frontend/src/plugins/courses/pages/admin/CourseEditorPage.tsx` - Editor page wrapper
- `frontend/src/plugins/courses/pages/public/CoursePlayer.tsx` - Content renderer
- `frontend/src/plugins/courses/types/index.ts` - Type definitions
- `backend/app/plugins/courses/seed_data.py` - Seed data script

---

**Next Steps**: Complete course content seeding via `seed_data.py`, then address editor issues in future sprints.
