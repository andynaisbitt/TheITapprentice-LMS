# Infinite Rush Game - Issues & Improvements

## Current Issues

### 1. Timer Stops Counting While Typing
- **Severity**: High
- **Description**: The countdown timer appears to stop or behave erratically while the user is actively typing
- **Expected Behavior**: Timer should continuously count down regardless of typing activity
- **Likely Cause**: Timer interval might be getting cleared/conflicted with input handling

### 2. Lacks Visual Effects
- **Severity**: Medium
- **Description**: The game feels visually flat compared to modern typing games
- **Missing Effects**:
  - No particle effects on correct/incorrect keystrokes
  - No screen shake on mistakes
  - No combo counter with visual flair
  - No speed lines or motion effects
  - No celebration effects for milestones

### 3. Missing Features from QuickBrownFox
- **Severity**: Medium
- **Description**: Infinite Rush doesn't have feature parity with QuickBrownFox game
- **Missing Features**:
  - [ ] Fox runner animation showing progress
  - [ ] Combo counter system with multipliers
  - [ ] Sound effects (keystroke sounds, combos, etc.)
  - [ ] Anti-cheat integration
  - [ ] Real-time WPM/accuracy display with animations
  - [ ] Confetti on personal bests
  - [ ] Streak display
  - [ ] Daily challenge integration

---

## Recommended Improvements

### Phase 1: Core Fixes
1. Fix timer implementation - ensure interval runs independently of input handlers
2. Add proper game state management (playing, paused, complete)
3. Integrate with existing hooks (useTypingEngine, useComboSystem, useSoundEffects)

### Phase 2: Visual Polish
1. Add particle system for keystrokes
2. Implement combo counter with visual feedback
3. Add screen shake on errors
4. Add speed/velocity visual indicators
5. Implement milestone celebrations (25 words, 50 words, etc.)

### Phase 3: Feature Parity
1. Add fox or similar mascot animation
2. Integrate anti-cheat system
3. Add sound effects matching QuickBrownFox
4. Ensure stats are submitted to API on completion
5. Add personal best tracking and notifications

---

## Technical Notes

### Current Implementation Location
- Component: `frontend/src/plugins/typing-game/components/InfiniteRushGame.tsx`
- Page: `frontend/src/plugins/typing-game/pages/InfiniteRushPage.tsx`

### Reference Implementation
- QuickBrownFox has all the features we want: `frontend/src/plugins/typing-game/components/QuickBrownFoxGame.tsx`
- Reusable hooks available:
  - `useTypingEngine` - Core typing logic
  - `useComboSystem` - Combo tracking
  - `useSoundEffects` - Audio feedback
  - `useAntiCheat` - Validation

---

*Last Updated: 2026-01-26*
