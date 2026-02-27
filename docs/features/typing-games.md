# Typing Games — Feature Documentation

**Platform:** TheITApprentice.com
**Route:** `/typing-practice`
**Stack:** React 18 + TypeScript, FastAPI backend, PostgreSQL
**Last updated:** February 2026

---

## Overview

The Typing Practice section is a suite of four distinct game modes built to help IT professionals and learners build speed and accuracy with IT-specific terminology — commands, flags, technology names, networking concepts, and real-world syntax.

Unlike generic typing games (e.g. Monkeytype), the word pools are drawn from real IT vocabulary. You're not typing random words — you're building muscle memory with the exact terminology you'll use on the job or in certification exams.

All modes are **free to play without an account**. Signing in unlocks score saving, leaderboards, XP tracking, streak bonuses, and milestone progress.

---

## Game Modes

### 1. Quick Brown Fox ⚡
**Route:** `/typing-practice/play`
**Format:** 3-round progressive challenge
**Colour theme:** Blue → Purple gradient

The flagship mode. Three rounds that escalate in difficulty and time pressure:

| Round | Name           | Time Limit | Description                        |
|-------|----------------|------------|------------------------------------|
| 1     | Warmup         | None       | Get familiar with the words        |
| 2     | Speed Challenge| 25 seconds | Same words, race the clock         |
| 3     | INSANE MODE    | 12 seconds | 12 seconds — type fast or fail     |

**Key mechanics:**
- Word-by-word input — you can't go back to fix previous words
- Real-time WPM and accuracy displayed live
- Combo system — consecutive correct words build a multiplier
- Fox Runner animation that reacts to your speed
- Anti-cheat: keystroke timing analysis and pattern detection
- Results screen with XP breakdown, streak update, and daily challenge progress

---

### 2. Infinite Rush ♾️
**Route:** `/typing-practice/infinite-rush`
**Format:** 60-second timed sprint
**Colour theme:** Orange → Red gradient

A pure speed test. Words stream continuously for 60 seconds and your goal is simply to type as many as possible without breaking your combo.

**Key mechanics:**
- Fixed 60-second countdown — visible at all times
- 12 words displayed at once; 6 new words are added automatically as you clear them (infinite stream)
- Score based on words completed × WPM
- Combo multiplier rewards consistency
- IT-themed word pools: commands, flags, hostnames, protocols, tool names
- Live stats: WPM, accuracy, combo, words completed
- Results saved and compared against your personal best

**Word pool examples:**
`sudo`, `chmod`, `netstat`, `192.168.1.1`, `localhost`, `docker`, `kubectl`, `ssh`, `grep`, `iptables`, `nginx`, `postgres`, `ansible`

---

### 3. Ghost Mode 👻
**Route:** `/typing-practice/ghost`
**Format:** 3-round progressive (same structure as Quick Brown Fox)
**Colour theme:** Purple → Indigo gradient

Race against a ghost of your own personal best performance.

**Key mechanics:**
- Your previous best run is recorded and replayed as a "ghost"
- A ghost progress bar shows where your previous self was at the same point in time
- Live ahead/behind indicator: you can see in real time whether you're beating your personal best
- Visual feedback changes based on whether you're winning or losing the race
- Same anti-cheat and combo systems as Quick Brown Fox
- Particularly satisfying for people who want a measurable improvement loop

**Best for:** Players who are competitive with themselves and want to see concrete improvement over time.

---

### 4. Practice Mode 🎯
**Route:** `/typing-practice/practice`
**Format:** Custom word lists, self-paced
**Colour theme:** Green → Teal gradient

A low-pressure mode for deliberate practice using custom word lists.

**Key mechanics:**
- Select from curated word lists (networking, Linux commands, scripting, etc.)
- Self-paced — no timer pressure unless you want it
- Ideal for building familiarity with specific terminology before exams or labs
- Results still tracked and contribute to XP

---

### 5. PVP Battle ⚔️ *(Coming Soon)*
**Route:** `/typing-practice/pvp`
**Status:** In development

Real-time typing battles against other players. The infrastructure is built; the mode will be enabled once matchmaking is stable.

---

## Stats & Progression

All signed-in players get:

| Stat              | Description                                    |
|-------------------|------------------------------------------------|
| Best WPM          | Personal all-time best words per minute        |
| Average Accuracy  | Mean accuracy across all completed games       |
| Total Games       | Lifetime games completed                       |
| Current Streak    | Consecutive days with at least one game played |
| XP Earned         | Experience points from typing activity         |

**Milestones system** — progressive targets with progress bars:
- Reach 30 / 50 / 80 / 100 / 120 / 150 WPM
- Play 10 / 25 / 50 / 100 / 250 / 500 games
- Reach 95% / 99% accuracy
- Build 3 / 7 / 14 / 30 / 60-day streaks

---

## Leaderboard

Top 3 players shown on the typing practice home page.
Full leaderboard at `/typing-practice/leaderboard`.
Sorted by best WPM. Public — no account needed to view.

---

## Anti-Cheat System

All game modes include:
- **Keystroke timing analysis** — detects unnaturally consistent timing (bot-like behaviour)
- **WPM anomaly detection** — flags results far outside the statistical norm
- **Pattern detection** — identifies paste events and macro-style input
- Results that fail anti-cheat checks are rejected server-side and not saved to the leaderboard

---

## Sound System

Optional audio feedback is built in across all game modes:
- Correct word: subtle positive tone
- Wrong key: brief error sound
- Combo milestone: ascending chime
- **Off by default** — toggle always visible in the game interface

---

## Mobile Support

All four game modes have full mobile keyboard support. The input field triggers the virtual keyboard on touch devices. Tested on iOS Safari and Android Chrome.

---

## Technical Notes

| Layer     | Detail                                                        |
|-----------|---------------------------------------------------------------|
| Frontend  | React 18 + TypeScript, Framer Motion animations               |
| State     | Custom hooks: `useTypingEngine`, `useAntiCheat`, `useComboSystem`, `useSoundEffects`, `useGameWords` |
| Backend   | FastAPI — game session management, score submission, leaderboard |
| Database  | PostgreSQL — game results, user stats, streak tracking         |
| Auth      | JWT — scores only saved when signed in; guest play always available |

---

## Screenshot Guide

To capture the right screenshots for marketing/docs, capture these specific states:

### Landing Page
- URL: `/typing-practice`
- What to show: The full page with Quick Brown Fox featured card, 2×2 game grid, and top players section
- Ideal state: Logged in with a visible streak and WPM stat

### Quick Brown Fox — In Progress
- URL: `/typing-practice/play`
- What to show: Mid-game, Round 2 (Speed Challenge), with a combo active and timer visible
- Ideal state: A few words typed, green highlighted correct words, red on current word

### Quick Brown Fox — Results Screen
- What to show: End of round 3, results card with WPM, accuracy, XP gained, and streak update

### Infinite Rush — In Progress
- URL: `/typing-practice/infinite-rush`
- What to show: Mid-game with countdown visible (e.g. 38 seconds remaining), combo counter active, word stream visible

### Ghost Mode — In Progress
- URL: `/typing-practice/ghost`
- What to show: Ghost progress bar visible, ahead/behind indicator showing "AHEAD" in green

### Practice Mode
- URL: `/typing-practice/practice`
- What to show: Word list selected, relaxed practice in progress

### Leaderboard
- URL: `/typing-practice/leaderboard`
- What to show: Top 10 with WPM scores, usernames, rank icons

---

*This document is part of the TheITApprentice platform documentation.*
