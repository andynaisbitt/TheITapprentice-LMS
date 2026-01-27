// frontend/src/plugins/skills/index.ts
/**
 * Skills Plugin - OSRS-style IT skill progression system
 *
 * Features:
 * - 12 IT skills with XP-based progression
 * - Level 1-99 with exponential XP curve
 * - 6 tiers: Novice -> Apprentice -> Journeyman -> Expert -> Master -> Grandmaster
 * - IT Level (Combat Level equivalent) for overall ranking
 * - Leaderboards (global and per-skill)
 * - XP history tracking
 * - Milestone achievements
 */

// Types
export * from './types';

// API Service
export { skillsApi } from './services/skillsApi';

// Pages
export { SkillsDashboard, SkillDetailPage, SkillsLeaderboard } from './pages';

// Components
export {
  SkillBadge,
  SkillProgressBar,
  SkillsWidget,
  SkillXPToast,
  SkillXPToastContainer,
  useSkillXPToasts,
} from './components';
