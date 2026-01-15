// frontend/src/plugins/shared/index.ts
/**
 * Shared plugin exports
 */

// Types
export * from './types';

// API
export { progressApi, default as progressApiDefault } from './services/progressApi';

// Components
export { XPProgressBar } from './components/XPProgressBar';
export { AchievementBadge } from './components/AchievementBadge';
export { AchievementsGrid } from './components/AchievementsGrid';
export { StreakCounter } from './components/StreakCounter';
