// src/store/index.ts
/**
 * Central export point for all Zustand stores
 *
 * Usage:
 *   import { useSiteSettingsStore } from '@/store';
 *
 * Or access state directly:
 *   const settings = useSiteSettingsStore((state) => state.settings);
 *   const loadSettings = useSiteSettingsStore((state) => state.loadSettings);
 */

export * from './useSiteSettingsStore';
