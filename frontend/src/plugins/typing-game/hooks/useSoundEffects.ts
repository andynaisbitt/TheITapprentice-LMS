// frontend/src/plugins/typing-game/hooks/useSoundEffects.ts
/**
 * Sound effects system for typing game
 * Provides audio feedback for various game events
 */

import { useCallback, useRef, useEffect, useState } from 'react';

type SoundType =
  | 'keystroke'
  | 'error'
  | 'combo'
  | 'combo_break'
  | 'milestone'
  | 'challenge_complete'
  | 'level_up'
  | 'game_start'
  | 'game_end'
  | 'personal_best'
  | 'countdown';

interface SoundConfig {
  url: string;
  volume: number;
  poolSize: number;
}

// Sound configurations - using Web Audio API oscillators for demo
// In production, replace with actual audio files
const SOUND_CONFIGS: Record<SoundType, SoundConfig> = {
  keystroke: { url: '', volume: 0.3, poolSize: 5 },
  error: { url: '', volume: 0.4, poolSize: 3 },
  combo: { url: '', volume: 0.5, poolSize: 3 },
  combo_break: { url: '', volume: 0.4, poolSize: 1 },
  milestone: { url: '', volume: 0.6, poolSize: 1 },
  challenge_complete: { url: '', volume: 0.7, poolSize: 1 },
  level_up: { url: '', volume: 0.8, poolSize: 1 },
  game_start: { url: '', volume: 0.5, poolSize: 1 },
  game_end: { url: '', volume: 0.5, poolSize: 1 },
  personal_best: { url: '', volume: 0.8, poolSize: 1 },
  countdown: { url: '', volume: 0.4, poolSize: 1 },
};

// Synthesized sound frequencies and durations
const SYNTH_SOUNDS: Record<SoundType, { freq: number; duration: number; type: OscillatorType; freqEnd?: number }[]> = {
  keystroke: [{ freq: 440, duration: 0.05, type: 'sine' }],
  error: [
    { freq: 200, duration: 0.1, type: 'sawtooth' },
    { freq: 150, duration: 0.1, type: 'sawtooth' },
  ],
  combo: [
    { freq: 523, duration: 0.08, type: 'sine' },
    { freq: 659, duration: 0.08, type: 'sine' },
    { freq: 784, duration: 0.1, type: 'sine' },
  ],
  combo_break: [{ freq: 300, duration: 0.2, type: 'sawtooth', freqEnd: 100 }],
  milestone: [
    { freq: 523, duration: 0.1, type: 'sine' },
    { freq: 659, duration: 0.1, type: 'sine' },
    { freq: 784, duration: 0.1, type: 'sine' },
    { freq: 1047, duration: 0.2, type: 'sine' },
  ],
  challenge_complete: [
    { freq: 392, duration: 0.15, type: 'sine' },
    { freq: 523, duration: 0.15, type: 'sine' },
    { freq: 659, duration: 0.15, type: 'sine' },
    { freq: 784, duration: 0.3, type: 'sine' },
  ],
  level_up: [
    { freq: 262, duration: 0.1, type: 'sine' },
    { freq: 330, duration: 0.1, type: 'sine' },
    { freq: 392, duration: 0.1, type: 'sine' },
    { freq: 523, duration: 0.1, type: 'sine' },
    { freq: 659, duration: 0.1, type: 'sine' },
    { freq: 784, duration: 0.3, type: 'sine' },
  ],
  game_start: [
    { freq: 440, duration: 0.1, type: 'sine' },
    { freq: 523, duration: 0.1, type: 'sine' },
    { freq: 659, duration: 0.15, type: 'sine' },
  ],
  game_end: [
    { freq: 659, duration: 0.15, type: 'sine' },
    { freq: 523, duration: 0.15, type: 'sine' },
    { freq: 440, duration: 0.2, type: 'sine' },
  ],
  personal_best: [
    { freq: 523, duration: 0.1, type: 'sine' },
    { freq: 659, duration: 0.1, type: 'sine' },
    { freq: 784, duration: 0.1, type: 'sine' },
    { freq: 1047, duration: 0.1, type: 'sine' },
    { freq: 784, duration: 0.1, type: 'sine' },
    { freq: 1047, duration: 0.3, type: 'sine' },
  ],
  countdown: [{ freq: 880, duration: 0.1, type: 'sine' }],
};

interface SoundSettings {
  enabled: boolean;
  volume: number; // 0-1
  keyboardSounds: boolean;
}

const DEFAULT_SETTINGS: SoundSettings = {
  enabled: true,
  volume: 0.5,
  keyboardSounds: true,
};

const STORAGE_KEY = 'typing_game_sound_settings';

export function useSoundEffects() {
  const [settings, setSettings] = useState<SoundSettings>(() => {
    if (typeof window === 'undefined') return DEFAULT_SETTINGS;
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? { ...DEFAULT_SETTINGS, ...JSON.parse(stored) } : DEFAULT_SETTINGS;
  });

  const audioContextRef = useRef<AudioContext | null>(null);
  const gainNodeRef = useRef<GainNode | null>(null);

  // Initialize audio context on user interaction
  const initAudioContext = useCallback(() => {
    if (!audioContextRef.current) {
      audioContextRef.current = new (window.AudioContext || (window as any).webkitAudioContext)();
      gainNodeRef.current = audioContextRef.current.createGain();
      gainNodeRef.current.connect(audioContextRef.current.destination);
      gainNodeRef.current.gain.value = settings.volume;
    }

    // Resume if suspended
    if (audioContextRef.current.state === 'suspended') {
      audioContextRef.current.resume();
    }
  }, [settings.volume]);

  // Update gain when volume changes
  useEffect(() => {
    if (gainNodeRef.current) {
      gainNodeRef.current.gain.value = settings.volume;
    }
  }, [settings.volume]);

  // Save settings to localStorage
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  }, [settings]);

  // Play synthesized sound
  const playSynthSound = useCallback((soundType: SoundType, volumeMultiplier = 1) => {
    if (!settings.enabled) return;
    if (soundType === 'keystroke' && !settings.keyboardSounds) return;

    initAudioContext();

    const ctx = audioContextRef.current;
    const gainNode = gainNodeRef.current;
    if (!ctx || !gainNode) return;

    const notes = SYNTH_SOUNDS[soundType];
    const config = SOUND_CONFIGS[soundType];

    let startTime = ctx.currentTime;

    notes.forEach((note) => {
      const oscillator = ctx.createOscillator();
      const noteGain = ctx.createGain();

      oscillator.type = note.type;
      oscillator.frequency.setValueAtTime(note.freq, startTime);

      if (note.freqEnd) {
        oscillator.frequency.linearRampToValueAtTime(note.freqEnd, startTime + note.duration);
      }

      noteGain.gain.setValueAtTime(config.volume * volumeMultiplier * settings.volume, startTime);
      noteGain.gain.exponentialRampToValueAtTime(0.01, startTime + note.duration);

      oscillator.connect(noteGain);
      noteGain.connect(ctx.destination);

      oscillator.start(startTime);
      oscillator.stop(startTime + note.duration + 0.05);

      startTime += note.duration;
    });
  }, [settings.enabled, settings.keyboardSounds, settings.volume, initAudioContext]);

  // Public API
  const playKeystroke = useCallback(() => {
    playSynthSound('keystroke');
  }, [playSynthSound]);

  const playError = useCallback(() => {
    playSynthSound('error');
  }, [playSynthSound]);

  const playCombo = useCallback((comboLevel: number = 1) => {
    // Higher combo = slightly louder
    const volumeMultiplier = Math.min(1 + comboLevel * 0.1, 1.5);
    playSynthSound('combo', volumeMultiplier);
  }, [playSynthSound]);

  const playComboBreak = useCallback(() => {
    playSynthSound('combo_break');
  }, [playSynthSound]);

  const playMilestone = useCallback(() => {
    playSynthSound('milestone');
  }, [playSynthSound]);

  const playChallengeComplete = useCallback(() => {
    playSynthSound('challenge_complete');
  }, [playSynthSound]);

  const playLevelUp = useCallback(() => {
    playSynthSound('level_up');
  }, [playSynthSound]);

  const playGameStart = useCallback(() => {
    playSynthSound('game_start');
  }, [playSynthSound]);

  const playGameEnd = useCallback(() => {
    playSynthSound('game_end');
  }, [playSynthSound]);

  const playPersonalBest = useCallback(() => {
    playSynthSound('personal_best');
  }, [playSynthSound]);

  const playCountdown = useCallback(() => {
    playSynthSound('countdown');
  }, [playSynthSound]);

  const updateSettings = useCallback((newSettings: Partial<SoundSettings>) => {
    setSettings(prev => ({ ...prev, ...newSettings }));
  }, []);

  const toggleSound = useCallback(() => {
    setSettings(prev => ({ ...prev, enabled: !prev.enabled }));
  }, []);

  const setVolume = useCallback((volume: number) => {
    setSettings(prev => ({ ...prev, volume: Math.max(0, Math.min(1, volume)) }));
  }, []);

  return {
    // Playback functions
    playKeystroke,
    playError,
    playCombo,
    playComboBreak,
    playMilestone,
    playChallengeComplete,
    playLevelUp,
    playGameStart,
    playGameEnd,
    playPersonalBest,
    playCountdown,

    // Settings
    settings,
    updateSettings,
    toggleSound,
    setVolume,

    // Initialize (call on first user interaction)
    initAudioContext,
  };
}

export default useSoundEffects;
