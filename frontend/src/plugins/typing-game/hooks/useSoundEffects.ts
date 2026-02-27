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

// Sound configurations — volumes are intentionally low for a subtle, ambient feel
const SOUND_CONFIGS: Record<SoundType, SoundConfig> = {
  keystroke:         { url: '', volume: 0.07, poolSize: 5 },
  error:             { url: '', volume: 0.18, poolSize: 3 },
  combo:             { url: '', volume: 0.20, poolSize: 3 },
  combo_break:       { url: '', volume: 0.16, poolSize: 1 },
  milestone:         { url: '', volume: 0.22, poolSize: 1 },
  challenge_complete:{ url: '', volume: 0.25, poolSize: 1 },
  level_up:          { url: '', volume: 0.25, poolSize: 1 },
  game_start:        { url: '', volume: 0.20, poolSize: 1 },
  game_end:          { url: '', volume: 0.20, poolSize: 1 },
  personal_best:     { url: '', volume: 0.25, poolSize: 1 },
  countdown:         { url: '', volume: 0.15, poolSize: 1 },
};

// Synthesized sound definitions — all sine waves (no sawtooth/square to avoid harshness).
// Durations are short; the envelope adds a 5 ms attack to prevent click artifacts.
const SYNTH_SOUNDS: Record<SoundType, { freq: number; duration: number; type: OscillatorType; freqEnd?: number }[]> = {
  // Barely-there soft tick — just enough feedback without distraction
  keystroke: [{ freq: 320, duration: 0.025, type: 'sine' }],

  // Gentle two-tone descend — conveys "wrong" without being jarring
  error: [
    { freq: 200, duration: 0.07, type: 'sine' },
    { freq: 150, duration: 0.07, type: 'sine' },
  ],

  // Quick ascending chord — subtle positive signal
  combo: [
    { freq: 440, duration: 0.05, type: 'sine' },
    { freq: 554, duration: 0.05, type: 'sine' },
    { freq: 659, duration: 0.07, type: 'sine' },
  ],

  // Soft descending glide — no harsh sawtooth
  combo_break: [{ freq: 260, duration: 0.12, type: 'sine', freqEnd: 130 }],

  // Two-note chime — clean and brief
  milestone: [
    { freq: 440, duration: 0.07, type: 'sine' },
    { freq: 660, duration: 0.12, type: 'sine' },
  ],

  // Three ascending tones — slightly celebratory but not overbearing
  challenge_complete: [
    { freq: 330, duration: 0.08, type: 'sine' },
    { freq: 440, duration: 0.08, type: 'sine' },
    { freq: 554, duration: 0.14, type: 'sine' },
  ],

  // Four ascending tones — meaningful without being arcade-y
  level_up: [
    { freq: 262, duration: 0.06, type: 'sine' },
    { freq: 330, duration: 0.06, type: 'sine' },
    { freq: 440, duration: 0.06, type: 'sine' },
    { freq: 523, duration: 0.14, type: 'sine' },
  ],

  // Two-note rising signal
  game_start: [
    { freq: 392, duration: 0.07, type: 'sine' },
    { freq: 523, duration: 0.10, type: 'sine' },
  ],

  // Two-note descend — quiet sign-off
  game_end: [
    { freq: 440, duration: 0.09, type: 'sine' },
    { freq: 330, duration: 0.11, type: 'sine' },
  ],

  // Four-note flourish — rewarding but not over the top
  personal_best: [
    { freq: 440, duration: 0.06, type: 'sine' },
    { freq: 554, duration: 0.06, type: 'sine' },
    { freq: 659, duration: 0.06, type: 'sine' },
    { freq: 880, duration: 0.16, type: 'sine' },
  ],

  // Single soft tick for countdown
  countdown: [{ freq: 660, duration: 0.07, type: 'sine' }],
};

interface SoundSettings {
  enabled: boolean;
  volume: number; // 0-1
  keyboardSounds: boolean;
}

const DEFAULT_SETTINGS: SoundSettings = {
  enabled: false,  // off by default — user opts in
  volume: 0.3,
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

      // Short attack (5 ms) prevents the hard click you get from jumping straight
      // to full volume, then decay to near-silence over the note's duration.
      const peak = config.volume * volumeMultiplier * settings.volume;
      noteGain.gain.setValueAtTime(0.0001, startTime);
      noteGain.gain.exponentialRampToValueAtTime(peak, startTime + 0.005);
      noteGain.gain.exponentialRampToValueAtTime(0.0001, startTime + note.duration);

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
