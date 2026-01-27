// frontend/src/plugins/typing-game/components/SoundSettings.tsx
import { Volume2, VolumeX, Keyboard } from 'lucide-react';
import { motion } from 'framer-motion';

interface SoundSettings {
  enabled: boolean;
  volume: number;
  keyboardSounds: boolean;
}

interface SoundSettingsProps {
  settings: SoundSettings;
  onToggleSound: () => void;
  onVolumeChange: (volume: number) => void;
  onToggleKeyboardSounds?: () => void;
  compact?: boolean;
}

export function SoundSettingsPanel({
  settings,
  onToggleSound,
  onVolumeChange,
  onToggleKeyboardSounds,
  compact = false,
}: SoundSettingsProps) {
  if (compact) {
    return (
      <button
        onClick={onToggleSound}
        className={`p-2 rounded-lg transition-colors ${
          settings.enabled
            ? 'bg-blue-100 text-blue-600 hover:bg-blue-200 dark:bg-blue-900 dark:text-blue-400'
            : 'bg-gray-100 text-gray-400 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-500'
        }`}
        title={settings.enabled ? 'Sound on' : 'Sound off'}
      >
        {settings.enabled ? (
          <Volume2 className="w-5 h-5" />
        ) : (
          <VolumeX className="w-5 h-5" />
        )}
      </button>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm">
      <h4 className="font-medium text-gray-900 dark:text-white mb-4 flex items-center gap-2">
        <Volume2 className="w-5 h-5 text-blue-500" />
        Sound Settings
      </h4>

      <div className="space-y-4">
        {/* Master toggle */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-700 dark:text-gray-300">Sound Effects</span>
          <button
            onClick={onToggleSound}
            className={`relative w-12 h-6 rounded-full transition-colors ${
              settings.enabled ? 'bg-blue-500' : 'bg-gray-300 dark:bg-gray-600'
            }`}
          >
            <motion.div
              animate={{ x: settings.enabled ? 24 : 0 }}
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
              className="absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow"
            />
          </button>
        </div>

        {/* Volume slider */}
        {settings.enabled && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-2"
          >
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Volume</span>
              <span className="text-sm text-gray-500 dark:text-gray-400">
                {Math.round(settings.volume * 100)}%
              </span>
            </div>
            <input
              type="range"
              min="0"
              max="1"
              step="0.1"
              value={settings.volume}
              onChange={(e) => onVolumeChange(parseFloat(e.target.value))}
              className="w-full h-2 bg-gray-200 dark:bg-gray-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
            />
          </motion.div>
        )}

        {/* Keyboard sounds toggle */}
        {settings.enabled && onToggleKeyboardSounds && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-between"
          >
            <div className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <Keyboard className="w-4 h-4" />
              Keystroke Sounds
            </div>
            <button
              onClick={onToggleKeyboardSounds}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                settings.keyboardSounds ? 'bg-blue-500' : 'bg-gray-300 dark:bg-gray-600'
              }`}
            >
              <motion.div
                animate={{ x: settings.keyboardSounds ? 24 : 0 }}
                transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                className="absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow"
              />
            </button>
          </motion.div>
        )}
      </div>
    </div>
  );
}

export default SoundSettingsPanel;
