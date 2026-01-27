// frontend/src/plugins/typing-game/components/LetterAccuracyHeatmap.tsx
import { motion } from 'framer-motion';
import { useMemo } from 'react';

interface LetterStat {
  character: string;
  accuracy: number;
  attempts: number;
}

interface LetterAccuracyHeatmapProps {
  letterStats: LetterStat[];
  showAllKeys?: boolean;
}

// QWERTY keyboard layout
const KEYBOARD_ROWS = [
  ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
  ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'],
  ['z', 'x', 'c', 'v', 'b', 'n', 'm'],
];

function getAccuracyColor(accuracy: number | null): string {
  if (accuracy === null) return 'bg-gray-200 dark:bg-gray-700';
  if (accuracy >= 95) return 'bg-green-400 dark:bg-green-600';
  if (accuracy >= 85) return 'bg-green-300 dark:bg-green-700';
  if (accuracy >= 75) return 'bg-yellow-300 dark:bg-yellow-600';
  if (accuracy >= 60) return 'bg-orange-300 dark:bg-orange-600';
  return 'bg-red-400 dark:bg-red-600';
}

function getTextColor(accuracy: number | null): string {
  if (accuracy === null) return 'text-gray-500 dark:text-gray-400';
  if (accuracy >= 95) return 'text-green-900 dark:text-green-100';
  if (accuracy >= 85) return 'text-green-800 dark:text-green-100';
  if (accuracy >= 75) return 'text-yellow-900 dark:text-yellow-100';
  if (accuracy >= 60) return 'text-orange-900 dark:text-orange-100';
  return 'text-red-900 dark:text-red-100';
}

export function LetterAccuracyHeatmap({ letterStats, showAllKeys = true }: LetterAccuracyHeatmapProps) {
  const statsMap = useMemo(() => {
    const map = new Map<string, LetterStat>();
    letterStats.forEach(stat => {
      map.set(stat.character.toLowerCase(), stat);
    });
    return map;
  }, [letterStats]);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
        Keyboard Accuracy Heatmap
      </h3>

      {/* Legend */}
      <div className="flex items-center justify-center gap-4 mb-6">
        <div className="flex items-center gap-2 text-xs">
          <div className="w-4 h-4 rounded bg-red-400 dark:bg-red-600" />
          <span className="text-gray-600 dark:text-gray-400">&lt;60%</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className="w-4 h-4 rounded bg-orange-300 dark:bg-orange-600" />
          <span className="text-gray-600 dark:text-gray-400">60-75%</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className="w-4 h-4 rounded bg-yellow-300 dark:bg-yellow-600" />
          <span className="text-gray-600 dark:text-gray-400">75-85%</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className="w-4 h-4 rounded bg-green-300 dark:bg-green-700" />
          <span className="text-gray-600 dark:text-gray-400">85-95%</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className="w-4 h-4 rounded bg-green-400 dark:bg-green-600" />
          <span className="text-gray-600 dark:text-gray-400">&gt;95%</span>
        </div>
      </div>

      {/* Keyboard */}
      <div className="flex flex-col items-center gap-2">
        {KEYBOARD_ROWS.map((row, rowIndex) => (
          <div
            key={rowIndex}
            className="flex gap-1"
            style={{ marginLeft: rowIndex === 1 ? '20px' : rowIndex === 2 ? '40px' : '0' }}
          >
            {row.map((key, keyIndex) => {
              const stat = statsMap.get(key);
              const accuracy = stat?.accuracy ?? null;
              const attempts = stat?.attempts ?? 0;
              const hasData = stat !== undefined && attempts > 0;

              return (
                <motion.div
                  key={key}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: (rowIndex * 10 + keyIndex) * 0.02 }}
                  whileHover={{ scale: 1.1, zIndex: 10 }}
                  className={`
                    relative w-10 h-10 sm:w-12 sm:h-12 rounded-lg
                    flex items-center justify-center
                    font-semibold uppercase text-lg
                    cursor-pointer transition-shadow
                    hover:shadow-lg
                    ${showAllKeys || hasData ? getAccuracyColor(accuracy) : 'bg-gray-100 dark:bg-gray-800'}
                    ${showAllKeys || hasData ? getTextColor(accuracy) : 'text-gray-400 dark:text-gray-600'}
                  `}
                  title={hasData
                    ? `${key.toUpperCase()}: ${accuracy?.toFixed(1)}% accuracy (${attempts} attempts)`
                    : `${key.toUpperCase()}: No data`
                  }
                >
                  {key}
                  {hasData && accuracy !== null && accuracy < 75 && (
                    <motion.div
                      animate={{ scale: [1, 1.2, 1] }}
                      transition={{ duration: 1, repeat: Infinity }}
                      className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full"
                    />
                  )}
                </motion.div>
              );
            })}
          </div>
        ))}

        {/* Space bar */}
        <div className="mt-2">
          {(() => {
            const stat = statsMap.get(' ');
            const accuracy = stat?.accuracy ?? null;
            const hasData = stat !== undefined && stat.attempts > 0;

            return (
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                whileHover={{ scale: 1.02 }}
                className={`
                  w-48 h-10 rounded-lg
                  flex items-center justify-center
                  text-sm font-medium
                  ${showAllKeys || hasData ? getAccuracyColor(accuracy) : 'bg-gray-100 dark:bg-gray-800'}
                  ${showAllKeys || hasData ? getTextColor(accuracy) : 'text-gray-400 dark:text-gray-600'}
                `}
                title={hasData
                  ? `Space: ${accuracy?.toFixed(1)}% accuracy`
                  : 'Space: No data'
                }
              >
                space
              </motion.div>
            );
          })()}
        </div>
      </div>

      {/* Worst performers list */}
      {letterStats.length > 0 && (
        <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            Keys Needing Practice
          </h4>
          <div className="flex flex-wrap gap-2">
            {letterStats
              .filter(s => s.accuracy < 85 && s.attempts >= 10)
              .sort((a, b) => a.accuracy - b.accuracy)
              .slice(0, 5)
              .map(stat => (
                <div
                  key={stat.character}
                  className={`px-3 py-1.5 rounded-lg ${getAccuracyColor(stat.accuracy)} ${getTextColor(stat.accuracy)} text-sm font-medium`}
                >
                  {stat.character === ' ' ? 'space' : stat.character.toUpperCase()}: {stat.accuracy.toFixed(0)}%
                </div>
              ))}
            {letterStats.filter(s => s.accuracy < 85 && s.attempts >= 10).length === 0 && (
              <p className="text-sm text-green-600 dark:text-green-400">
                Great job! All your frequently used keys are above 85% accuracy.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default LetterAccuracyHeatmap;
