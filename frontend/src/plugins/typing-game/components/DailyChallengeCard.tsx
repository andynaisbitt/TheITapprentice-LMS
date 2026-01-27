// frontend/src/plugins/typing-game/components/DailyChallengeCard.tsx
import { motion } from 'framer-motion';
import { Trophy, Zap, Target, Keyboard, Award, CheckCircle, Gift, Loader2 } from 'lucide-react';

interface Challenge {
  challenge_id: string;
  challenge_type: string;
  name: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard';
  target_value: number;
  current_value: number;
  progress_percent: number;
  is_completed: boolean;
  is_claimed: boolean;
  xp_reward: number;
}

interface DailyChallengeCardProps {
  challenge: Challenge;
  onClaim: (challengeId: string) => void;
  claiming?: boolean;
}

const CHALLENGE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  games_completed: Keyboard,
  wpm_achieved: Zap,
  accuracy_achieved: Target,
  words_typed: Award,
  combo_achieved: Trophy,
};

const DIFFICULTY_COLORS = {
  easy: {
    bg: 'from-green-50 to-emerald-50 dark:from-green-900/20 dark:to-emerald-900/20',
    border: 'border-green-200 dark:border-green-800',
    badge: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    progress: 'bg-green-500',
  },
  medium: {
    bg: 'from-yellow-50 to-amber-50 dark:from-yellow-900/20 dark:to-amber-900/20',
    border: 'border-yellow-200 dark:border-yellow-800',
    badge: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    progress: 'bg-yellow-500',
  },
  hard: {
    bg: 'from-red-50 to-orange-50 dark:from-red-900/20 dark:to-orange-900/20',
    border: 'border-red-200 dark:border-red-800',
    badge: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    progress: 'bg-red-500',
  },
};

export function DailyChallengeCard({ challenge, onClaim, claiming }: DailyChallengeCardProps) {
  const Icon = CHALLENGE_ICONS[challenge.challenge_type] || Trophy;
  const colors = DIFFICULTY_COLORS[challenge.difficulty];

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`relative bg-gradient-to-br ${colors.bg} rounded-xl p-3 sm:p-4 border ${colors.border} overflow-hidden`}
    >
      {/* Completed overlay */}
      {challenge.is_claimed && (
        <div className="absolute inset-0 bg-white/60 dark:bg-gray-900/60 backdrop-blur-sm flex items-center justify-center z-10">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="flex flex-col items-center gap-1.5 sm:gap-2"
          >
            <CheckCircle className="w-10 h-10 sm:w-12 sm:h-12 text-green-500" />
            <span className="font-medium text-sm sm:text-base text-green-600 dark:text-green-400">Claimed!</span>
          </motion.div>
        </div>
      )}

      <div className="flex items-start justify-between mb-2 sm:mb-3">
        <div className="flex items-center gap-2 sm:gap-3">
          <div className={`p-1.5 sm:p-2 rounded-lg ${colors.badge}`}>
            <Icon className="w-4 h-4 sm:w-5 sm:h-5" />
          </div>
          <div>
            <h4 className="font-semibold text-sm sm:text-base text-gray-900 dark:text-white line-clamp-1">{challenge.name}</h4>
            <span className={`text-[10px] sm:text-xs px-1.5 sm:px-2 py-0.5 rounded-full ${colors.badge} capitalize`}>
              {challenge.difficulty}
            </span>
          </div>
        </div>
        <div className="text-right flex-shrink-0">
          <div className="flex items-center gap-0.5 sm:gap-1 text-amber-600 dark:text-amber-400 font-bold text-xs sm:text-sm">
            <Gift className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            {challenge.xp_reward}
          </div>
        </div>
      </div>

      <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mb-2 sm:mb-3 line-clamp-2">
        {challenge.description}
      </p>

      {/* Progress bar */}
      <div className="mb-2 sm:mb-3">
        <div className="flex justify-between text-[10px] sm:text-xs text-gray-600 dark:text-gray-400 mb-1">
          <span>{challenge.current_value} / {challenge.target_value}</span>
          <span>{Math.round(challenge.progress_percent)}%</span>
        </div>
        <div className="h-1.5 sm:h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${challenge.progress_percent}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            className={`h-full ${colors.progress} rounded-full`}
          />
        </div>
      </div>

      {/* Claim button */}
      {challenge.is_completed && !challenge.is_claimed && (
        <motion.button
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => onClaim(challenge.challenge_id)}
          disabled={claiming}
          className="w-full py-1.5 sm:py-2 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white font-semibold text-sm rounded-lg shadow-lg disabled:opacity-50 flex items-center justify-center gap-1.5 sm:gap-2 active:scale-95 transition-transform"
        >
          {claiming ? (
            <>
              <Loader2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 animate-spin" />
              <span className="text-xs sm:text-sm">Claiming...</span>
            </>
          ) : (
            <>
              <Gift className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
              <span className="text-xs sm:text-sm">Claim</span>
            </>
          )}
        </motion.button>
      )}
    </motion.div>
  );
}

export default DailyChallengeCard;
