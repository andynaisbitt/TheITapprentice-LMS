// frontend/src/plugins/typing-game/components/FoxRunnerAnimation.tsx
/**
 * Fox Runner Animation - Visual progress indicator for typing games
 *
 * Shows a fox running across the screen as the user types,
 * jumping over a lazy dog when reaching the jump point.
 */

import React, { useMemo } from 'react';
import { motion } from 'framer-motion';

interface FoxRunnerAnimationProps {
  progress: number; // 0-100
  isPlaying: boolean;
  className?: string;
}

export const FoxRunnerAnimation: React.FC<FoxRunnerAnimationProps> = ({
  progress,
  isPlaying,
  className = '',
}) => {
  // Dog position is at 70% of the track
  const DOG_POSITION = 70;
  const JUMP_START = 60;
  const JUMP_END = 80;

  // Calculate if fox is jumping
  const isJumping = progress >= JUMP_START && progress <= JUMP_END;
  const jumpProgress = isJumping
    ? (progress - JUMP_START) / (JUMP_END - JUMP_START)
    : 0;

  // Calculate jump arc (parabola)
  const jumpHeight = isJumping
    ? Math.sin(jumpProgress * Math.PI) * 30
    : 0;

  // Fox running animation frames
  const foxFrame = useMemo(() => {
    if (!isPlaying) return 0;
    return Math.floor((progress * 4) % 4);
  }, [progress, isPlaying]);

  return (
    <div className={`relative w-full h-16 overflow-hidden ${className}`}>
      {/* Ground/grass line */}
      <div className="absolute bottom-2 left-0 right-0 h-1 bg-gradient-to-r from-green-400 via-green-500 to-green-400 rounded-full opacity-60" />

      {/* Grass tufts */}
      <div className="absolute bottom-2 left-0 right-0 flex justify-between px-4">
        {[...Array(12)].map((_, i) => (
          <div
            key={i}
            className="w-1 h-2 bg-green-500 rounded-t-full opacity-40"
            style={{ transform: `rotate(${(i % 2 === 0 ? -1 : 1) * 10}deg)` }}
          />
        ))}
      </div>

      {/* Lazy Dog - sitting at 70% position */}
      <motion.div
        className="absolute bottom-3"
        style={{ left: `${DOG_POSITION}%`, transform: 'translateX(-50%)' }}
        animate={{
          y: isJumping ? [0, -2, 0] : 0,
        }}
        transition={{ duration: 0.3 }}
      >
        <div className="relative">
          {/* Dog body */}
          <div className="w-10 h-6 bg-amber-600 rounded-lg relative">
            {/* Dog head */}
            <div className="absolute -left-3 -top-1 w-5 h-5 bg-amber-700 rounded-full">
              {/* Ear */}
              <div className="absolute -top-1 left-0 w-2 h-3 bg-amber-800 rounded-full transform -rotate-12" />
              {/* Eye */}
              <div className="absolute top-1.5 left-2.5 w-1 h-1 bg-black rounded-full">
                {/* Closed eye when fox jumps over */}
                {isJumping && (
                  <div className="absolute inset-0 bg-amber-700 rounded-full" />
                )}
              </div>
              {/* Snout */}
              <div className="absolute bottom-0 left-1 w-3 h-2 bg-amber-600 rounded-b-lg" />
            </div>
            {/* Tail */}
            <motion.div
              className="absolute -right-2 top-0 w-3 h-2 bg-amber-700 rounded-full origin-left"
              animate={{ rotate: isJumping ? [0, 20, 0] : [-5, 5, -5] }}
              transition={{ duration: 0.5, repeat: Infinity }}
            />
            {/* Legs (tucked - lazy dog) */}
            <div className="absolute bottom-0 left-1 w-2 h-2 bg-amber-700 rounded-b" />
            <div className="absolute bottom-0 right-1 w-2 h-2 bg-amber-700 rounded-b" />
          </div>
          {/* "Zzz" when not jumping */}
          {!isJumping && progress < JUMP_START && (
            <motion.div
              className="absolute -top-4 -right-2 text-xs text-gray-400 font-bold"
              animate={{ opacity: [0.3, 1, 0.3], y: [0, -2, 0] }}
              transition={{ duration: 1.5, repeat: Infinity }}
            >
              z<span className="text-[10px]">z</span><span className="text-[8px]">z</span>
            </motion.div>
          )}
          {/* Exclamation when fox is near */}
          {progress >= JUMP_START - 10 && progress < JUMP_START && (
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className="absolute -top-5 left-1/2 -translate-x-1/2 text-yellow-500 font-bold text-sm"
            >
              !
            </motion.div>
          )}
        </div>
      </motion.div>

      {/* Quick Brown Fox */}
      <motion.div
        className="absolute bottom-3"
        style={{
          left: `${Math.min(progress, 95)}%`,
          transform: 'translateX(-50%)',
        }}
        animate={{
          y: -jumpHeight,
          rotate: isJumping ? [0, -10, 0, 10, 0] : 0,
        }}
        transition={{
          y: { duration: 0.1 },
          rotate: { duration: 0.2 },
        }}
      >
        <div className="relative">
          {/* Fox body */}
          <motion.div
            className="w-8 h-5 bg-orange-500 rounded-lg relative"
            animate={{
              scaleX: isPlaying ? [1, 1.1, 1] : 1,
            }}
            transition={{ duration: 0.15, repeat: isPlaying ? Infinity : 0 }}
          >
            {/* Fox head */}
            <div className="absolute -right-2 -top-1 w-4 h-4 bg-orange-600 rounded-full">
              {/* Ears */}
              <div className="absolute -top-2 left-0 w-1.5 h-2.5 bg-orange-700 rounded-t-full transform -rotate-12" />
              <div className="absolute -top-2 right-0 w-1.5 h-2.5 bg-orange-700 rounded-t-full transform rotate-12" />
              {/* Eye */}
              <div className="absolute top-1 right-1 w-1.5 h-1.5 bg-black rounded-full">
                <div className="absolute top-0 right-0 w-0.5 h-0.5 bg-white rounded-full" />
              </div>
              {/* Snout */}
              <div className="absolute bottom-0 right-0 w-2 h-1.5 bg-white rounded-r-lg" />
              {/* Nose */}
              <div className="absolute bottom-0.5 right-0 w-1 h-1 bg-black rounded-full" />
            </div>
            {/* White chest */}
            <div className="absolute bottom-0 right-1 w-3 h-2 bg-white rounded-t-lg opacity-80" />
            {/* Tail */}
            <motion.div
              className="absolute -left-3 top-0 w-4 h-3 bg-orange-600 rounded-full origin-right"
              animate={{
                rotate: isPlaying ? [-20, 20, -20] : 0,
              }}
              transition={{ duration: 0.2, repeat: isPlaying ? Infinity : 0 }}
            >
              {/* White tail tip */}
              <div className="absolute left-0 top-0.5 w-1.5 h-2 bg-white rounded-full" />
            </motion.div>
            {/* Legs - animated when running */}
            <motion.div
              className="absolute bottom-0 left-1 w-1.5 h-3 bg-orange-700 rounded-b origin-top"
              animate={{
                rotate: isPlaying && !isJumping ? [-30, 30, -30] : (isJumping ? -45 : 0),
              }}
              transition={{ duration: 0.1, repeat: isPlaying && !isJumping ? Infinity : 0 }}
            />
            <motion.div
              className="absolute bottom-0 left-3 w-1.5 h-3 bg-orange-700 rounded-b origin-top"
              animate={{
                rotate: isPlaying && !isJumping ? [30, -30, 30] : (isJumping ? -30 : 0),
              }}
              transition={{ duration: 0.1, repeat: isPlaying && !isJumping ? Infinity : 0 }}
            />
            <motion.div
              className="absolute bottom-0 right-2 w-1.5 h-3 bg-orange-700 rounded-b origin-top"
              animate={{
                rotate: isPlaying && !isJumping ? [-20, 20, -20] : (isJumping ? 30 : 0),
              }}
              transition={{ duration: 0.1, repeat: isPlaying && !isJumping ? Infinity : 0 }}
            />
            <motion.div
              className="absolute bottom-0 right-0.5 w-1.5 h-3 bg-orange-700 rounded-b origin-top"
              animate={{
                rotate: isPlaying && !isJumping ? [20, -20, 20] : (isJumping ? 45 : 0),
              }}
              transition={{ duration: 0.1, repeat: isPlaying && !isJumping ? Infinity : 0 }}
            />
          </motion.div>

          {/* Speed lines when running fast */}
          {isPlaying && progress > 10 && !isJumping && (
            <div className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-full">
              {[...Array(3)].map((_, i) => (
                <motion.div
                  key={i}
                  className="h-0.5 bg-orange-300 rounded-full mb-1"
                  style={{ width: `${8 - i * 2}px`, marginLeft: `${i * 3}px` }}
                  animate={{ opacity: [0.3, 0.7, 0.3] }}
                  transition={{ duration: 0.2, delay: i * 0.05, repeat: Infinity }}
                />
              ))}
            </div>
          )}

          {/* Jump effect - stars/sparkles */}
          {isJumping && (
            <>
              <motion.div
                className="absolute -top-2 left-1/2 text-yellow-400 text-xs"
                initial={{ opacity: 0, scale: 0 }}
                animate={{ opacity: 1, scale: 1, y: -5 }}
                transition={{ duration: 0.2 }}
              >
                ✨
              </motion.div>
            </>
          )}
        </div>
      </motion.div>

      {/* Finish flag at 95% */}
      {progress >= 90 && (
        <motion.div
          className="absolute bottom-3 right-2"
          initial={{ opacity: 0, scale: 0 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="w-1 h-8 bg-gray-600 rounded-t">
            <motion.div
              className="absolute top-0 left-1 w-4 h-3 bg-gradient-to-br from-white via-black to-white bg-[length:4px_4px]"
              style={{
                backgroundImage: 'repeating-conic-gradient(#000 0% 25%, #fff 0% 50%)',
                backgroundSize: '4px 4px',
              }}
              animate={{ x: [0, 2, 0] }}
              transition={{ duration: 0.5, repeat: Infinity }}
            />
          </div>
        </motion.div>
      )}

      {/* Progress percentage */}
      <div className="absolute top-0 right-2 text-xs text-gray-400 font-mono">
        {Math.round(progress)}%
      </div>
    </div>
  );
};

export default FoxRunnerAnimation;
