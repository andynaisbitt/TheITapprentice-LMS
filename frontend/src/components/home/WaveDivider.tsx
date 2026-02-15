// src/components/home/WaveDivider.tsx
/**
 * Wave Divider - SVG wave transitions between sections
 * Creates smooth visual flow between different background colors
 */

import React from 'react';

interface WaveDividerProps {
  /** Color of the wave (the section above) */
  fromColor?: string;
  /** Color below the wave (the section below) */
  toColor?: string;
  /** Flip the wave upside down */
  flip?: boolean;
  /** Wave style variant */
  variant?: 'smooth' | 'sharp' | 'layered';
  /** Custom className */
  className?: string;
}

const WaveDivider: React.FC<WaveDividerProps> = ({
  fromColor = 'fill-slate-900',
  flip = false,
  variant = 'smooth',
  className = '',
}) => {
  const transforms = flip ? 'rotate-180' : '';

  const waves = {
    smooth: (
      <svg
        viewBox="0 0 1440 120"
        preserveAspectRatio="none"
        className={`w-full h-16 sm:h-20 lg:h-24 ${fromColor} ${transforms} ${className}`}
      >
        <path
          d="M0,64 C288,120 576,0 864,64 C1152,128 1296,32 1440,64 L1440,120 L0,120 Z"
          className="opacity-100"
        />
      </svg>
    ),
    sharp: (
      <svg
        viewBox="0 0 1440 120"
        preserveAspectRatio="none"
        className={`w-full h-12 sm:h-16 lg:h-20 ${fromColor} ${transforms} ${className}`}
      >
        <path d="M0,0 L720,120 L1440,0 L1440,120 L0,120 Z" />
      </svg>
    ),
    layered: (
      <svg
        viewBox="0 0 1440 120"
        preserveAspectRatio="none"
        className={`w-full h-20 sm:h-24 lg:h-32 ${transforms} ${className}`}
      >
        <path
          d="M0,96 C320,32 480,96 720,64 C960,32 1120,96 1440,64 L1440,120 L0,120 Z"
          className={`${fromColor} opacity-30`}
        />
        <path
          d="M0,64 C240,96 480,32 720,64 C960,96 1200,32 1440,80 L1440,120 L0,120 Z"
          className={`${fromColor} opacity-60`}
        />
        <path
          d="M0,80 C360,48 540,96 720,80 C900,64 1080,112 1440,96 L1440,120 L0,120 Z"
          className={`${fromColor}`}
        />
      </svg>
    ),
  };

  return (
    <div className="relative w-full overflow-hidden leading-none -mb-1">
      {waves[variant]}
    </div>
  );
};

export default WaveDivider;
