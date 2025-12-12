// Frontend/src/components/Pages/blocks/HeroBlock.tsx
import React from 'react';
import { motion } from 'framer-motion';

interface HeroBlockProps {
  data: {
    title: string;
    subtitle?: string;
    backgroundImage?: string;
    ctaText?: string;
    ctaLink?: string;
    badge?: string;
    gradientText?: boolean;
    gradientBackground?: boolean;
  };
}

export const HeroBlock: React.FC<HeroBlockProps> = ({ data }) => {
  const { title, subtitle, backgroundImage, ctaText, ctaLink, badge, gradientText, gradientBackground } = data;

  const sectionClasses = gradientBackground
    ? "min-h-screen bg-gradient-to-br from-gray-50 via-blue-50 to-purple-50 dark:from-gray-900 dark:via-gray-900 dark:to-gray-900 py-12"
    : backgroundImage
    ? "relative min-h-[60vh] flex items-center justify-center overflow-hidden"
    : "min-h-[60vh] flex items-center justify-center";

  return (
    <motion.section
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.6 }}
      className={sectionClasses}
      style={{
        backgroundImage: backgroundImage ? `url(${backgroundImage})` : undefined,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
      }}
    >
      {/* Overlay if background image exists */}
      {backgroundImage && (
        <div className="absolute inset-0 bg-black/50" />
      )}

      <div className={`${backgroundImage ? 'relative z-10' : ''} container mx-auto px-4 text-center`}>
        {badge && (
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="inline-block mb-4"
          >
            <span className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white text-sm font-semibold rounded-full shadow-lg">
              {badge}
            </span>
          </motion.div>
        )}

        <motion.h1
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className={
            gradientText
              ? "text-6xl md:text-7xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 mb-6"
              : "text-5xl md:text-6xl lg:text-7xl font-bold text-white mb-6"
          }
        >
          {title}
        </motion.h1>

        {subtitle && (
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5, duration: 0.6 }}
            className={
              gradientBackground || gradientText
                ? "text-2xl md:text-3xl text-gray-700 dark:text-gray-300 font-light max-w-3xl mx-auto mb-8"
                : "text-xl md:text-2xl text-gray-200 mb-8 max-w-3xl mx-auto"
            }
          >
            {subtitle}
          </motion.p>
        )}

        {ctaText && ctaLink && (
          <motion.a
            href={ctaLink}
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.6 }}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="inline-block bg-blue-600 hover:bg-blue-700 text-white font-semibold px-8 py-3 rounded-lg transition-colors"
          >
            {ctaText}
          </motion.a>
        )}
      </div>
    </motion.section>
  );
};
