// Frontend/src/components/Pages/blocks/CTABlock.tsx
import React from 'react';
import { motion } from 'framer-motion';

interface CTABlockProps {
  data: {
    title: string;
    description?: string;
    primaryButton?: {
      text: string;
      link: string;
    };
    secondaryButton?: {
      text: string;
      link: string;
    };
    gradientColor?: 'blue-purple' | 'blue' | 'green' | 'purple';
  };
}

const gradientColors = {
  'blue-purple': 'bg-gradient-to-r from-blue-600 to-purple-600',
  'blue': 'bg-blue-600 dark:bg-blue-700',
  'green': 'bg-green-600 dark:bg-green-700',
  'purple': 'bg-purple-600 dark:bg-purple-700',
};

export const CTABlock: React.FC<CTABlockProps> = ({ data }) => {
  const { title, description, primaryButton, secondaryButton, gradientColor = 'blue' } = data;

  return (
    <motion.section
      initial={{ opacity: 0, scale: 0.95 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      className={`py-20 ${gradientColors[gradientColor]} rounded-2xl mx-4 md:mx-8`}
    >
      <div className="container mx-auto px-4 text-center">
        <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
          {title}
        </h2>

        {description && (
          <p className="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
            {description}
          </p>
        )}

        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
          {primaryButton && (
            <motion.a
              href={primaryButton.link}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="inline-block bg-white text-blue-600 font-semibold px-8 py-3 rounded-lg hover:bg-gray-100 transition-colors"
            >
              {primaryButton.text}
            </motion.a>
          )}

          {secondaryButton && (
            <motion.a
              href={secondaryButton.link}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="inline-block bg-transparent border-2 border-white text-white font-semibold px-8 py-3 rounded-lg hover:bg-white hover:text-blue-600 transition-colors"
            >
              {secondaryButton.text}
            </motion.a>
          )}
        </div>
      </div>
    </motion.section>
  );
};
