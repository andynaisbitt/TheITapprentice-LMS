// Frontend/src/components/Pages/blocks/FeatureGridBlock.tsx
import React from 'react';
import { motion } from 'framer-motion';

interface Feature {
  icon: string;
  title: string;
  description: string;
}

interface FeatureGridBlockProps {
  data: {
    title?: string;
    titleIcon?: string;
    features: Feature[];
    columns?: 1 | 2 | 3 | 4;
  };
}

export const FeatureGridBlock: React.FC<FeatureGridBlockProps> = ({ data }) => {
  const { title, titleIcon, features, columns = 3 } = data;

  const gridColsClasses = {
    1: 'grid-cols-1',
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  };

  return (
    <motion.section
      initial={{ opacity: 0 }}
      whileInView={{ opacity: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      className="py-16 bg-white dark:bg-gray-800"
    >
      <div className="container mx-auto px-4">
        {title && (
          <h2 className="text-3xl font-black text-gray-900 dark:text-white mb-8 flex items-center gap-3">
            {titleIcon && <span className="text-4xl">{titleIcon}</span>}
            {title}
          </h2>
        )}

        <div className={`grid ${gridColsClasses[columns]} gap-6`}>
          {features.map((feature, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: idx * 0.1, duration: 0.5 }}
              whileHover={{ scale: 1.05, transition: { duration: 0.2 } }}
              className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-700 dark:to-gray-800 p-6 rounded-xl border-2 border-transparent hover:border-blue-500 dark:hover:border-blue-400 transition-all cursor-default"
            >
              <div className="text-4xl mb-3">{feature.icon}</div>
              <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-2">
                {feature.title}
              </h3>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                {feature.description}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.section>
  );
};
