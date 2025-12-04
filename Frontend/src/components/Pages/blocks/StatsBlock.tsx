// Frontend/src/components/Pages/blocks/StatsBlock.tsx
import React from 'react';
import { motion } from 'framer-motion';

interface Stat {
  label: string;
  value: string;
  suffix?: string;
}

interface StatsBlockProps {
  data: {
    stats: Stat[];
    title?: string;
  };
}

export const StatsBlock: React.FC<StatsBlockProps> = ({ data }) => {
  const { stats, title } = data;

  return (
    <motion.section
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      className="py-16 bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-900"
    >
      <div className="container mx-auto px-4">
        {title && (
          <h2 className="text-3xl font-bold text-center mb-12 text-gray-900 dark:text-white">
            {title}
          </h2>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {stats.map((stat, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
              className="text-center"
            >
              <div className="text-4xl md:text-5xl font-bold text-blue-600 dark:text-blue-400 mb-2">
                {stat.value}{stat.suffix}
              </div>
              <div className="text-gray-600 dark:text-gray-400 text-lg">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.section>
  );
};
