// Frontend/src/components/Pages/blocks/TechStackBlock.tsx
import React from 'react';
import { motion } from 'framer-motion';

interface TechItem {
  icon: string;
  name: string;
  description?: string;
}

interface TechStack {
  title: string;
  icon: string;
  color: 'blue' | 'green' | 'purple' | 'orange';
  items: TechItem[];
}

interface TechStackBlockProps {
  data: {
    title?: string;
    titleIcon?: string;
    stacks: TechStack[];
  };
}

const colorClasses = {
  blue: {
    bg: 'from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20',
    border: 'border-blue-200 dark:border-blue-700',
    title: 'text-blue-900 dark:text-blue-300',
    dot: 'bg-blue-500',
  },
  green: {
    bg: 'from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20',
    border: 'border-green-200 dark:border-green-700',
    title: 'text-green-900 dark:text-green-300',
    dot: 'bg-green-500',
  },
  purple: {
    bg: 'from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20',
    border: 'border-purple-200 dark:border-purple-700',
    title: 'text-purple-900 dark:text-purple-300',
    dot: 'bg-purple-500',
  },
  orange: {
    bg: 'from-orange-50 to-orange-100 dark:from-orange-900/20 dark:to-orange-800/20',
    border: 'border-orange-200 dark:border-orange-700',
    title: 'text-orange-900 dark:text-orange-300',
    dot: 'bg-orange-500',
  },
};

export const TechStackBlock: React.FC<TechStackBlockProps> = ({ data }) => {
  const { title, titleIcon, stacks } = data;

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

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {stacks.map((stack, index) => {
            const colors = colorClasses[stack.color];
            return (
              <motion.div
                key={index}
                whileHover={{ scale: 1.02 }}
                className={`bg-gradient-to-br ${colors.bg} p-8 rounded-xl border-2 ${colors.border}`}
              >
                <h3 className={`text-2xl font-bold ${colors.title} mb-6 flex items-center gap-3`}>
                  <span className="text-3xl">{stack.icon}</span>
                  {stack.title}
                </h3>
                <div className="space-y-3">
                  {stack.items.map((item, idx) => (
                    <div key={idx} className="flex items-center gap-3 text-gray-700 dark:text-gray-300">
                      <span className={`w-2 h-2 ${colors.dot} rounded-full`}></span>
                      <span>
                        <span className="font-semibold">{item.name}</span>
                        {item.description && ` ${item.description}`}
                      </span>
                    </div>
                  ))}
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </motion.section>
  );
};
