// Frontend/src/components/Pages/blocks/TextBlock.tsx
import React from 'react';
import { motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';

interface TextBlockProps {
  data: {
    content: string;
    alignment?: 'left' | 'center' | 'right';
    maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  };
}

const maxWidthClasses = {
  sm: 'max-w-2xl',
  md: 'max-w-4xl',
  lg: 'max-w-6xl',
  xl: 'max-w-7xl',
  full: 'max-w-full',
};

const alignmentClasses = {
  left: 'text-left',
  center: 'text-center',
  right: 'text-right',
};

export const TextBlock: React.FC<TextBlockProps> = ({ data }) => {
  const { content, alignment = 'left', maxWidth = 'lg' } = data;

  return (
    <motion.section
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      className="py-12"
    >
      <div className={`container mx-auto px-4 ${maxWidthClasses[maxWidth]} ${alignmentClasses[alignment]}`}>
        <div className="prose prose-lg dark:prose-invert max-w-none">
          <ReactMarkdown>{content}</ReactMarkdown>
        </div>
      </div>
    </motion.section>
  );
};
