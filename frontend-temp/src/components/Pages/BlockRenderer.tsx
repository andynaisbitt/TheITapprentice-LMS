// Frontend/src/components/Pages/BlockRenderer.tsx
import React from 'react';
import { ContentBlock } from '../../services/api/pages.api';
import { HeroBlock } from './blocks/HeroBlock';
import { TextBlock } from './blocks/TextBlock';
import { StatsBlock } from './blocks/StatsBlock';
import { CTABlock } from './blocks/CTABlock';
import { FeatureGridBlock } from './blocks/FeatureGridBlock';
import { TechStackBlock } from './blocks/TechStackBlock';

interface BlockRendererProps {
  blocks: ContentBlock[];
}

export const BlockRenderer: React.FC<BlockRendererProps> = ({ blocks }) => {
  const renderBlock = (block: ContentBlock, index: number) => {
    switch (block.type) {
      case 'hero':
        return <HeroBlock key={index} data={block.data as any} />;

      case 'text':
        return <TextBlock key={index} data={block.data as any} />;

      case 'stats':
        return <StatsBlock key={index} data={block.data as any} />;

      case 'cta':
        return <CTABlock key={index} data={block.data as any} />;

      case 'featureGrid':
        return <FeatureGridBlock key={index} data={block.data as any} />;

      case 'techStack':
        return <TechStackBlock key={index} data={block.data as any} />;

      // Add more block types as needed
      case 'image':
        return (
          <section key={index} className="py-12">
            <div className="container mx-auto px-4">
              <img
                src={block.data.url}
                alt={block.data.alt || ''}
                className="w-full max-w-4xl mx-auto rounded-lg shadow-lg"
              />
              {block.data.caption && (
                <p className="text-center text-gray-600 dark:text-gray-400 mt-4">
                  {block.data.caption}
                </p>
              )}
            </div>
          </section>
        );

      default:
        console.warn(`Unknown block type: ${block.type}`);
        return null;
    }
  };

  return (
    <div className="dynamic-page">
      {blocks.map((block, index) => renderBlock(block, index))}
    </div>
  );
};
