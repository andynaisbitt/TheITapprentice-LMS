import React from 'react';
import { TrendingUp, Hash } from 'lucide-react';

interface TrendingTopic {
  tag: string;
  count: number;
  trend: 'up' | 'stable' | 'down';
  percentage?: number;
}

interface TrendingTopicsProps {
  topics?: TrendingTopic[];
  maxTopics?: number;
  timeFrame?: '24h' | '7d' | '30d';
  onTopicClick?: (topic: string) => void;
}

const TrendingTopics: React.FC<TrendingTopicsProps> = ({
  topics = [],
  maxTopics = 8,
  timeFrame = '7d',
  onTopicClick
}) => {
  // Mock data if no topics provided
  const mockTrendingTopics: TrendingTopic[] = [
    { tag: 'Python', count: 24, trend: 'up', percentage: 12 },
    { tag: 'Networking', count: 18, trend: 'up', percentage: 8 },
    { tag: 'PowerShell', count: 15, trend: 'stable' },
    { tag: 'WordPress', count: 12, trend: 'down', percentage: -3 },
    { tag: 'IT Tools', count: 11, trend: 'up', percentage: 15 },
    { tag: 'Troubleshooting', count: 9, trend: 'stable' },
    { tag: 'Automation', count: 8, trend: 'up', percentage: 22 },
    { tag: 'Security', count: 7, trend: 'up', percentage: 5 }
  ];

  const displayTopics = topics.length > 0 ? topics : mockTrendingTopics;
  const topTopics = displayTopics.slice(0, maxTopics);

  const getTrendColor = (trend: string) => {
    switch (trend) {
      case 'up': return 'text-green-500';
      case 'down': return 'text-red-500';
      default: return 'text-muted-foreground';
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return '↗';
      case 'down': return '↘';
      default: return '→';
    }
  };

  return (
    <section className="bg-card rounded-lg p-6 border border-border">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-foreground">Trending Topics</h3>
        </div>
        <span className="text-sm text-muted-foreground">Last {timeFrame}</span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {topTopics.map((topic) => (
          <button
            key={topic.tag}
            onClick={() => onTopicClick?.(topic.tag)}
            className="group flex items-center justify-between p-3 rounded-lg border border-border hover:border-primary/50 hover:bg-accent transition-all text-left"
          >
            <div className="flex items-center gap-2 min-w-0">
              <Hash className="w-3 h-3 text-muted-foreground flex-shrink-0" />
              <span className="font-medium text-foreground truncate">{topic.tag}</span>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className="text-sm text-muted-foreground">{topic.count}</span>
              <span className={`text-sm ${getTrendColor(topic.trend)}`}>
                {getTrendIcon(topic.trend)}
                {topic.percentage && Math.abs(topic.percentage)}
                {topic.percentage && '%'}
              </span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
};

export default TrendingTopics;