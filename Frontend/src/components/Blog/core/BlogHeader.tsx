import React from 'react';
import { BookOpen, TrendingUp, Users, Clock } from 'lucide-react';

interface BlogStats {
  totalPosts: number;
  totalReads: number;
  activeReaders: number;
  avgReadTime: string;
}

interface BlogHeaderProps {
  title?: string;
  subtitle?: string;
  stats?: BlogStats;
  showStats?: boolean;
  backgroundImage?: string;
  variant?: 'default' | 'minimal' | 'hero';
  children?: React.ReactNode;
}

const BlogHeader: React.FC<BlogHeaderProps> = ({
  title = "Blog",
  subtitle = "Share your knowledge and insights with the world through engaging content.",
  stats,
  showStats = false,
  backgroundImage,
  variant = 'default',
  children
}) => {
  const mockStats: BlogStats = {
    totalPosts: 47,
    totalReads: 12500,
    activeReaders: 1200,
    avgReadTime: '8 min'
  };

  const displayStats = stats || mockStats;

  if (variant === 'minimal') {
    return (
      <div className="text-center py-8">
        <h1 className="text-2xl font-bold text-foreground mb-2">{title}</h1>
        {subtitle && (
          <p className="text-muted-foreground max-w-2xl mx-auto">{subtitle}</p>
        )}
        {children}
      </div>
    );
  }

  if (variant === 'hero') {
    return (
      <div 
        className="relative py-20 px-6 text-center overflow-hidden"
        style={backgroundImage ? {
          backgroundImage: `linear-gradient(rgba(0,0,0,0.5), rgba(0,0,0,0.5)), url(${backgroundImage})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center'
        } : undefined}
      >
        {!backgroundImage && (
          <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-background to-secondary/10" />
        )}
        
        <div className="relative z-10 max-w-4xl mx-auto">
          <h1 className="text-4xl sm:text-5xl font-bold text-foreground mb-6">
            {title}
          </h1>
          {subtitle && (
            <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto">
              {subtitle}
            </p>
          )}
          
          {showStats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-2xl mx-auto mb-8">
              <div className="text-center">
                <BookOpen className="w-8 h-8 text-primary mx-auto mb-2" />
                <div className="text-2xl font-bold text-foreground">{displayStats.totalPosts}</div>
                <div className="text-sm text-muted-foreground">Posts</div>
              </div>
              <div className="text-center">
                <TrendingUp className="w-8 h-8 text-primary mx-auto mb-2" />
                <div className="text-2xl font-bold text-foreground">{displayStats.totalReads.toLocaleString()}</div>
                <div className="text-sm text-muted-foreground">Total Reads</div>
              </div>
              <div className="text-center">
                <Users className="w-8 h-8 text-primary mx-auto mb-2" />
                <div className="text-2xl font-bold text-foreground">{displayStats.activeReaders.toLocaleString()}</div>
                <div className="text-sm text-muted-foreground">Active Readers</div>
              </div>
              <div className="text-center">
                <Clock className="w-8 h-8 text-primary mx-auto mb-2" />
                <div className="text-2xl font-bold text-foreground">{displayStats.avgReadTime}</div>
                <div className="text-sm text-muted-foreground">Avg Read</div>
              </div>
            </div>
          )}
          
          {children}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg p-8 shadow-sm border border-border hover:shadow-md transition-all text-center mb-10">
      <h1 className="text-3xl sm:text-4xl font-extrabold text-foreground mb-4">
        {title}
      </h1>
      {subtitle && (
        <p className="text-muted-foreground mb-6 max-w-3xl mx-auto">
          {subtitle}
        </p>
      )}
      
      {showStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-2xl mx-auto mb-6">
          <div className="text-center p-4 bg-accent rounded-lg">
            <BookOpen className="w-6 h-6 text-primary mx-auto mb-2" />
            <div className="text-xl font-bold text-foreground">{displayStats.totalPosts}</div>
            <div className="text-xs text-muted-foreground">Posts</div>
          </div>
          <div className="text-center p-4 bg-accent rounded-lg">
            <TrendingUp className="w-6 h-6 text-primary mx-auto mb-2" />
            <div className="text-xl font-bold text-foreground">{displayStats.totalReads.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Reads</div>
          </div>
          <div className="text-center p-4 bg-accent rounded-lg">
            <Users className="w-6 h-6 text-primary mx-auto mb-2" />
            <div className="text-xl font-bold text-foreground">{displayStats.activeReaders.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Readers</div>
          </div>
          <div className="text-center p-4 bg-accent rounded-lg">
            <Clock className="w-6 h-6 text-primary mx-auto mb-2" />
            <div className="text-xl font-bold text-foreground">{displayStats.avgReadTime}</div>
            <div className="text-xs text-muted-foreground">Avg Read</div>
          </div>
        </div>
      )}
      
      {children}
    </div>
  );
};

export default BlogHeader;