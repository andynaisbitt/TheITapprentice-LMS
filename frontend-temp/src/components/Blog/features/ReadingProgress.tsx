import React, { useState, useEffect } from 'react';
import { Clock, CheckCircle } from 'lucide-react';

interface ReadingProgressProps {
  contentId: string;
  totalReadTime?: number; // in minutes
  onProgressUpdate?: (progress: number) => void;
  onComplete?: () => void;
  variant?: 'bar' | 'circle' | 'minimal';
  position?: 'top' | 'bottom' | 'floating';
  showTimeRemaining?: boolean;
}

const ReadingProgress: React.FC<ReadingProgressProps> = ({
  contentId,
  totalReadTime = 5,
  onProgressUpdate,
  onComplete,
  variant = 'bar',
  position = 'top',
  showTimeRemaining = true
}) => {
  const [progress, setProgress] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const [timeElapsed, setTimeElapsed] = useState(0);

  useEffect(() => {
    let interval: NodeJS.Timeout;

    const handleScroll = () => {
      const windowHeight = window.innerHeight;
      const documentHeight = document.documentElement.scrollHeight - windowHeight;
      const scrollTop = window.pageYOffset;
      
      if (documentHeight > 0) {
        const scrollProgress = Math.min((scrollTop / documentHeight) * 100, 100);
        setProgress(scrollProgress);
        onProgressUpdate?.(scrollProgress);

        if (scrollProgress >= 90 && !isComplete) {
          setIsComplete(true);
          onComplete?.();
        }
      }
    };

    // Time-based progress tracking
    interval = setInterval(() => {
      setTimeElapsed(prev => {
        const newTime = prev + 1;
        const timeProgress = Math.min((newTime / (totalReadTime * 60)) * 100, 100);
        
        if (timeProgress >= 100 && !isComplete) {
          setIsComplete(true);
          onComplete?.();
        }
        
        return newTime;
      });
    }, 1000);

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll(); // Initial calculation

    return () => {
      window.removeEventListener('scroll', handleScroll);
      if (interval) clearInterval(interval);
    };
  }, [contentId, totalReadTime, isComplete, onProgressUpdate, onComplete]);

  const timeRemaining = Math.max(0, (totalReadTime * 60) - timeElapsed);
  const minutesRemaining = Math.floor(timeRemaining / 60);
  const secondsRemaining = timeRemaining % 60;

  if (variant === 'circle') {
    const circumference = 2 * Math.PI * 16; // radius of 16
    const strokeDashoffset = circumference - (progress / 100) * circumference;

    return (
      <div className={`fixed z-50 ${
        position === 'top' ? 'top-4 right-4' : 
        position === 'bottom' ? 'bottom-4 right-4' : 
        'top-1/2 right-4 -translate-y-1/2'
      }`}>
        <div className="bg-background/90 backdrop-blur-sm rounded-full p-3 shadow-lg border border-border">
          <div className="relative">
            <svg className="w-8 h-8 transform -rotate-90" viewBox="0 0 36 36">
              <path
                d="M18,2.0845 a 15.9155,15.9155 0 0,1 0,31.831 a 15.9155,15.9155 0 0,1 0,-31.831"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeOpacity="0.1"
                className="text-muted-foreground"
              />
              <path
                d="M18,2.0845 a 15.9155,15.9155 0 0,1 0,31.831 a 15.9155,15.9155 0 0,1 0,-31.831"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                className={isComplete ? "text-green-500" : "text-primary"}
                style={{
                  transition: 'stroke-dashoffset 0.3s ease-in-out'
                }}
              />
            </svg>
            {isComplete && (
              <CheckCircle className="absolute inset-0 w-8 h-8 text-green-500" />
            )}
          </div>
          {showTimeRemaining && !isComplete && (
            <div className="text-xs text-center mt-1 text-muted-foreground">
              {minutesRemaining}:{secondsRemaining.toString().padStart(2, '0')}
            </div>
          )}
        </div>
      </div>
    );
  }

  if (variant === 'minimal') {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Clock className="w-4 h-4" />
        <span>{Math.round(progress)}% complete</span>
        {showTimeRemaining && !isComplete && (
          <span>• {minutesRemaining}:{secondsRemaining.toString().padStart(2, '0')} left</span>
        )}
        {isComplete && <CheckCircle className="w-4 h-4 text-green-500" />}
      </div>
    );
  }

  return (
    <div className={`fixed z-50 left-0 right-0 ${
      position === 'top' ? 'top-0' : 'bottom-0'
    }`}>
      <div className="bg-background/90 backdrop-blur-sm border-b border-border p-2">
        <div className="max-w-4xl mx-auto flex items-center gap-4">
          <div className="flex-1">
            <div className="w-full bg-secondary rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all duration-300 ${
                  isComplete ? 'bg-green-500' : 'bg-primary'
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
          
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <span>{Math.round(progress)}%</span>
            {showTimeRemaining && !isComplete && (
              <div className="flex items-center gap-1">
                <Clock className="w-4 h-4" />
                <span>{minutesRemaining}:{secondsRemaining.toString().padStart(2, '0')}</span>
              </div>
            )}
            {isComplete && (
              <div className="flex items-center gap-1 text-green-500">
                <CheckCircle className="w-4 h-4" />
                <span>Complete</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReadingProgress;