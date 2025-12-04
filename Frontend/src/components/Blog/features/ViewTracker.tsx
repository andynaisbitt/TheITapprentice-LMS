import React, { useEffect, useRef } from 'react';

interface ViewTrackerProps {
  postId: string;
  onView?: (postId: string, duration: number) => void;
  onProgress?: (postId: string, progress: number) => void;
  threshold?: number; // Percentage of viewport that must be visible
  minViewTime?: number; // Minimum time in seconds before counting as a view
}

const ViewTracker: React.FC<ViewTrackerProps> = ({
  postId,
  onView,
  onProgress,
  threshold = 0.5,
  minViewTime = 3
}) => {
  const elementRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef<number | null>(null);
  const totalViewTimeRef = useRef<number>(0);
  const isViewingRef = useRef<boolean>(false);
  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const calculateScrollProgress = () => {
    const element = elementRef.current;
    if (!element) return 0;

    const rect = element.getBoundingClientRect();
    const elementHeight = rect.height;
    const windowHeight = window.innerHeight;
    
    // How much of the element is above the viewport
    const scrolledPastTop = Math.max(0, -rect.top);
    
    // How much of the element can be scrolled through
    const scrollableHeight = elementHeight - windowHeight;
    
    if (scrollableHeight <= 0) {
      // Element is smaller than viewport, consider it 100% when fully visible
      return rect.top <= 0 && rect.bottom >= windowHeight ? 100 : 0;
    }
    
    // Calculate percentage scrolled through the element
    const progress = Math.min(100, Math.max(0, (scrolledPastTop / scrollableHeight) * 100));
    return progress;
  };

  useEffect(() => {
    const element = elementRef.current;
    if (!element) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        
        if (entry.isIntersecting && entry.intersectionRatio >= threshold) {
          // Started viewing
          if (!isViewingRef.current) {
            isViewingRef.current = true;
            startTimeRef.current = Date.now();
            
            // Start progress tracking
            progressIntervalRef.current = setInterval(() => {
              if (isViewingRef.current && startTimeRef.current) {
                const currentViewTime = (Date.now() - startTimeRef.current) / 1000;
                totalViewTimeRef.current += 1; // Add 1 second
                
                // Calculate progress based on scroll position
                const scrollProgress = calculateScrollProgress();
                if (onProgress) {
                  onProgress(postId, scrollProgress);
                }
              }
            }, 1000);
          }
        } else {
          // Stopped viewing
          if (isViewingRef.current) {
            isViewingRef.current = false;
            
            if (startTimeRef.current) {
              const viewDuration = (Date.now() - startTimeRef.current) / 1000;
              totalViewTimeRef.current += viewDuration;
              
              // Only count as a view if they viewed for minimum time
              if (viewDuration >= minViewTime && onView) {
                onView(postId, totalViewTimeRef.current);
              }
              
              startTimeRef.current = null;
            }
            
            // Stop progress tracking
            if (progressIntervalRef.current) {
              clearInterval(progressIntervalRef.current);
              progressIntervalRef.current = null;
            }
          }
        }
      },
      {
        threshold: [0, threshold, 1.0]
      }
    );

    observer.observe(element);

    // Cleanup function
    return () => {
      observer.disconnect();
      
      // Final view tracking if still viewing
      if (isViewingRef.current && startTimeRef.current) {
        const finalViewDuration = (Date.now() - startTimeRef.current) / 1000;
        totalViewTimeRef.current += finalViewDuration;
        
        if (finalViewDuration >= minViewTime && onView) {
          onView(postId, totalViewTimeRef.current);
        }
      }
      
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, [postId, onView, onProgress, threshold, minViewTime]);

  // This component renders an invisible tracker
  return (
    <div 
      ref={elementRef} 
      className="absolute inset-0 pointer-events-none"
      aria-hidden="true"
      data-view-tracker={postId}
    />
  );
};

// Hook version for easier integration
export const useViewTracker = (
  postId: string,
  options?: {
    threshold?: number;
    minViewTime?: number;
    onView?: (postId: string, duration: number) => void;
    onProgress?: (postId: string, progress: number) => void;
  }
) => {
  const elementRef = useRef<HTMLElement | null>(null);
  const startTimeRef = useRef<number | null>(null);
  const totalViewTimeRef = useRef<number>(0);
  const isViewingRef = useRef<boolean>(false);
  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const { threshold = 0.5, minViewTime = 3, onView, onProgress } = options || {};

  const calculateScrollProgress = (element: HTMLElement) => {
    const rect = element.getBoundingClientRect();
    const elementHeight = rect.height;
    const windowHeight = window.innerHeight;
    
    const scrolledPastTop = Math.max(0, -rect.top);
    const scrollableHeight = elementHeight - windowHeight;
    
    if (scrollableHeight <= 0) {
      return rect.top <= 0 && rect.bottom >= windowHeight ? 100 : 0;
    }
    
    const progress = Math.min(100, Math.max(0, (scrolledPastTop / scrollableHeight) * 100));
    return progress;
  };

  useEffect(() => {
    const element = elementRef.current;
    if (!element) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        
        if (entry.isIntersecting && entry.intersectionRatio >= threshold) {
          if (!isViewingRef.current) {
            isViewingRef.current = true;
            startTimeRef.current = Date.now();
            
            progressIntervalRef.current = setInterval(() => {
              if (isViewingRef.current && startTimeRef.current) {
                const currentViewTime = (Date.now() - startTimeRef.current) / 1000;
                totalViewTimeRef.current += 1;
                
                const scrollProgress = calculateScrollProgress(element);
                if (onProgress) {
                  onProgress(postId, scrollProgress);
                }
              }
            }, 1000);
          }
        } else {
          if (isViewingRef.current) {
            isViewingRef.current = false;
            
            if (startTimeRef.current) {
              const viewDuration = (Date.now() - startTimeRef.current) / 1000;
              totalViewTimeRef.current += viewDuration;
              
              if (viewDuration >= minViewTime && onView) {
                onView(postId, totalViewTimeRef.current);
              }
              
              startTimeRef.current = null;
            }
            
            if (progressIntervalRef.current) {
              clearInterval(progressIntervalRef.current);
              progressIntervalRef.current = null;
            }
          }
        }
      },
      { threshold: [0, threshold, 1.0] }
    );

    if (element) {
      observer.observe(element);
    }

    return () => {
      observer.disconnect();
      
      if (isViewingRef.current && startTimeRef.current) {
        const finalViewDuration = (Date.now() - startTimeRef.current) / 1000;
        totalViewTimeRef.current += finalViewDuration;
        
        if (finalViewDuration >= minViewTime && onView) {
          onView(postId, totalViewTimeRef.current);
        }
      }
      
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, [postId, threshold, minViewTime, onView, onProgress]);

  return elementRef;
};

export default ViewTracker;