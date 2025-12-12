import React from 'react';

interface FadeInProps {
  children: React.ReactNode;
  delay?: number;
  duration?: number;
  className?: string;
}

export const FadeIn: React.FC<FadeInProps> = ({ 
  children, 
  delay = 0, 
  duration = 300, 
  className = '' 
}) => {
  const [isVisible, setIsVisible] = React.useState(false);

  React.useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), delay);
    return () => clearTimeout(timer);
  }, [delay]);

  return (
    <div
      className={`transition-opacity duration-${duration} ${
        isVisible ? 'opacity-100' : 'opacity-0'
      } ${className}`}
    >
      {children}
    </div>
  );
};

interface SlideInProps {
  children: React.ReactNode;
  direction?: 'left' | 'right' | 'up' | 'down';
  delay?: number;
  duration?: number;
  className?: string;
}

export const SlideIn: React.FC<SlideInProps> = ({
  children,
  direction = 'up',
  delay = 0,
  duration = 300,
  className = ''
}) => {
  const [isVisible, setIsVisible] = React.useState(false);

  React.useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), delay);
    return () => clearTimeout(timer);
  }, [delay]);

  const getTransformClasses = () => {
    const transforms = {
      left: isVisible ? 'translate-x-0' : '-translate-x-full',
      right: isVisible ? 'translate-x-0' : 'translate-x-full',
      up: isVisible ? 'translate-y-0' : 'translate-y-4',
      down: isVisible ? 'translate-y-0' : '-translate-y-4'
    };
    return transforms[direction];
  };

  return (
    <div
      className={`transition-all duration-${duration} transform ${getTransformClasses()} ${
        isVisible ? 'opacity-100' : 'opacity-0'
      } ${className}`}
    >
      {children}
    </div>
  );
};

interface StaggeredAnimationProps {
  children: React.ReactNode[];
  delay?: number;
  stagger?: number;
  className?: string;
}

export const StaggeredAnimation: React.FC<StaggeredAnimationProps> = ({
  children,
  delay = 0,
  stagger = 100,
  className = ''
}) => {
  return (
    <div className={className}>
      {children.map((child, index) => (
        <FadeIn key={index} delay={delay + index * stagger}>
          {child}
        </FadeIn>
      ))}
    </div>
  );
};

interface PulseProps {
  children: React.ReactNode;
  className?: string;
}

export const Pulse: React.FC<PulseProps> = ({ children, className = '' }) => {
  return (
    <div className={`animate-pulse ${className}`}>
      {children}
    </div>
  );
};

interface BounceProps {
  children: React.ReactNode;
  className?: string;
}

export const Bounce: React.FC<BounceProps> = ({ children, className = '' }) => {
  return (
    <div className={`animate-bounce ${className}`}>
      {children}
    </div>
  );
};

interface ScaleOnHoverProps {
  children: React.ReactNode;
  scale?: number;
  className?: string;
}

export const ScaleOnHover: React.FC<ScaleOnHoverProps> = ({ 
  children, 
  scale = 105, 
  className = '' 
}) => {
  return (
    <div className={`transition-transform duration-200 hover:scale-${scale} ${className}`}>
      {children}
    </div>
  );
};

const Animations = {
  FadeIn,
  SlideIn,
  StaggeredAnimation,
  Pulse,
  Bounce,
  ScaleOnHover
};

export default Animations;