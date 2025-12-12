import React from 'react';

interface BlogLayoutProps {
  children: React.ReactNode;
  sidebar?: React.ReactNode;
  sidebarPosition?: 'left' | 'right';
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full';
  spacing?: 'tight' | 'normal' | 'loose';
  className?: string;
}

const BlogLayout: React.FC<BlogLayoutProps> = ({
  children,
  sidebar,
  sidebarPosition = 'right',
  maxWidth = 'lg',
  spacing = 'normal',
  className = ''
}) => {
  const maxWidthClasses = {
    sm: 'max-w-2xl',
    md: 'max-w-4xl',
    lg: 'max-w-6xl',
    xl: 'max-w-7xl',
    '2xl': 'max-w-screen-2xl',
    full: 'max-w-full'
  };

  const spacingClasses = {
    tight: 'space-y-6',
    normal: 'space-y-10',
    loose: 'space-y-16'
  };

  const containerClass = `min-h-screen flex flex-col bg-background text-foreground transition-colors ${className}`;
  const wrapperClass = `${spacingClasses[spacing]} p-6 ${maxWidthClasses[maxWidth]} mx-auto w-full`;

  if (!sidebar) {
    return (
      <div className={containerClass}>
        <div className={wrapperClass}>
          {children}
        </div>
      </div>
    );
  }

  return (
    <div className={containerClass}>
      <div className={`${spacingClasses[spacing]} p-6 ${maxWidthClasses[maxWidth]} mx-auto w-full`}>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {sidebarPosition === 'left' && (
            <aside className="lg:col-span-4 space-y-6">
              {sidebar}
            </aside>
          )}
          
          <main className={
            sidebar 
              ? sidebarPosition === 'left' 
                ? 'lg:col-span-8' 
                : 'lg:col-span-8'
              : 'col-span-full'
          }>
            {children}
          </main>
          
          {sidebarPosition === 'right' && (
            <aside className="lg:col-span-4 space-y-6">
              {sidebar}
            </aside>
          )}
        </div>
      </div>
    </div>
  );
};

export default BlogLayout;