// src/components/course-builder/CoursePreview.tsx
/**
 * Course Preview - Live preview of course content
 * Shows how students will see the course
 */

import React, { useState } from 'react';
import { Course, CourseModule, ModuleSection, ContentBlock } from '../../types';
import { X, ChevronLeft, ChevronRight, BookOpen, Clock } from 'lucide-react';

interface CoursePreviewProps {
  course: Course;
  modules: CourseModule[];
  onClose: () => void;
}

export const CoursePreview: React.FC<CoursePreviewProps> = ({
  course,
  modules,
  onClose
}) => {
  const [selectedModule, setSelectedModule] = useState<CourseModule | null>(
    modules.length > 0 ? modules[0] : null
  );
  const [selectedSection, setSelectedSection] = useState<ModuleSection | null>(
    modules.length > 0 && modules[0].sections && modules[0].sections.length > 0 
      ? modules[0].sections[0] 
      : null
  );

  const handleModuleChange = (module: CourseModule) => {
    setSelectedModule(module);
    if (module.sections && module.sections.length > 0) {
      setSelectedSection(module.sections[0]);
    } else {
      setSelectedSection(null);
    }
  };

  const handleNextSection = () => {
    if (!selectedModule || !selectedSection) return;
    
    const currentIndex = selectedModule.sections?.findIndex(s => s.id === selectedSection.id) ?? -1;
    if (currentIndex >= 0 && selectedModule.sections && currentIndex < selectedModule.sections.length - 1) {
      setSelectedSection(selectedModule.sections[currentIndex + 1]);
    } else {
      // Move to next module
      const moduleIndex = modules.findIndex(m => m.id === selectedModule.id);
      if (moduleIndex < modules.length - 1) {
        const nextModule = modules[moduleIndex + 1];
        setSelectedModule(nextModule);
        if (nextModule.sections && nextModule.sections.length > 0) {
          setSelectedSection(nextModule.sections[0]);
        }
      }
    }
  };

  const handlePrevSection = () => {
    if (!selectedModule || !selectedSection) return;
    
    const currentIndex = selectedModule.sections?.findIndex(s => s.id === selectedSection.id) ?? -1;
    if (currentIndex > 0 && selectedModule.sections) {
      setSelectedSection(selectedModule.sections[currentIndex - 1]);
    } else {
      // Move to previous module
      const moduleIndex = modules.findIndex(m => m.id === selectedModule.id);
      if (moduleIndex > 0) {
        const prevModule = modules[moduleIndex - 1];
        setSelectedModule(prevModule);
        if (prevModule.sections && prevModule.sections.length > 0) {
          setSelectedSection(prevModule.sections[prevModule.sections.length - 1]);
        }
      }
    }
  };

  const renderBlock = (block: ContentBlock) => {
    switch (block.type) {
      case 'text':
        const textContent = block.content as any;
        return (
          <div className="prose dark:prose-invert max-w-none">
            {textContent.format === 'markdown' ? (
              <div dangerouslySetInnerHTML={{ __html: renderMarkdown(textContent.text) }} />
            ) : (
              <p className="whitespace-pre-wrap">{textContent.text}</p>
            )}
          </div>
        );
      
      case 'heading':
        const headingContent = block.content as any;
        const HeadingTag = `h${headingContent.level}` as keyof JSX.IntrinsicElements;
        return (
          <HeadingTag className="font-bold text-gray-900 dark:text-white my-4">
            {headingContent.text}
          </HeadingTag>
        );
      
      case 'video':
        const videoContent = block.content as any;
        return (
          <div className="my-4">
            <div className="aspect-video bg-gray-200 dark:bg-gray-700 rounded-lg flex items-center justify-center">
              <div className="text-center">
                <div className="text-4xl mb-2">🎥</div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Video: {videoContent.url}
                </p>
              </div>
            </div>
            {videoContent.caption && (
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-2 text-center">
                {videoContent.caption}
              </p>
            )}
          </div>
        );
      
      case 'code':
        const codeContent = block.content as any;
        return (
          <div className="my-4">
            {codeContent.filename && (
              <div className="bg-gray-200 dark:bg-gray-700 px-4 py-2 rounded-t-lg text-sm font-mono">
                {codeContent.filename}
              </div>
            )}
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-b-lg overflow-x-auto">
              <code className={`language-${codeContent.language}`}>
                {codeContent.code}
              </code>
            </pre>
          </div>
        );
      
      case 'image':
        const imageContent = block.content as any;
        return (
          <div className="my-4">
            <img 
              src={imageContent.url} 
              alt={imageContent.alt} 
              className="max-w-full h-auto rounded-lg shadow-lg"
            />
            {imageContent.caption && (
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-2 text-center">
                {imageContent.caption}
              </p>
            )}
          </div>
        );
      
      case 'callout':
        const calloutContent = block.content as any;
        const calloutStyles: Record<string, string> = {
          info: 'bg-blue-50 dark:bg-blue-900/20 border-blue-500 text-blue-900 dark:text-blue-100',
          warning: 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-500 text-yellow-900 dark:text-yellow-100',
          success: 'bg-green-50 dark:bg-green-900/20 border-green-500 text-green-900 dark:text-green-100',
          error: 'bg-red-50 dark:bg-red-900/20 border-red-500 text-red-900 dark:text-red-100',
          tip: 'bg-purple-50 dark:bg-purple-900/20 border-purple-500 text-purple-900 dark:text-purple-100'
        };
        const calloutType = calloutContent.type || 'info';
        return (
          <div className={`my-4 p-4 border-l-4 rounded ${calloutStyles[calloutType] || calloutStyles.info}`}>
            {calloutContent.title && (
              <h4 className="font-semibold mb-2">{calloutContent.title}</h4>
            )}
            <p>{calloutContent.content}</p>
          </div>
        );
      
      case 'quiz':
        const quizContent = block.content as any;
        return (
          <div className="my-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <h4 className="font-semibold mb-3 flex items-center gap-2">
              ❓ Quiz ({quizContent.questions?.length || 0} questions)
            </h4>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Passing score: {quizContent.passing_score || 70}% • Max attempts: {quizContent.max_attempts || 3}
            </p>
          </div>
        );
      
      case 'divider':
        const dividerContent = block.content as any;
        const dividerStyles: Record<string, string> = {
          solid: 'border-solid',
          dashed: 'border-dashed',
          dotted: 'border-dotted'
        };
        const spacing: Record<string, string> = {
          small: 'my-2',
          medium: 'my-4',
          large: 'my-8'
        };
        const dividerStyle = dividerContent.style || 'solid';
        const dividerSpacing = dividerContent.spacing || 'medium';
        return (
          <hr className={`border-gray-300 dark:border-gray-600 ${dividerStyles[dividerStyle] || dividerStyles.solid} ${spacing[dividerSpacing] || spacing.medium}`} />
        );
      
      default:
        return (
          <div className="my-4 p-4 bg-gray-100 dark:bg-gray-800 rounded text-center text-gray-500 dark:text-gray-400">
            {block.type} block (preview not available)
          </div>
        );
    }
  };

  const renderMarkdown = (text: string) => {
    return text
      .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold mt-4 mb-2">$1</h3>')
      .replace(/^## (.*$)/gim, '<h2 class="text-xl font-semibold mt-4 mb-2">$1</h2>')
      .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold mt-4 mb-2">$1</h1>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code class="bg-gray-100 dark:bg-gray-800 px-1 py-0.5 rounded text-sm font-mono">$1</code>')
      .replace(/\n/g, '<br />');
  };

  return (
    <div className="fixed inset-0 bg-white dark:bg-gray-900 z-50 flex flex-col">
      {/* Header */}
      <div className="bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition"
            >
              <X className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                {course.title}
              </h1>
              <div className="flex items-center gap-4 text-sm text-gray-600 dark:text-gray-400 mt-1">
                <span className="flex items-center gap-1">
                  <BookOpen className="w-4 h-4" />
                  {modules.length} modules
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  {course.estimated_hours}h
                </span>
                <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded text-xs">
                  {course.level}
                </span>
              </div>
            </div>
          </div>
          <div className="text-sm text-gray-600 dark:text-gray-400 bg-yellow-100 dark:bg-yellow-900/30 px-3 py-1 rounded">
            📋 Preview Mode
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar - Module List */}
        <div className="w-80 bg-gray-50 dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 overflow-y-auto">
          <div className="p-4">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
              Course Content
            </h3>
            <div className="space-y-2">
              {modules.map((module, index) => (
                <div key={module.id} className="space-y-1">
                  <button
                    onClick={() => handleModuleChange(module)}
                    className={`w-full text-left p-3 rounded-lg transition ${
                      selectedModule?.id === module.id
                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                        : 'hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300'
                    }`}
                  >
                    <div className="font-medium">
                      {index + 1}. {module.title}
                    </div>
                    <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                      {module.sections?.length || 0} sections • {module.duration}
                    </div>
                  </button>
                  
                  {/* Show sections if module is selected */}
                  {selectedModule?.id === module.id && module.sections && (
                    <div className="ml-4 space-y-1">
                      {module.sections.map((section, sIndex) => (
                        <button
                          key={section.id}
                          onClick={() => setSelectedSection(section)}
                          className={`w-full text-left p-2 rounded text-sm transition ${
                            selectedSection?.id === section.id
                              ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'
                              : 'hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400'
                          }`}
                        >
                          {sIndex + 1}. {section.title}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="flex-1 overflow-y-auto">
          <div className="max-w-4xl mx-auto p-8">
            {selectedSection ? (
              <>
                {/* Section Header */}
                <div className="mb-8">
                  <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400 mb-2">
                    <span>{selectedModule?.title}</span>
                    <span>•</span>
                    <span>{selectedSection.time_estimate}</span>
                    <span>•</span>
                    <span>{selectedSection.points} points</span>
                  </div>
                  <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                    {selectedSection.title}
                  </h2>
                  {selectedSection.description && (
                    <p className="text-gray-600 dark:text-gray-400">
                      {selectedSection.description}
                    </p>
                  )}
                </div>

                {/* Section Content */}
                <div className="space-y-6">
                  {selectedSection.content_blocks.length === 0 ? (
                    <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                      No content blocks in this section
                    </div>
                  ) : (
                    selectedSection.content_blocks.map((block, index) => (
                      <div key={block.id || index}>
                        {renderBlock(block)}
                      </div>
                    ))
                  )}
                </div>

                {/* Navigation */}
                <div className="flex items-center justify-between mt-12 pt-8 border-t border-gray-200 dark:border-gray-700">
                  <button
                    onClick={handlePrevSection}
                    className="flex items-center gap-2 px-4 py-2 text-gray-600 dark:text-gray-400 
                             hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition"
                  >
                    <ChevronLeft className="w-5 h-5" />
                    Previous
                  </button>
                  <button
                    onClick={handleNextSection}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white 
                             rounded-lg hover:bg-blue-700 transition"
                  >
                    Next
                    <ChevronRight className="w-5 h-5" />
                  </button>
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <BookOpen className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600 dark:text-gray-400">
                  Select a section to preview
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CoursePreview;