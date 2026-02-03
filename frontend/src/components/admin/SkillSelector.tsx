// src/components/admin/SkillSelector.tsx
/**
 * Reusable Skill Selector Component
 * For assigning skills to quizzes, courses, tutorials, etc.
 */

import { useState, useEffect } from 'react';
import { Swords, X, Plus, Loader2 } from 'lucide-react';
import { apiClient } from '../../services/api/client';

interface Skill {
  id: number;
  name: string;
  slug: string;
  icon: string;
  category: 'technical' | 'soft';
}

interface SkillSelectorProps {
  selectedSlugs: string[];
  onChange: (slugs: string[]) => void;
  label?: string;
  helpText?: string;
  maxSkills?: number;
}

export const SkillSelector: React.FC<SkillSelectorProps> = ({
  selectedSlugs,
  onChange,
  label = 'Related Skills',
  helpText = 'Skills that will receive XP when this content is completed',
  maxSkills = 5,
}) => {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [loading, setLoading] = useState(true);
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    loadSkills();
  }, []);

  const loadSkills = async () => {
    try {
      const response = await apiClient.get('/api/v1/skills/');
      setSkills(response.data);
    } catch (error) {
      console.error('Failed to load skills:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = (slug: string) => {
    if (!selectedSlugs.includes(slug) && selectedSlugs.length < maxSkills) {
      onChange([...selectedSlugs, slug]);
    }
    setIsOpen(false);
  };

  const handleRemove = (slug: string) => {
    onChange(selectedSlugs.filter((s) => s !== slug));
  };

  const getSkillBySlug = (slug: string): Skill | undefined => {
    return skills.find((s) => s.slug === slug);
  };

  const availableSkills = skills.filter((s) => !selectedSlugs.includes(s.slug));

  const getCategoryColor = (category: string) => {
    return category === 'technical'
      ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
      : 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400';
  };

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-gray-500">
        <Loader2 className="w-4 h-4 animate-spin" />
        Loading skills...
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
        <span className="flex items-center gap-2">
          <Swords className="w-4 h-4" />
          {label}
        </span>
      </label>

      {helpText && (
        <p className="text-xs text-gray-500 dark:text-gray-400">{helpText}</p>
      )}

      {/* Selected Skills */}
      <div className="flex flex-wrap gap-2">
        {selectedSlugs.map((slug) => {
          const skill = getSkillBySlug(slug);

          // Show unrecognised slugs with a warning style so admins can remove them
          if (!skill) {
            return (
              <span
                key={slug}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
                title="This skill slug does not match any active skill"
              >
                {slug}
                <button
                  type="button"
                  onClick={() => handleRemove(slug)}
                  className="ml-1 hover:bg-black/10 dark:hover:bg-white/10 rounded-full p-0.5"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            );
          }

          return (
            <span
              key={slug}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium ${getCategoryColor(skill.category)}`}
            >
              <span>{skill.icon}</span>
              {skill.name}
              <button
                type="button"
                onClick={() => handleRemove(slug)}
                className="ml-1 hover:bg-black/10 dark:hover:bg-white/10 rounded-full p-0.5"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          );
        })}

        {/* Add Button */}
        {selectedSlugs.length < maxSkills && (
          <div className="relative">
            <button
              type="button"
              onClick={() => setIsOpen(!isOpen)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            >
              <Plus className="w-4 h-4" />
              Add Skill
            </button>

            {/* Dropdown */}
            {isOpen && (
              <>
                <div
                  className="fixed inset-0 z-10"
                  onClick={() => setIsOpen(false)}
                />
                <div className="absolute left-0 top-full mt-1 z-20 w-64 max-h-64 overflow-y-auto bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
                  {availableSkills.length > 0 ? (
                    <>
                      {/* Technical Skills */}
                      {availableSkills.filter((s) => s.category === 'technical').length > 0 && (
                        <div>
                          <div className="px-3 py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase bg-gray-50 dark:bg-gray-700/50">
                            Technical Skills
                          </div>
                          {availableSkills
                            .filter((s) => s.category === 'technical')
                            .map((skill) => (
                              <button
                                key={skill.slug}
                                type="button"
                                onClick={() => handleAdd(skill.slug)}
                                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                              >
                                <span>{skill.icon}</span>
                                <span className="text-gray-900 dark:text-white">{skill.name}</span>
                              </button>
                            ))}
                        </div>
                      )}

                      {/* Soft Skills */}
                      {availableSkills.filter((s) => s.category === 'soft').length > 0 && (
                        <div>
                          <div className="px-3 py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase bg-gray-50 dark:bg-gray-700/50">
                            Soft Skills
                          </div>
                          {availableSkills
                            .filter((s) => s.category === 'soft')
                            .map((skill) => (
                              <button
                                key={skill.slug}
                                type="button"
                                onClick={() => handleAdd(skill.slug)}
                                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                              >
                                <span>{skill.icon}</span>
                                <span className="text-gray-900 dark:text-white">{skill.name}</span>
                              </button>
                            ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="px-3 py-4 text-sm text-gray-500 text-center">
                      All skills selected
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {selectedSlugs.length === 0 && (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          No skills selected - XP will be awarded to Problem Solving by default
        </p>
      )}

      {selectedSlugs.length >= maxSkills && (
        <p className="text-xs text-gray-500">
          Maximum {maxSkills} skills allowed
        </p>
      )}
    </div>
  );
};

export default SkillSelector;
