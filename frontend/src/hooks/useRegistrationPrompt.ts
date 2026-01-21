// src/hooks/useRegistrationPrompt.ts
/**
 * Hook for managing registration prompts across LMS features
 * Handles the logic of when to show prompts and what happens when user skips
 */

import { useState, useCallback } from 'react';
import { useAuth } from '../state/contexts/AuthContext';
import type { PromptContext } from '../components/auth/RegistrationPrompt';

interface UseRegistrationPromptOptions {
  /** The context determines the messaging shown */
  context: PromptContext;
  /** If true, prompt cannot be skipped (e.g., PvP) */
  required?: boolean;
  /** Callback when user skips the prompt */
  onSkip?: () => void;
  /** Callback when user decides to register/login */
  onRegister?: () => void;
}

interface UseRegistrationPromptReturn {
  /** Whether the prompt modal is open */
  isPromptOpen: boolean;
  /** Whether the user has dismissed the prompt (for this session) */
  hasSkipped: boolean;
  /** Whether the user is authenticated */
  isAuthenticated: boolean;
  /** Show the registration prompt */
  showPrompt: () => void;
  /** Close the prompt without skipping */
  closePrompt: () => void;
  /** Handle skip action */
  handleSkip: () => void;
  /** Check auth and show prompt if needed, returns true if action can proceed */
  checkAuthAndProceed: () => boolean;
  /** The context for the prompt */
  context: PromptContext;
  /** Whether prompt is required (cannot skip) */
  required: boolean;
}

/**
 * Hook to manage registration prompts for LMS features
 *
 * Usage:
 * ```tsx
 * const { isPromptOpen, checkAuthAndProceed, handleSkip, closePrompt, context, required } = useRegistrationPrompt({
 *   context: 'course',
 *   onSkip: () => startCourseWithoutAuth(),
 * });
 *
 * const handleStartCourse = () => {
 *   if (checkAuthAndProceed()) {
 *     // User is authenticated, proceed normally
 *     startCourseWithAuth();
 *   }
 *   // If not authenticated, prompt is now showing
 * };
 *
 * return (
 *   <>
 *     <button onClick={handleStartCourse}>Start Course</button>
 *     <RegistrationPrompt
 *       isOpen={isPromptOpen}
 *       onClose={closePrompt}
 *       onSkip={handleSkip}
 *       context={context}
 *       required={required}
 *     />
 *   </>
 * );
 * ```
 */
export const useRegistrationPrompt = ({
  context,
  required = false,
  onSkip,
  onRegister,
}: UseRegistrationPromptOptions): UseRegistrationPromptReturn => {
  const { isAuthenticated } = useAuth();
  const [isPromptOpen, setIsPromptOpen] = useState(false);
  const [hasSkipped, setHasSkipped] = useState(false);

  const showPrompt = useCallback(() => {
    setIsPromptOpen(true);
  }, []);

  const closePrompt = useCallback(() => {
    setIsPromptOpen(false);
    if (onRegister) {
      onRegister();
    }
  }, [onRegister]);

  const handleSkip = useCallback(() => {
    setHasSkipped(true);
    setIsPromptOpen(false);
    if (onSkip) {
      onSkip();
    }
  }, [onSkip]);

  /**
   * Check if user is authenticated and show prompt if not
   * Returns true if user can proceed (authenticated or has skipped)
   */
  const checkAuthAndProceed = useCallback((): boolean => {
    if (isAuthenticated) {
      return true;
    }

    // If required, always show prompt and block
    if (required) {
      setIsPromptOpen(true);
      return false;
    }

    // If user has already skipped this session, let them proceed
    if (hasSkipped) {
      return true;
    }

    // Show the prompt
    setIsPromptOpen(true);
    return false;
  }, [isAuthenticated, required, hasSkipped]);

  return {
    isPromptOpen,
    hasSkipped,
    isAuthenticated,
    showPrompt,
    closePrompt,
    handleSkip,
    checkAuthAndProceed,
    context,
    required,
  };
};

export default useRegistrationPrompt;
