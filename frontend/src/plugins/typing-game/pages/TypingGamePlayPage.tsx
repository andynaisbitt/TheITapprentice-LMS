// frontend/src/plugins/typing-game/pages/TypingGamePlayPage.tsx
/**
 * Quick Brown Fox game play page
 */

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { QuickBrownFoxGame } from '../components/QuickBrownFoxGame';

export const TypingGamePlayPage: React.FC = () => {
  const navigate = useNavigate();
  const [gameCompleted, setGameCompleted] = useState(false);

  const handleExit = () => {
    // Navigate with state indicating game was completed (for stats refresh)
    navigate('/games/typing', { state: { gameCompleted } });
  };

  const handleGameComplete = () => {
    setGameCompleted(true);
  };

  // Navigate back with state on link click
  const handleBackClick = (e: React.MouseEvent) => {
    e.preventDefault();
    navigate('/games/typing', { state: { gameCompleted } });
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-4 sm:py-6 md:py-8">
      <div className="max-w-4xl mx-auto px-2 sm:px-4">
        {/* Back button - visible when game is in idle state */}
        <Link
          to="/games/typing"
          onClick={handleBackClick}
          className="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white mb-4 sm:mb-6 text-sm sm:text-base"
        >
          <ArrowLeft className="w-4 h-4" />
          <span className="hidden sm:inline">Back to Typing Games</span>
          <span className="sm:hidden">Back</span>
        </Link>

        {/* Game component */}
        <QuickBrownFoxGame
          onExit={handleExit}
          onComplete={handleGameComplete}
        />
      </div>
    </div>
  );
};

export default TypingGamePlayPage;
