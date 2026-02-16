// frontend/src/plugins/typing-game/pages/InfiniteRushPage.tsx
/**
 * Infinite Rush game page wrapper
 */

import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { InfiniteRushGame } from '../components';
import type { TypingGameResultsResponse } from '../types';

export const InfiniteRushPage: React.FC = () => {
  const navigate = useNavigate();
  const [gameCompleted, setGameCompleted] = useState(false);

  const handleComplete = (results: TypingGameResultsResponse) => {
    console.log('Infinite Rush completed:', results);
    setGameCompleted(true);
  };

  const handleExit = () => {
    navigate('/typing-practice', { state: { gameCompleted } });
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-4 sm:py-8">
      <div className="container mx-auto px-4 mb-3">
        <Link
          to="/typing-practice"
          className="inline-flex items-center gap-1.5 text-sm sm:text-base text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span className="hidden sm:inline">Back to Typing Practice</span>
          <span className="sm:hidden">Main Menu</span>
        </Link>
      </div>
      <InfiniteRushGame
        onComplete={handleComplete}
        onExit={handleExit}
      />
    </div>
  );
};

export default InfiniteRushPage;
