// frontend/src/plugins/typing-game/pages/InfiniteRushPage.tsx
/**
 * Infinite Rush game page wrapper
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
      <InfiniteRushGame
        onComplete={handleComplete}
        onExit={handleExit}
      />
    </div>
  );
};

export default InfiniteRushPage;
