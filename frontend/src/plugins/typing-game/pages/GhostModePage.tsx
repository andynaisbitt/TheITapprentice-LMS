// frontend/src/plugins/typing-game/pages/GhostModePage.tsx
/**
 * Ghost Mode game page wrapper
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { GhostModeGame } from '../components';
import type { TypingGameResultsResponse } from '../types';

export const GhostModePage: React.FC = () => {
  const navigate = useNavigate();
  const [gameCompleted, setGameCompleted] = useState(false);

  const handleComplete = (results: TypingGameResultsResponse) => {
    console.log('Ghost Mode completed:', results);
    setGameCompleted(true);
  };

  const handleExit = () => {
    navigate('/typing-practice', { state: { gameCompleted } });
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-4 sm:py-8">
      <GhostModeGame
        onComplete={handleComplete}
        onExit={handleExit}
      />
    </div>
  );
};

export default GhostModePage;
