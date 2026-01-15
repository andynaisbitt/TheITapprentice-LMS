// frontend/src/plugins/typing-game/pages/TypingGamePlayPage.tsx
/**
 * Quick Brown Fox game play page
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { QuickBrownFoxGame } from '../components/QuickBrownFoxGame';

export const TypingGamePlayPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        {/* Back button */}
        <Link
          to="/games/typing"
          className="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Typing Games
        </Link>

        {/* Game component */}
        <QuickBrownFoxGame />
      </div>
    </div>
  );
};

export default TypingGamePlayPage;
