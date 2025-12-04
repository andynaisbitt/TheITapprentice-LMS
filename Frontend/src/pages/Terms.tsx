// src/pages/Terms.tsx
import React from 'react';

export const Terms: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-12">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">Terms of Service</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-8">Last updated: {new Date().toLocaleDateString()}</p>

          <div className="prose dark:prose-invert max-w-none">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">1. Acceptance of Terms</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              By accessing and using this website, you accept and agree to be bound by the terms and provision of this agreement.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">2. Use License</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              Permission is granted to temporarily access the materials on this website for personal, non-commercial use only.
              This is the grant of a license, not a transfer of title, and under this license you may not:
            </p>
            <ul className="list-disc pl-6 text-gray-700 dark:text-gray-300 mb-4">
              <li>Modify or copy the materials</li>
              <li>Use the materials for any commercial purpose</li>
              <li>Remove any copyright or proprietary notations</li>
              <li>Transfer the materials to another person</li>
            </ul>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">3. User Content</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              You retain ownership of any content you post on this website. By posting content, you grant us a worldwide,
              non-exclusive, royalty-free license to use, reproduce, and display your content.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">4. Prohibited Uses</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              You may not use this website:
            </p>
            <ul className="list-disc pl-6 text-gray-700 dark:text-gray-300 mb-4">
              <li>In any way that violates any applicable law or regulation</li>
              <li>To transmit spam, chain letters, or other unsolicited communications</li>
              <li>To impersonate or attempt to impersonate another user</li>
              <li>To engage in any automated use of the system</li>
              <li>To interfere with the proper working of the website</li>
            </ul>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">5. Disclaimer</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              The materials on this website are provided on an 'as is' basis. We make no warranties, expressed or implied,
              and hereby disclaim all other warranties including, without limitation, implied warranties of merchantability,
              fitness for a particular purpose, or non-infringement.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">6. Limitations</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              In no event shall we or our suppliers be liable for any damages (including, without limitation, damages for loss of data
              or profit, or due to business interruption) arising out of the use or inability to use the materials on this website.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">7. Revisions</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              We may revise these terms of service at any time without notice. By using this website you are agreeing to be bound
              by the then current version of these terms of service.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">8. Governing Law</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              These terms and conditions are governed by and construed in accordance with the laws and you irrevocably submit to the
              exclusive jurisdiction of the courts in that location.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Terms;
