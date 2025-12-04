// src/pages/Privacy.tsx
import React from 'react';

export const Privacy: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-12">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">Privacy Policy</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-8">Last updated: {new Date().toLocaleDateString()}</p>

          <div className="prose dark:prose-invert max-w-none">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">1. Information We Collect</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              We collect information that you provide directly to us, including when you create an account, post content, or contact us.
              This may include your name, email address, and any content you create.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">2. How We Use Your Information</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              We use the information we collect to:
            </p>
            <ul className="list-disc pl-6 text-gray-700 dark:text-gray-300 mb-4">
              <li>Provide, maintain, and improve our services</li>
              <li>Send you technical notices and support messages</li>
              <li>Respond to your comments and questions</li>
              <li>Protect against fraudulent or illegal activity</li>
            </ul>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">3. Cookies and Analytics</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              We use cookies and similar technologies to provide functionality and analyze how our service is used.
              We may use Google Analytics to understand user behavior. You can opt out of Google Analytics by installing the
              Google Analytics opt-out browser add-on.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">4. Data Security</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              We take reasonable measures to protect your information from unauthorized access, use, or disclosure.
              However, no internet transmission is ever fully secure, and we cannot guarantee absolute security.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">5. Your Rights (GDPR)</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              If you are in the European Economic Area, you have certain rights including:
            </p>
            <ul className="list-disc pl-6 text-gray-700 dark:text-gray-300 mb-4">
              <li>Right to access your personal data</li>
              <li>Right to correct inaccurate data</li>
              <li>Right to delete your data</li>
              <li>Right to export your data</li>
              <li>Right to object to processing</li>
            </ul>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">6. Children's Privacy</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              Our service is not directed to children under 13. We do not knowingly collect personal information from children under 13.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">7. Changes to This Policy</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              We may update this privacy policy from time to time. We will notify you of any changes by posting the new policy on this page
              and updating the "Last updated" date.
            </p>

            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mt-8 mb-4">8. Contact Us</h2>
            <p className="text-gray-700 dark:text-gray-300 mb-4">
              If you have questions about this Privacy Policy, please contact us at:{' '}
              <a href="/contact" className="text-blue-600 dark:text-blue-400 hover:underline">Contact Page</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Privacy;
