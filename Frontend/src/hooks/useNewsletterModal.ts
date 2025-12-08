// src/hooks/useNewsletterModal.ts
/**
 * Hook to manage newsletter modal state globally
 * Simple event-based approach without external dependencies
 */

import { useEffect, useState } from 'react';

// Custom event for opening newsletter modal
export const NEWSLETTER_MODAL_OPEN_EVENT = 'newsletter-modal-open';

export const openNewsletterModal = () => {
  window.dispatchEvent(new Event(NEWSLETTER_MODAL_OPEN_EVENT));
};

export const useNewsletterModal = () => {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const handleOpen = () => setIsOpen(true);
    window.addEventListener(NEWSLETTER_MODAL_OPEN_EVENT, handleOpen);
    return () => window.removeEventListener(NEWSLETTER_MODAL_OPEN_EVENT, handleOpen);
  }, []);

  const closeModal = () => setIsOpen(false);

  return {
    isOpen,
    openModal: openNewsletterModal,
    closeModal,
  };
};

export default useNewsletterModal;
