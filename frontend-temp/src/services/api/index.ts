// src/services/api/index.ts
/**
 * Central export for all API modules - FastReactCMS
 */

// Export client and utilities
export { default as apiClient } from './client';
export { setCSRFToken, getCSRFToken, clearCSRFToken } from './client';

// Export all types
export type * from './types';

// Export API modules
export { authApi, userApi } from './auth.api';
export { blogApi } from './blog.api';
export { adminBlogApi } from './admin-blog.api';
export { adminCategoryApi } from './admin-category.api';
export { adminTagApi } from './admin-tag.api';
export type { Category, CategoryCreate, CategoryUpdate } from './admin-category.api';