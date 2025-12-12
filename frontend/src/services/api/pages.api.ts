// Frontend/src/services/api/pages.api.ts
import apiClient from './client';

export interface ContentBlock {
  type: string;
  data: Record<string, any>;
}

export interface Page {
  id: number;
  slug: string;
  title: string;
  meta_title?: string;
  meta_description?: string;
  meta_keywords?: string;
  canonical_url?: string;
  blocks: ContentBlock[];
  published: boolean;
  created_at: string;
  updated_at?: string;
  created_by?: number;
}

export interface PageCreate {
  slug: string;
  title: string;
  meta_title?: string;
  meta_description?: string;
  meta_keywords?: string;
  canonical_url?: string;
  blocks: ContentBlock[];
  published: boolean;
}

export interface PageUpdate {
  slug?: string;
  title?: string;
  meta_title?: string;
  meta_description?: string;
  meta_keywords?: string;
  canonical_url?: string;
  blocks?: ContentBlock[];
  published?: boolean;
}

export interface PageListResponse {
  pages: Page[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export const pagesApi = {
  // Public endpoints
  getBySlug: async (slug: string): Promise<Page> => {
    const response = await apiClient.get(`/api/v1/pages/${slug}`);
    return response.data;
  },

  list: async (skip = 0, limit = 20): Promise<PageListResponse> => {
    const response = await apiClient.get('/api/v1/pages', {
      params: { skip, limit }
    });
    return response.data;
  },

  // Admin endpoints
  admin: {
    create: async (page: PageCreate): Promise<Page> => {
      const response = await apiClient.post('/api/v1/admin/pages', page);
      return response.data;
    },

    list: async (skip = 0, limit = 20, published_only = false): Promise<PageListResponse> => {
      const response = await apiClient.get('/api/v1/admin/pages', {
        params: { skip, limit, published_only }
      });
      return response.data;
    },

    getById: async (id: number): Promise<Page> => {
      const response = await apiClient.get(`/api/v1/admin/pages/${id}`);
      return response.data;
    },

    update: async (id: number, page: PageUpdate): Promise<Page> => {
      const response = await apiClient.put(`/api/v1/admin/pages/${id}`, page);
      return response.data;
    },

    delete: async (id: number): Promise<void> => {
      await apiClient.delete(`/api/v1/admin/pages/${id}`);
    }
  }
};
