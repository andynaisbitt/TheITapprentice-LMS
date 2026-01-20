// src/services/api/admin-stats.api.ts
/**
 * Admin Stats API endpoints
 * Provides dashboard statistics, activity data, and system status
 */

import { apiClient } from './client';

export interface DashboardStats {
  total_posts: number;
  total_categories: number;
  total_tags: number;
  total_views: number;
  draft_posts: number;
  total_users: number;
  active_users: number;
  new_users_this_month: number;
  total_tutorials: number;
  tutorials_published: number;
  total_courses: number;
  courses_published: number;
  total_enrollments: number;
  typing_games_played: number;
  total_xp_awarded: number;
}

export interface TrendData {
  label: string;
  value: number;
  change?: number;
  change_label?: string;
}

export interface ActivityItem {
  id: string;
  type: string;
  title: string;
  description: string;
  timestamp: string;
  user_name?: string;
}

export interface AttentionItem {
  id: string;
  type: string;
  title: string;
  count: number;
  description: string;
  link: string;
  priority: 'low' | 'medium' | 'high';
}

export interface SystemStatusItem {
  id: string;
  name: string;
  status: 'healthy' | 'warning' | 'error';
  message?: string;
}

export interface DashboardResponse {
  stats: DashboardStats;
  trends: TrendData[];
  recent_activities: ActivityItem[];
  attention_items: AttentionItem[];
  system_status: SystemStatusItem[];
  last_updated: string;
}

export interface LMSProgressStudent {
  id: number;
  username: string;
  email: string;
  total_xp: number;
  level: number;
  current_streak: number;
  tutorials_completed: number;
  courses_completed: number;
  games_played: number;
  achievements_unlocked: number;
  last_active?: string;
}

export interface LMSProgressResponse {
  students: LMSProgressStudent[];
  totals: {
    total_students: number;
    total_xp_earned: number;
    total_tutorials_completed: number;
    total_games_played: number;
    total_achievements_unlocked: number;
  };
}

export interface ContentStats {
  blog: {
    total_posts: number;
    published: number;
    drafts: number;
    total_views: number;
    categories: number;
  };
  pages: {
    total: number;
    published: number;
  };
  tutorials?: {
    total: number;
    published: number;
    categories: number;
    total_views: number;
  };
  courses?: {
    total: number;
    published: number;
    draft: number;
  };
}

export const adminStatsApi = {
  /**
   * Get comprehensive dashboard statistics
   * Includes stats, trends, recent activities, attention items, and system status
   */
  getDashboard: async (): Promise<DashboardResponse> => {
    const response = await apiClient.get<DashboardResponse>('/api/v1/admin/stats/dashboard');
    return response.data;
  },

  /**
   * Get LMS progress statistics across all students
   */
  getLMSProgress: async (): Promise<LMSProgressResponse> => {
    const response = await apiClient.get<LMSProgressResponse>('/api/v1/admin/stats/lms/progress');
    return response.data;
  },

  /**
   * Get content statistics (posts, pages, tutorials, courses)
   */
  getContentStats: async (): Promise<ContentStats> => {
    const response = await apiClient.get<ContentStats>('/api/v1/admin/stats/content');
    return response.data;
  },
};

export default adminStatsApi;
