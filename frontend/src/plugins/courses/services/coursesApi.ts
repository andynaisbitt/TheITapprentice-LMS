// frontend/src/plugins/courses/services/coursesApi.ts
/**
 * Course API endpoints (Public & Admin)
 * Matches backend course routes
 * Adapted from ITAppBetaV1 for BlogCMS
 */

import { apiClient } from '../../../services/api/client';
import {
  CONTENT_BLOCK_TEMPLATES,
  type Course,
  type CourseModule,
  type ModuleSection,
  type CourseListResponse,
  type CourseFilters,
  type CreateCourseRequest,
  type UpdateCourseRequest,
  type CreateModuleRequest,
  type CreateSectionRequest,
  type UpdateSectionRequest,
  type EnrollmentRequest,
  type ProgressUpdateRequest,
  type BulkCourseCreate,
  type CourseEnrollment,
  type ContentBlockTemplate,
  type Certificate,
} from '../types';

// ============================================================================
// PUBLIC COURSE API
// ============================================================================

export const coursesApi = {
  /**
   * Get published courses (public)
   */
  getCourses: async (filters?: CourseFilters): Promise<CourseListResponse> => {
    const response = await apiClient.get<CourseListResponse>('/api/v1/courses', {
      params: filters,
    });
    return response.data;
  },

  /**
   * Get single course by ID (public)
   */
  getCourse: async (courseId: string): Promise<Course> => {
    const response = await apiClient.get<Course>(`/api/v1/courses/${courseId}`);
    return response.data;
  },

  /**
   * Enroll in a course (authenticated)
   */
  enrollInCourse: async (data: EnrollmentRequest): Promise<CourseEnrollment> => {
    const response = await apiClient.post<CourseEnrollment>('/api/v1/courses/enroll', data);
    return response.data;
  },

  /**
   * Get user's enrolled courses (authenticated)
   */
  getMyCourses: async (): Promise<Course[]> => {
    const response = await apiClient.get<Course[]>('/api/v1/courses/my-courses');
    return response.data;
  },

  /**
   * Update course progress (authenticated)
   */
  updateProgress: async (
    courseId: string,
    moduleId: string,
    data: ProgressUpdateRequest
  ): Promise<{
    message: string;
    progress: number;
    module_completed: boolean;
    completed_sections: string[];
    course_complete: boolean;
    completed: boolean;
    certificate?: {
      title: string;
      description: string;
      verification_code: string;
      skills_acquired: string[];
    };
    certificate_id?: number;
  }> => {
    const response = await apiClient.put(
      `/api/v1/courses/progress/${courseId}/module/${moduleId}`,
      data
    );
    return response.data;
  },

  /**
   * Repair course progress by recalculating from actual data (authenticated)
   */
  repairProgress: async (courseId: string): Promise<{
    message: string;
    repaired: boolean;
    old_progress: number;
    new_progress: number;
    is_complete: boolean;
    certificate_created: boolean;
    certificate?: {
      title: string;
      verification_code: string;
      issued_at: string;
    };
  }> => {
    const response = await apiClient.post(`/api/v1/courses/progress/${courseId}/repair`);
    return response.data;
  },

  /**
   * Get detailed progress for a course (authenticated)
   */
  getProgress: async (courseId: string): Promise<{
    course_id: string;
    overall_progress: number;
    is_complete: boolean;
    completed_modules: string[];
    current_module: string | null;
    total_time_spent: number;
    module_progress: Record<string, {
      completed: boolean;
      time_spent: number;
      completed_sections: string[];
      quiz_scores: Record<string, number>;
      last_position: string;
    }>;
    last_accessed: string;
  }> => {
    const response = await apiClient.get(`/api/v1/courses/progress/${courseId}`);
    return response.data;
  },

  // ============================================================================
  // CERTIFICATE API
  // ============================================================================

  /**
   * Get all certificates for the current user (authenticated)
   */
  getMyCertificates: async (): Promise<Certificate[]> => {
    const response = await apiClient.get<Certificate[]>('/api/v1/courses/certificates/me');
    return response.data;
  },

  /**
   * Get certificate for a specific course (authenticated)
   */
  getCourseCertificate: async (courseId: string): Promise<Certificate> => {
    const response = await apiClient.get<Certificate>(`/api/v1/courses/certificates/${courseId}`);
    return response.data;
  },

  /**
   * Verify a certificate by verification code (public)
   */
  verifyCertificate: async (code: string): Promise<{
    valid: boolean;
    certificate: Certificate;
  }> => {
    const response = await apiClient.get(`/api/v1/courses/certificates/verify/${code}`);
    return response.data;
  },
};

// ============================================================================
// ADMIN COURSE API
// ============================================================================

export const adminCoursesApi = {
  /**
   * Get all courses including drafts (admin)
   */
  getAllCourses: async (filters?: CourseFilters): Promise<CourseListResponse> => {
    const response = await apiClient.get<CourseListResponse>('/api/v1/courses/admin/courses', {
      params: filters,
    });
    return response.data;
  },

  /**
   * Get single course with full details (admin)
   */
  getCourse: async (courseId: string): Promise<Course> => {
    const response = await apiClient.get<Course>(`/api/v1/courses/admin/courses/${courseId}`);
    return response.data;
  },

  /**
   * Create new course (admin)
   */
  createCourse: async (data: CreateCourseRequest): Promise<Course> => {
    const response = await apiClient.post<Course>('/api/v1/courses/admin/courses', data);
    return response.data;
  },

  /**
   * Update course (admin)
   */
  updateCourse: async (courseId: string, data: UpdateCourseRequest): Promise<Course> => {
    const response = await apiClient.put<Course>(`/api/v1/courses/admin/courses/${courseId}`, data);
    return response.data;
  },

  /**
   * Delete course (admin)
   */
  deleteCourse: async (courseId: string): Promise<{ success: boolean; message: string }> => {
    const response = await apiClient.delete(`/api/v1/courses/admin/courses/${courseId}`);
    return response.data;
  },

  /**
   * Publish/unpublish course (admin)
   */
  togglePublish: async (
    courseId: string,
    published: boolean
  ): Promise<{ success: boolean; message: string }> => {
    const response = await apiClient.post(`/api/v1/courses/admin/courses/${courseId}/publish`, { published });
    return response.data;
  },

  /**
   * Bulk save course with all modules and sections (admin)
   * Saves entire course structure in one transaction
   */
  bulkSaveCourse: async (data: {
    course: Partial<Course>;
    modules: CourseModule[];
  }): Promise<Course> => {
    const response = await apiClient.post<Course>('/api/v1/courses/admin/courses/bulk-save', data);
    return response.data;
  },

  // ============================================================================
  // MODULE MANAGEMENT
  // ============================================================================

  /**
   * Add module to course (admin)
   */
  addModule: async (courseId: string, data: CreateModuleRequest): Promise<CourseModule> => {
    const response = await apiClient.post<CourseModule>(
      `/api/v1/courses/admin/courses/${courseId}/modules`,
      data
    );
    return response.data;
  },

  /**
   * Update module (admin)
   */
  updateModule: async (
    courseId: string,
    moduleId: string,
    data: Partial<CreateModuleRequest>
  ): Promise<CourseModule> => {
    const response = await apiClient.put<CourseModule>(
      `/api/v1/courses/admin/courses/${courseId}/modules/${moduleId}`,
      data
    );
    return response.data;
  },

  /**
   * Delete module (admin)
   */
  deleteModule: async (
    courseId: string,
    moduleId: string
  ): Promise<{ success: boolean; message: string }> => {
    const response = await apiClient.delete(
      `/api/v1/courses/admin/courses/${courseId}/modules/${moduleId}`
    );
    return response.data;
  },

  // ============================================================================
  // SECTION MANAGEMENT
  // ============================================================================

  /**
   * Add section to module (admin)
   */
  addSection: async (
    courseId: string,
    moduleId: string,
    data: CreateSectionRequest
  ): Promise<ModuleSection> => {
    const response = await apiClient.post<ModuleSection>(
      `/api/v1/courses/admin/courses/${courseId}/modules/${moduleId}/sections`,
      data
    );
    return response.data;
  },

  /**
   * Update section (admin)
   */
  updateSection: async (
    courseId: string,
    moduleId: string,
    sectionId: string,
    data: UpdateSectionRequest
  ): Promise<ModuleSection> => {
    const response = await apiClient.put<ModuleSection>(
      `/api/v1/courses/admin/courses/${courseId}/modules/${moduleId}/sections/${sectionId}`,
      data
    );
    return response.data;
  },

  /**
   * Delete section (admin)
   */
  deleteSection: async (
    courseId: string,
    moduleId: string,
    sectionId: string
  ): Promise<{ success: boolean; message: string }> => {
    const response = await apiClient.delete(
      `/api/v1/courses/admin/courses/${courseId}/modules/${moduleId}/sections/${sectionId}`
    );
    return response.data;
  },

  // ============================================================================
  // BULK OPERATIONS
  // ============================================================================

  /**
   * Bulk create entire course structure (admin)
   */
  bulkCreateCourse: async (data: BulkCourseCreate): Promise<Course> => {
    const response = await apiClient.post<Course>('/api/v1/courses/admin/courses/bulk/create', data);
    return response.data;
  },

  // ============================================================================
  // CONTENT BLOCK TEMPLATES
  // ============================================================================

  /**
   * Get content block templates (admin helper)
   */
  getContentBlockTemplates: async (): Promise<ContentBlockTemplate[]> => {
    // This could be an API call, but for now return the static templates
    return Promise.resolve(CONTENT_BLOCK_TEMPLATES);
  },
};

// Export both APIs
export const courseApi = {
  public: coursesApi,
  admin: adminCoursesApi,
};