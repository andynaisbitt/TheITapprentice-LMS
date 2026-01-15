import { Routes, Route, Navigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import { useAuth } from '../state/contexts/AuthContext';
import { Layout } from '../components/layout/Layout';

// Lazy load pages
const BlogHome = lazy(() => import('../pages/BlogHome'));
const BlogList = lazy(() => import('../pages/BlogList'));
const BlogPostView = lazy(() => import('../pages/blog/BlogPostView'));
const Login = lazy(() => import('../pages/Login'));
const Register = lazy(() => import('../pages/Register'));
const BlogEditor = lazy(() => import('../pages/admin/BlogEditor'));
const BlogPostsList = lazy(() => import('../pages/admin/BlogPostsList'));
const CategoryManager = lazy(() => import('../pages/admin/CategoryManager'));
const TagManager = lazy(() => import('../pages/admin/TagManager'));
const AdminDashboard = lazy(() => import('../pages/admin/AdminDashboard'));
const SiteSettings = lazy(() => import('../pages/admin/SiteSettings'));
const NavigationManager = lazy(() => import('../pages/admin/NavigationManager'));
const ThemeCustomizer = lazy(() => import('../pages/admin/ThemeCustomizer'));
const Newsletter = lazy(() => import('../pages/admin/Newsletter'));
const Privacy = lazy(() => import('../pages/Privacy'));
const Terms = lazy(() => import('../pages/Terms'));
const About = lazy(() => import('../pages/About'));
const Contact = lazy(() => import('../pages/Contact'));
const DynamicPage = lazy(() => import('../pages/DynamicPage'));
const PagesList = lazy(() => import('../pages/admin/PagesList'));
const PageEditor = lazy(() => import('../pages/admin/PageEditor'));
const UserManagement = lazy(() => import('../pages/admin/UserManagement'));
const VerifyEmail = lazy(() => import('../pages/VerifyEmail'));
const Unsubscribe = lazy(() => import('../pages/Unsubscribe'));
const CanonicalResolver = lazy(() => import('../components/CanonicalResolver'));
const UserDashboard = lazy(() => import('../pages/user/UserDashboard'));
const Profile = lazy(() => import('../pages/user/Profile'));

// Tutorial plugin pages
const TutorialsPage = lazy(() => import('../plugins/tutorials/pages/TutorialsPage'));
const TutorialDetailPage = lazy(() => import('../plugins/tutorials/pages/TutorialDetailPage'));
const MyTutorialsPage = lazy(() => import('../plugins/tutorials/pages/MyTutorialsPage'));

// Tutorial admin pages
const TutorialManagementPage = lazy(() => import('../plugins/tutorials/pages/admin/TutorialManagementPage'));
const TutorialEditorPage = lazy(() => import('../plugins/tutorials/pages/admin/TutorialEditorPage'));
const TutorialAnalyticsPage = lazy(() => import('../plugins/tutorials/pages/admin/TutorialAnalyticsPage'));
const UserProgressPage = lazy(() => import('../plugins/tutorials/pages/admin/UserProgressPage'));

// Course plugin pages
const CoursesListPage = lazy(() => import('../plugins/courses/pages/public/CoursesList'));
const CourseDetailPage = lazy(() => import('../plugins/courses/pages/public/CourseDetail'));
const CoursePlayerPage = lazy(() => import('../plugins/courses/pages/public/CoursePlayer'));

// Course admin pages
const CourseManagementPage = lazy(() => import('../plugins/courses/pages/admin/CourseManagementPage'));
const CourseEditorPage = lazy(() => import('../plugins/courses/pages/admin/CourseEditorPage'));

// Typing Game plugin pages
const TypingGamePage = lazy(() => import('../plugins/typing-game/pages/TypingGamePage'));
const TypingGamePlayPage = lazy(() => import('../plugins/typing-game/pages/TypingGamePlayPage'));
const TypingLeaderboardPage = lazy(() => import('../plugins/typing-game/pages/TypingLeaderboardPage'));

// Loading component
const PageLoader = () => (
  <div className="flex items-center justify-center min-h-screen">
    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
  </div>
);

// Protected route wrapper
interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <PageLoader />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

// Admin-only route wrapper
interface AdminRouteProps {
  children: React.ReactNode;
}

const AdminRoute = ({ children }: AdminRouteProps) => {
  const { isAuthenticated, isAdmin, loading } = useAuth();

  if (loading) {
    return <PageLoader />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!isAdmin) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

// Main routes component
export const AppRoutes = () => {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        {/* Public routes with Layout */}
        <Route
          path="/"
          element={
            <Layout fullWidth>
              <BlogHome />
            </Layout>
          }
        />
        <Route
          path="/blog"
          element={
            <Layout>
              <BlogList />
            </Layout>
          }
        />
        <Route
          path="/blog/:slug"
          element={
            <Layout>
              <BlogPostView />
            </Layout>
          }
        />

        {/* Login page (no header/footer) */}
        <Route
          path="/login"
          element={
            <Layout hideHeader hideFooter>
              <Login />
            </Layout>
          }
        />

        {/* Register page (no header/footer) */}
        <Route
          path="/register"
          element={
            <Layout hideHeader hideFooter>
              <Register />
            </Layout>
          }
        />

        {/* Email Verification page (no header/footer) */}
        <Route
          path="/verify-email"
          element={
            <Layout hideHeader hideFooter>
              <VerifyEmail />
            </Layout>
          }
        />

        {/* Unsubscribe page (public, no header/footer) */}
        <Route
          path="/unsubscribe"
          element={
            <Layout hideHeader hideFooter>
              <Unsubscribe />
            </Layout>
          }
        />

        {/* User Dashboard (protected, for non-admins) */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Layout>
                <UserDashboard />
              </Layout>
            </ProtectedRoute>
          }
        />

        {/* User Profile (protected) */}
        <Route
          path="/profile"
          element={
            <ProtectedRoute>
              <Layout>
                <Profile />
              </Layout>
            </ProtectedRoute>
          }
        />

        {/* Public User Profile - View any user's profile */}
        <Route
          path="/profile/:username"
          element={
            <Layout>
              <Profile />
            </Layout>
          }
        />

        {/* Tutorial Routes - LMS Plugin */}
        <Route
          path="/tutorials"
          element={
            <Layout>
              <TutorialsPage />
            </Layout>
          }
        />
        <Route
          path="/tutorials/:slug"
          element={
            <Layout>
              <TutorialDetailPage />
            </Layout>
          }
        />
        <Route
          path="/my-tutorials"
          element={
            <ProtectedRoute>
              <Layout>
                <MyTutorialsPage />
              </Layout>
            </ProtectedRoute>
          }
        />

        {/* Course Routes - LMS Plugin */}
        <Route
          path="/courses"
          element={
            <Layout>
              <CoursesListPage />
            </Layout>
          }
        />
        <Route
          path="/courses/:courseId"
          element={
            <Layout>
              <CourseDetailPage />
            </Layout>
          }
        />
        <Route
          path="/courses/:courseId/learn"
          element={
            <Layout>
              <CoursePlayerPage />
            </Layout>
          }
        />
        <Route
          path="/my-courses"
          element={
            <ProtectedRoute>
              <Layout>
                <CoursesListPage />
              </Layout>
            </ProtectedRoute>
          }
        />

        {/* Typing Game Routes - LMS Plugin */}
        <Route
          path="/games/typing"
          element={
            <Layout>
              <TypingGamePage />
            </Layout>
          }
        />
        <Route
          path="/games/typing/play"
          element={
            <Layout>
              <TypingGamePlayPage />
            </Layout>
          }
        />
        <Route
          path="/games/typing/leaderboard"
          element={
            <Layout>
              <TypingLeaderboardPage />
            </Layout>
          }
        />

        {/* Essential pages - now dynamic */}
        <Route
          path="/privacy"
          element={
            <Layout>
              <DynamicPage slug="privacy" />
            </Layout>
          }
        />
        <Route
          path="/terms"
          element={
            <Layout>
              <DynamicPage slug="terms" />
            </Layout>
          }
        />
        <Route
          path="/about"
          element={
            <Layout>
              <DynamicPage slug="about" />
            </Layout>
          }
        />
        <Route
          path="/contact"
          element={
            <Layout>
              <DynamicPage slug="contact" />
            </Layout>
          }
        />

        {/* Admin routes (protected, no footer) */}
        <Route
          path="/admin"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <AdminDashboard />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/posts"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <BlogPostsList />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/blog"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <BlogEditor />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/blog/:id"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <BlogEditor />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/categories"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <CategoryManager />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tags"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <TagManager />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <SiteSettings />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/navigation"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <NavigationManager />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/newsletter"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <Newsletter />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/theme"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <ThemeCustomizer />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/pages"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <PagesList />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/pages/new"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <PageEditor />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/pages/:id"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <PageEditor />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/users"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <UserManagement />
              </Layout>
            </AdminRoute>
          }
        />

        {/* Admin Tutorial Routes - LMS Plugin */}
        <Route
          path="/admin/tutorials"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <TutorialManagementPage />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/new"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <TutorialEditorPage />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/:id/edit"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <TutorialEditorPage />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/analytics"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <TutorialAnalyticsPage />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/user-progress"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <UserProgressPage />
              </Layout>
            </AdminRoute>
          }
        />

        {/* Admin Course Routes - LMS Plugin */}
        <Route
          path="/admin/courses"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <CourseManagementPage />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/courses/new"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <CourseEditorPage />
              </Layout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/courses/:id/edit"
          element={
            <AdminRoute>
              <Layout hideFooter>
                <CourseEditorPage />
              </Layout>
            </AdminRoute>
          }
        />

        {/* Dynamic pages - must be before catch-all */}
        <Route
          path="/pages/:slug"
          element={
            <Layout>
              <DynamicPage />
            </Layout>
          }
        />

        {/* Canonical URL resolver - MUST BE SECOND-TO-LAST
            This catches any URLs that might be canonical URLs
            and redirects them to the proper slug-based route.
            Order matters: this must be before the final 404 redirect. */}
        <Route
          path="/:possibleCanonical"
          element={
            <Layout>
              <CanonicalResolver />
            </Layout>
          }
        />

        {/* 404 catch-all - MUST BE LAST */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
};
