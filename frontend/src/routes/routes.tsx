import { Routes, Route, Navigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import { useAuth } from '../state/contexts/AuthContext';
import { Layout } from '../components/layout/Layout';

// Lazy load pages
const BlogHome = lazy(() => import('../pages/BlogHome'));
const BlogList = lazy(() => import('../pages/BlogList'));
const BlogPostView = lazy(() => import('../pages/blog/BlogPostView'));
const Login = lazy(() => import('../pages/Login'));
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
const Unsubscribe = lazy(() => import('../pages/Unsubscribe'));
const CanonicalResolver = lazy(() => import('../components/CanonicalResolver'));

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

        {/* Unsubscribe page (public, no header/footer) */}
        <Route
          path="/unsubscribe"
          element={
            <Layout hideHeader hideFooter>
              <Unsubscribe />
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
            <ProtectedRoute>
              <Layout hideFooter>
                <AdminDashboard />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/posts"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <BlogPostsList />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/blog"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <BlogEditor />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/blog/:id"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <BlogEditor />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/categories"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <CategoryManager />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/tags"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <TagManager />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <SiteSettings />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/navigation"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <NavigationManager />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/newsletter"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <Newsletter />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/theme"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <ThemeCustomizer />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/pages"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <PagesList />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/pages/new"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <PageEditor />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/pages/:id"
          element={
            <ProtectedRoute>
              <Layout hideFooter>
                <PageEditor />
              </Layout>
            </ProtectedRoute>
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
