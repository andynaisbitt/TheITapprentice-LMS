import { Routes, Route, Navigate } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import { useAuth } from '../state/contexts/AuthContext';
import { Layout } from '../components/layout/Layout';
import { AdminLayout } from '../components/admin/layout';

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
const XPLeaderboardPage = lazy(() => import('../pages/user/XPLeaderboardPage'));
const ChallengeHistoryPage = lazy(() => import('../pages/user/ChallengeHistoryPage'));

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
const PVPPage = lazy(() => import('../plugins/typing-game/pages/PVPPage'));
const PracticeGamePage = lazy(() => import('../plugins/typing-game/pages/PracticeGamePage'));

// Quiz plugin pages
const QuizzesPage = lazy(() => import('../plugins/quizzes/pages/QuizzesPage'));
const QuizPlayerPage = lazy(() => import('../plugins/quizzes/pages/QuizPlayerPage'));

// Quiz admin pages
const QuizManagerPage = lazy(() => import('../plugins/quizzes/pages/admin/QuizManagerPage'));
const QuizEditorPage = lazy(() => import('../plugins/quizzes/pages/admin/QuizEditorPage'));

// New Admin Pages (v2.1)
const TutorialCategoryManager = lazy(() => import('../pages/admin/TutorialCategoryManager'));
const PluginManager = lazy(() => import('../pages/admin/PluginManager'));
const SystemHealthPage = lazy(() => import('../pages/admin/SystemHealthPage'));
const ActivityLogPage = lazy(() => import('../pages/admin/ActivityLogPage'));
const AchievementsAdmin = lazy(() => import('../pages/admin/AchievementsAdmin'));
const AnalyticsPage = lazy(() => import('../pages/admin/AnalyticsPage'));
const LMSProgressPage = lazy(() => import('../pages/admin/LMSProgressPage'));

// New Admin Pages (v2.2) - Full Implementations
const RolesAdmin = lazy(() => import('../pages/admin/RolesAdmin'));
const XPConfigAdmin = lazy(() => import('../pages/admin/XPConfigAdmin'));
const CourseEnrollmentsAdmin = lazy(() => import('../pages/admin/CourseEnrollmentsAdmin'));
const WordListsAdmin = lazy(() => import('../pages/admin/WordListsAdmin'));
const TypingChallengesAdmin = lazy(() => import('../pages/admin/TypingChallengesAdmin'));
const GameLeaderboardAdmin = lazy(() => import('../pages/admin/GameLeaderboardAdmin'));
const DailyChallengesAdmin = lazy(() => import('../pages/admin/DailyChallengesAdmin'));

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

        {/* XP Leaderboard - Public */}
        <Route
          path="/leaderboard"
          element={
            <Layout>
              <XPLeaderboardPage />
            </Layout>
          }
        />

        {/* Challenge History - Protected */}
        <Route
          path="/challenges/history"
          element={
            <ProtectedRoute>
              <Layout>
                <ChallengeHistoryPage />
              </Layout>
            </ProtectedRoute>
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
        <Route
          path="/games/typing/pvp"
          element={
            <ProtectedRoute>
              <Layout>
                <PVPPage />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/games/typing/practice"
          element={
            <Layout>
              <PracticeGamePage />
            </Layout>
          }
        />

        {/* Quiz Routes - LMS Plugin */}
        <Route
          path="/quizzes"
          element={
            <Layout>
              <QuizzesPage />
            </Layout>
          }
        />
        <Route
          path="/quizzes/:quizId"
          element={
            <Layout>
              <QuizPlayerPage />
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

        {/* Admin routes with new sidebar layout */}
        <Route
          path="/admin"
          element={
            <AdminRoute>
              <AdminLayout>
                <AdminDashboard />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/posts"
          element={
            <AdminRoute>
              <AdminLayout>
                <BlogPostsList />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/blog"
          element={
            <AdminRoute>
              <AdminLayout>
                <BlogEditor />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/blog/:id"
          element={
            <AdminRoute>
              <AdminLayout>
                <BlogEditor />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/categories"
          element={
            <AdminRoute>
              <AdminLayout>
                <CategoryManager />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tags"
          element={
            <AdminRoute>
              <AdminLayout>
                <TagManager />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <AdminRoute>
              <AdminLayout>
                <SiteSettings />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/navigation"
          element={
            <AdminRoute>
              <AdminLayout>
                <NavigationManager />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/newsletter"
          element={
            <AdminRoute>
              <AdminLayout>
                <Newsletter />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/theme"
          element={
            <AdminRoute>
              <AdminLayout>
                <ThemeCustomizer />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/pages"
          element={
            <AdminRoute>
              <AdminLayout>
                <PagesList />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/pages/new"
          element={
            <AdminRoute>
              <AdminLayout>
                <PageEditor />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/pages/:id"
          element={
            <AdminRoute>
              <AdminLayout>
                <PageEditor />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/users"
          element={
            <AdminRoute>
              <AdminLayout>
                <UserManagement />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* Admin Tutorial Routes - LMS Plugin */}
        <Route
          path="/admin/tutorials"
          element={
            <AdminRoute>
              <AdminLayout>
                <TutorialManagementPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/new"
          element={
            <AdminRoute>
              <AdminLayout>
                <TutorialEditorPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/:id/edit"
          element={
            <AdminRoute>
              <AdminLayout>
                <TutorialEditorPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/analytics"
          element={
            <AdminRoute>
              <AdminLayout>
                <TutorialAnalyticsPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorials/user-progress"
          element={
            <AdminRoute>
              <AdminLayout>
                <UserProgressPage />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* Admin Course Routes - LMS Plugin */}
        <Route
          path="/admin/courses"
          element={
            <AdminRoute>
              <AdminLayout>
                <CourseManagementPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/courses/new"
          element={
            <AdminRoute>
              <AdminLayout>
                <CourseEditorPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/courses/:id/edit"
          element={
            <AdminRoute>
              <AdminLayout>
                <CourseEditorPage />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* Admin Quiz Routes - LMS Plugin */}
        <Route
          path="/admin/quizzes"
          element={
            <AdminRoute>
              <AdminLayout>
                <QuizManagerPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/quizzes/new"
          element={
            <AdminRoute>
              <AdminLayout>
                <QuizEditorPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/quizzes/:id/edit"
          element={
            <AdminRoute>
              <AdminLayout>
                <QuizEditorPage />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* New Admin Routes - v2.1 */}
        <Route
          path="/admin/analytics"
          element={
            <AdminRoute>
              <AdminLayout>
                <AnalyticsPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/tutorial-categories"
          element={
            <AdminRoute>
              <AdminLayout>
                <TutorialCategoryManager />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/lms/progress"
          element={
            <AdminRoute>
              <AdminLayout>
                <LMSProgressPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/achievements"
          element={
            <AdminRoute>
              <AdminLayout>
                <AchievementsAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/daily-challenges"
          element={
            <AdminRoute>
              <AdminLayout>
                <DailyChallengesAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/activity"
          element={
            <AdminRoute>
              <AdminLayout>
                <ActivityLogPage />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/plugins"
          element={
            <AdminRoute>
              <AdminLayout>
                <PluginManager />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/system"
          element={
            <AdminRoute>
              <AdminLayout>
                <SystemHealthPage />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* Admin User & XP Routes - v2.2 */}
        <Route
          path="/admin/users/roles"
          element={
            <AdminRoute>
              <AdminLayout>
                <RolesAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/xp-config"
          element={
            <AdminRoute>
              <AdminLayout>
                <XPConfigAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* Admin Course Enrollments - v2.2 */}
        <Route
          path="/admin/courses/enrollments"
          element={
            <AdminRoute>
              <AdminLayout>
                <CourseEnrollmentsAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />

        {/* Admin Game Routes - v2.2 */}
        <Route
          path="/admin/games/word-lists"
          element={
            <AdminRoute>
              <AdminLayout>
                <WordListsAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/games/challenges"
          element={
            <AdminRoute>
              <AdminLayout>
                <TypingChallengesAdmin />
              </AdminLayout>
            </AdminRoute>
          }
        />
        <Route
          path="/admin/games/leaderboard"
          element={
            <AdminRoute>
              <AdminLayout>
                <GameLeaderboardAdmin />
              </AdminLayout>
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
