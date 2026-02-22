import { Navigate, Outlet, useSearchParams } from 'react-router-dom';
import { DevBanner } from '@/components/DevBanner';
import { Navbar } from '@/components/layout/Navbar';
import { useUserSystem } from '@/components/ConfigProvider';
import { useAuth } from '@/hooks/auth/useAuth';

export function NormalLayout() {
  const [searchParams] = useSearchParams();
  const view = searchParams.get('view');
  const shouldHideNavbar = view === 'preview' || view === 'diffs';
  const { enforceLogin, loading } = useUserSystem();
  const { isSignedIn } = useAuth();

  // If enforce_login is enabled and user is not signed in, redirect to onboarding
  if (enforceLogin && !isSignedIn && !loading) {
    return <Navigate to="/onboarding" replace />;
  }

  return (
    <>
      <div className="flex flex-col h-screen">
        <DevBanner />
        {!shouldHideNavbar && <Navbar />}
        <div className="flex-1 overflow-auto">
          <Outlet />
        </div>
      </div>
    </>
  );
}
