import { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useUserSystem } from './ConfigProvider';

interface ProtectedRouteProps {
  children: ReactNode;
}

/**
 * ProtectedRoute component that redirects to onboarding page
 * if enforce_login is enabled and user is not logged in.
 */
export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { enforceLogin, loginStatus, loading } = useUserSystem();

  if (loading) {
    return (
      <div className="h-screen bg-primary flex items-center justify-center">
        <p className="text-low">Loading...</p>
      </div>
    );
  }

  // If enforce_login is enabled and user is not logged in, redirect to onboarding
  if (enforceLogin && loginStatus?.status !== 'loggedin') {
    return <Navigate to="/onboarding" replace />;
  }

  return <>{children}</>;
}
