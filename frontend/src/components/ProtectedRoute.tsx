import { Navigate } from 'react-router-dom';
import { useUserSystem } from './ConfigProvider';

interface ProtectedRouteProps {
  children: React.ReactElement;
}

/**
 * Protects a route by requiring login when VK_ENFORCE_LOGIN is set
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

  // If login is enforced and user is not logged in, redirect to sign-in
  if (enforceLogin && loginStatus?.status !== 'loggedin') {
    return <Navigate to="/onboarding/sign-in" replace />;
  }

  return children;
}
