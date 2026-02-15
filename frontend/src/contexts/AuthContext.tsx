import React, { createContext, useContext, useEffect, useState } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { authApi } from '@/api/auth';
import { useNavigate, useLocation } from 'react-router-dom';

interface AuthContextType {
  isLoading: boolean;
  checkAuthStatus: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isLoading, setIsLoading] = useState(true);
  const { token, setAuth, clearAuth, setSetupRequired } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();

  const checkAuthStatus = async () => {
    try {
      const status = await authApi.checkStatus();
      
      // If setup is required, redirect to setup page
      if (status.setup_required) {
        setSetupRequired(true);
        if (location.pathname !== '/auth/setup') {
          navigate('/auth/setup', { replace: true });
        }
        return;
      }

      // If we have a token, verify it's still valid
      if (token) {
        try {
          const { user } = await authApi.getCurrentUser(token);
          setAuth(user, token);
        } catch (error) {
          // Token is invalid, clear auth
          console.error('Token validation failed:', error);
          clearAuth();
          if (!location.pathname.startsWith('/auth')) {
            navigate('/auth/login', { replace: true });
          }
        }
      } else {
        // No token, redirect to login unless already on auth pages
        if (!location.pathname.startsWith('/auth')) {
          navigate('/auth/login', { replace: true });
        }
      }
    } catch (error) {
      console.error('Failed to check auth status:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkAuthStatus();
  }, []);

  // Add axios/fetch interceptor for 401 responses
  useEffect(() => {
    const handleUnauthorized = () => {
      clearAuth();
      navigate('/auth/login', { replace: true });
    };

    // Store the handler for potential cleanup
    (window as any).__handleUnauthorized = handleUnauthorized;

    return () => {
      delete (window as any).__handleUnauthorized;
    };
  }, [clearAuth, navigate]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-brand mx-auto mb-4" />
          <p className="text-muted">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <AuthContext.Provider value={{ isLoading, checkAuthStatus }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
