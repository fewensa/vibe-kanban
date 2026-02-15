import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { authApi } from '@/api/auth';
import { PrimaryButton } from '@/components/ui-new/primitives/PrimaryButton';
import { LockKeyIcon, EnvelopeIcon } from '@phosphor-icons/react';

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { setAuth } = useAuthStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await authApi.login({ email, password });
      setAuth(response.user, response.session_token);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-panel rounded-lg shadow-lg p-8 border border-border">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-normal mb-2">
              Vibe Kanban
            </h1>
            <p className="text-muted">
              Sign in to your account
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded text-red-400 text-sm">
              {error}
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Input */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-normal mb-2">
                Email
              </label>
              <div className="relative">
                <EnvelopeIcon
                  className="absolute left-3 top-1/2 transform -translate-y-1/2 size-icon-sm text-muted"
                  weight="regular"
                />
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded text-normal placeholder-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
                  placeholder="admin@example.com"
                  required
                  disabled={isLoading}
                  autoComplete="email"
                  autoFocus
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-normal mb-2">
                Password
              </label>
              <div className="relative">
                <LockKeyIcon
                  className="absolute left-3 top-1/2 transform -translate-y-1/2 size-icon-sm text-muted"
                  weight="regular"
                />
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded text-normal placeholder-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
                  placeholder="Enter your password"
                  required
                  disabled={isLoading}
                  autoComplete="current-password"
                />
              </div>
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <PrimaryButton
                variant="default"
                type="submit"
                actionIcon={isLoading ? 'spinner' : undefined}
                disabled={isLoading}
                className="w-full justify-center"
              >
                {isLoading ? 'Signing in...' : 'Sign in'}
              </PrimaryButton>
            </div>
          </form>
        </div>

        {/* Footer */}
        <div className="mt-6 text-center text-sm text-muted">
          <p>Secure local authentication</p>
        </div>
      </div>
    </div>
  );
}
