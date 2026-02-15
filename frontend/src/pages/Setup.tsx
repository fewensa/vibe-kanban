import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { authApi } from '@/api/auth';
import { PrimaryButton } from '@/components/ui-new/primitives/PrimaryButton';
import { LockKeyIcon, EnvelopeIcon, UserIcon } from '@phosphor-icons/react';

export function Setup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { setAuth } = useAuthStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validate passwords match
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Basic password validation
    if (password.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    setIsLoading(true);

    try {
      const response = await authApi.setup({
        email,
        password,
        username: username || null,
      });
      setAuth(response.user, response.session_token);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
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
              Welcome to Vibe Kanban
            </h1>
            <p className="text-muted">
              Create your admin account
            </p>
          </div>

          {/* Info Box */}
          <div className="mb-6 p-4 bg-brand/10 border border-brand/20 rounded">
            <p className="text-sm text-normal">
              This is your first time running Vibe Kanban. Please create an admin account to get started.
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded text-red-400 text-sm">
              {error}
            </div>
          )}

          {/* Setup Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Input */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-normal mb-2">
                Email <span className="text-red-400">*</span>
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

            {/* Username Input (Optional) */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-normal mb-2">
                Username <span className="text-muted text-xs">(optional)</span>
              </label>
              <div className="relative">
                <UserIcon
                  className="absolute left-3 top-1/2 transform -translate-y-1/2 size-icon-sm text-muted"
                  weight="regular"
                />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded text-normal placeholder-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
                  placeholder="admin"
                  disabled={isLoading}
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-normal mb-2">
                Password <span className="text-red-400">*</span>
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
                  placeholder="At least 8 characters"
                  required
                  disabled={isLoading}
                  autoComplete="new-password"
                  minLength={8}
                />
              </div>
              <p className="mt-1 text-xs text-muted">
                Minimum 8 characters
              </p>
            </div>

            {/* Confirm Password Input */}
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-normal mb-2">
                Confirm Password <span className="text-red-400">*</span>
              </label>
              <div className="relative">
                <LockKeyIcon
                  className="absolute left-3 top-1/2 transform -translate-y-1/2 size-icon-sm text-muted"
                  weight="regular"
                />
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded text-normal placeholder-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
                  placeholder="Confirm your password"
                  required
                  disabled={isLoading}
                  autoComplete="new-password"
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
                {isLoading ? 'Creating account...' : 'Create Admin Account'}
              </PrimaryButton>
            </div>
          </form>
        </div>

        {/* Footer */}
        <div className="mt-6 text-center text-sm text-muted">
          <p>This account will have full access to Vibe Kanban</p>
        </div>
      </div>
    </div>
  );
}
