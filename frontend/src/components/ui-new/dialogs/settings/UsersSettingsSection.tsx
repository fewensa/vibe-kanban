import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { PlusIcon, TrashIcon } from '@phosphor-icons/react';
import { authApi } from '@/api/auth';
import type { LocalUser } from 'shared/types';
import { useUserSystem } from '@/components/ConfigProvider';
import { PrimaryButton } from '../../primitives/PrimaryButton';
import {
  SettingsCard,
  SettingsField,
  SettingsInput,
} from './SettingsComponents';

export function UsersSettingsSection() {
  const { t } = useTranslation('settings');
  const { user: currentUser } = useUserSystem();
  const [users, setUsers] = useState<LocalUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newUser, setNewUser] = useState({
    username: '',
    email: '',
    password: '',
  });
  const [creating, setCreating] = useState(false);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const userList = await authApi.listUsers();
      setUsers(userList);
    } catch (err: any) {
      setError(err.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreateUser = async () => {
    if (!newUser.username || !newUser.email || !newUser.password) {
      return;
    }

    setCreating(true);
    try {
      await authApi.createUser(newUser);
      await loadUsers();
      setShowCreateDialog(false);
      setNewUser({ username: '', email: '', password: '' });
    } catch (err: any) {
      setError(err.message || 'Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (userId === currentUser?.id) {
      setError('Cannot delete yourself');
      return;
    }

    if (!confirm('Are you sure you want to delete this user?')) {
      return;
    }

    try {
      await authApi.deleteUser(userId);
      await loadUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to delete user');
    }
  };

  return (
    <div className="p-4 space-y-4">
      <SettingsCard
        title="Users"
        description="Manage user accounts"
        headerAction={
          <PrimaryButton
            onClick={() => setShowCreateDialog(!showCreateDialog)}
            size="sm"
          >
            <PlusIcon className="size-icon-sm" weight="bold" />
            Create User
          </PrimaryButton>
        }
      >
        {loading ? (
          <div className="text-sm text-low py-4">Loading users...</div>
        ) : users.length === 0 ? (
          <div className="text-sm text-low py-4">No users found</div>
        ) : (
          <div className="space-y-2">
            {users.map((user) => (
              <div
                key={user.id}
                className="flex items-center justify-between p-3 rounded-sm border border-border bg-panel/50"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-high truncate">
                    {user.username || user.email}
                  </div>
                  <div className="text-xs text-low truncate">{user.email}</div>
                </div>
                {currentUser?.id !== user.id && (
                  <button
                    onClick={() => handleDeleteUser(user.id)}
                    className="p-1.5 text-low hover:text-error hover:bg-error/10 rounded-sm transition-colors"
                  >
                    <TrashIcon className="size-icon-sm" weight="bold" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </SettingsCard>

      {showCreateDialog && (
        <SettingsCard title="Create New User" description="Add a new user account">
          <div className="space-y-4">
            <SettingsField label="Email" description="User's email address">
              <SettingsInput
                type="email"
                value={newUser.email}
                onChange={(e) =>
                  setNewUser({ ...newUser, email: e.target.value })
                }
                placeholder="john@example.com"
              />
            </SettingsField>

            <SettingsField label="Username" description="Unique username (optional)">
              <SettingsInput
                value={newUser.username}
                onChange={(e) =>
                  setNewUser({ ...newUser, username: e.target.value })
                }
                placeholder="john_doe"
              />
            </SettingsField>

            <SettingsField
              label="Password"
              description="Must be at least 8 characters"
            >
              <SettingsInput
                type="password"
                value={newUser.password}
                onChange={(e) =>
                  setNewUser({ ...newUser, password: e.target.value })
                }
                placeholder="••••••••"
              />
            </SettingsField>

            <div className="flex gap-2 justify-end pt-2">
              <PrimaryButton
                onClick={() => {
                  setShowCreateDialog(false);
                  setNewUser({ username: '', email: '', password: '' });
                }}
                variant="secondary"
                size="sm"
              >
                Cancel
              </PrimaryButton>
              <PrimaryButton
                onClick={handleCreateUser}
                disabled={creating || !newUser.email || !newUser.password}
                size="sm"
              >
                {creating ? 'Creating...' : 'Create'}
              </PrimaryButton>
            </div>
          </div>
        </SettingsCard>
      )}

      {error && (
        <div className="text-sm text-error bg-error/10 border border-error/20 rounded-sm p-3">
          {error}
        </div>
      )}
    </div>
  );
}
