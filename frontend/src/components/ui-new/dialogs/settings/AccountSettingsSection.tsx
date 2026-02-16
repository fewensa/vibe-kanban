import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { authApi } from '@/api/auth';
import {
  SettingsCard,
  SettingsField,
  SettingsInput,
  SettingsSaveBar,
} from './SettingsComponents';

export function AccountSettingsSection() {
  const { t } = useTranslation('settings');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      setError('All fields are required');
      return;
    }

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    setSaving(true);
    try {
      await authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setSuccess(false), 3000);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to change password');
    } finally {
      setSaving(false);
    }
  };

  const isDirty = !!(currentPassword || newPassword || confirmPassword);

  return (
    <div className="p-4 space-y-4">
      <SettingsCard
        title="Change Password"
        description="Update your account password"
      >
        <form onSubmit={handleSubmit} className="space-y-4">
          <SettingsField
            label="Current Password"
            description="Enter your current password"
          >
            <SettingsInput
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Current password"
            />
          </SettingsField>

          <SettingsField
            label="New Password"
            description="Must be at least 8 characters"
          >
            <SettingsInput
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="New password"
            />
          </SettingsField>

          <SettingsField
            label="Confirm New Password"
            description="Re-enter your new password"
          >
            <SettingsInput
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
            />
          </SettingsField>
        </form>
      </SettingsCard>

      <SettingsSaveBar
        dirty={isDirty}
        saving={saving}
        error={error}
        success={success}
        onSave={handleSubmit}
        onDiscard={() => {
          setCurrentPassword('');
          setNewPassword('');
          setConfirmPassword('');
          setError(null);
          setSuccess(false);
        }}
      />
    </div>
  );
}
