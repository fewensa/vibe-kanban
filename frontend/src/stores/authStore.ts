import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { LocalUser } from 'shared/types';

interface AuthState {
  user: LocalUser | null;
  token: string | null;
  isAuthenticated: boolean;
  setupRequired: boolean;
  
  setAuth: (user: LocalUser, token: string) => void;
  clearAuth: () => void;
  setSetupRequired: (required: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      setupRequired: false,

      setAuth: (user, token) => set({ 
        user, 
        token, 
        isAuthenticated: true,
        setupRequired: false 
      }),
      
      clearAuth: () => set({ 
        user: null, 
        token: null, 
        isAuthenticated: false 
      }),
      
      setSetupRequired: (required) => set({ setupRequired: required }),
    }),
    {
      name: 'vk-auth-storage',
    }
  )
);
