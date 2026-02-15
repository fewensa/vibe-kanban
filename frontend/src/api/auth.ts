import type { 
  AuthStatusResponse, 
  LoginRequest, 
  LoginResponse, 
  SetupRequest,
  LocalCurrentUserResponse 
} from 'shared/types';
import { useAuthStore } from '@/stores/authStore';

const API_BASE = '/api';

// Helper to get auth token from store
function getAuthToken(): string | null {
  return useAuthStore.getState().token;
}

// Helper to add auth header to requests
function getAuthHeaders(): HeadersInit {
  const token = getAuthToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  return headers;
}

// Helper to handle unauthorized responses
async function handleResponse(res: Response) {
  if (res.status === 401) {
    // Token is invalid, trigger logout
    const handleUnauthorized = (window as any).__handleUnauthorized;
    if (handleUnauthorized) {
      handleUnauthorized();
    }
    throw new Error('Unauthorized');
  }
  
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.error || `Request failed with status ${res.status}`);
  }
  
  return res;
}

export const authApi = {
  async checkStatus(): Promise<AuthStatusResponse> {
    const res = await fetch(`${API_BASE}/auth/local/status`);
    await handleResponse(res);
    return res.json();
  },

  async setup(data: SetupRequest): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/local/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    await handleResponse(res);
    return res.json();
  },

  async login(data: LoginRequest): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/local/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    await handleResponse(res);
    return res.json();
  },

  async logout(token: string): Promise<void> {
    const res = await fetch(`${API_BASE}/auth/local/logout`, {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json' 
      },
    });
    await handleResponse(res);
  },

  async getCurrentUser(token: string): Promise<LocalCurrentUserResponse> {
    const res = await fetch(`${API_BASE}/auth/local/me`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    await handleResponse(res);
    return res.json();
  },
};

// Export helper for other API modules to use
export { getAuthHeaders };
