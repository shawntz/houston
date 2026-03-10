const BASE = '/api/admin';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: 'unknown' }));
    throw new Error(body.error || `HTTP ${res.status}`);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

// Users
export const listUsers = () => request<any[]>('/users');
export const getUser = (id: string) => request<any>(`/users/${id}`);
export const createUser = (data: any) =>
  request<any>('/users', { method: 'POST', body: JSON.stringify(data) });
export const updateUser = (id: string, data: any) =>
  request<any>(`/users/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const deleteUser = (id: string) =>
  request<void>(`/users/${id}`, { method: 'DELETE' });

// Apps
export const listApps = () => request<any[]>('/apps');
export const getApp = (id: string) => request<any>(`/apps/${id}`);
export const createApp = (data: any) =>
  request<any>('/apps', { method: 'POST', body: JSON.stringify(data) });
export const deleteApp = (id: string) =>
  request<void>(`/apps/${id}`, { method: 'DELETE' });
export const rotateAppSecret = (id: string) =>
  request<any>(`/apps/${id}/rotate-secret`, { method: 'POST' });

// Sessions
export const listSessions = () => request<any[]>('/sessions');
export const revokeSession = (id: string) =>
  request<void>(`/sessions/${id}`, { method: 'DELETE' });

// Audit Log
export const queryAuditLog = (params?: { action?: string; user_id?: string; limit?: number }) => {
  const qs = new URLSearchParams();
  if (params?.action) qs.set('action', params.action);
  if (params?.user_id) qs.set('user_id', params.user_id);
  if (params?.limit) qs.set('limit', String(params.limit));
  const query = qs.toString();
  return request<any[]>(`/audit-log${query ? `?${query}` : ''}`);
};
