

/**
 * Helper to get the API base URL.
 * In development (Vite), it's relative.
 * In production/deployment, it can be overridden by VITE_API_URL.
 */
import { supabase } from '@/react-app/lib/supabase';

export function getApiUrl(path: string): string {
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    const baseUrl = import.meta.env.VITE_API_URL || '';
    const cleanBaseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    return `${cleanBaseUrl}${cleanPath}`;
}

/**
 * Return headers including Authorization if a Supabase session exists.
 * Pass null for contentType if you don't want Content-Type set (e.g. file downloads).
 */
export async function getAuthHeaders(contentType: string | null = 'application/json'): Promise<HeadersInit> {
  const { data: { session } } = await supabase.auth.getSession();
  const headers: HeadersInit = {};
  if (contentType) headers['Content-Type'] = contentType;
  if (session?.access_token) {
    headers['Authorization'] = `Bearer ${session.access_token}`;
  }
  return headers;
}
