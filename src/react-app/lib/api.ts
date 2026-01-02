
/**
 * Helper to get the API base URL.
 * In development (Vite), it's relative.
 * In production/deployment, it can be overridden by VITE_API_URL.
 */
export function getApiUrl(path: string): string {
    // Ensure path starts with /
    const cleanPath = path.startsWith('/') ? path : `/${path}`;

    // Get base URL from environment or default to empty (relative)
    const baseUrl = import.meta.env.VITE_API_URL || '';

    // Remove trailing slash from baseUrl if present
    const cleanBaseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;

    return `${cleanBaseUrl}${cleanPath}`;
}
