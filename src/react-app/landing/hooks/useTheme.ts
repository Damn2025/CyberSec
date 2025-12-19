import { useCallback, useEffect, useMemo, useState } from 'react';

const STORAGE_KEY = 'theme';

export type Theme = 'dark' | 'light';

function normalizeTheme(value: unknown): Theme | null {
  return value === 'dark' || value === 'light' ? value : null;
}

export function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark';
  try {
    const stored = normalizeTheme(window.localStorage?.getItem(STORAGE_KEY));
    // Default to dark unless the user explicitly chose (and we saved) a theme.
    return stored ?? 'dark';
  } catch {
    return 'dark';
  }
}

export function applyTheme(theme: Theme): void {
  const normalized = normalizeTheme(theme) ?? 'dark';
  const root = document.documentElement;

  root.dataset.theme = normalized;
  root.classList.toggle('dark', normalized === 'dark');
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    if (typeof document !== 'undefined') {
      const fromDom = normalizeTheme(document.documentElement?.dataset?.theme);
      if (fromDom) return fromDom;
    }
    return getInitialTheme();
  });

  useEffect(() => {
    applyTheme(theme);
    try {
      window.localStorage?.setItem(STORAGE_KEY, theme);
    } catch {
      // no-op
    }
  }, [theme]);

  const setTheme = useCallback((next: Theme) => {
    const normalized = normalizeTheme(next);
    if (!normalized) return;
    setThemeState(normalized);
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((t: Theme) => (t === 'dark' ? 'light' : 'dark'));
  }, []);

  return useMemo(
    () => ({
      theme,
      setTheme,
      toggleTheme,
      isDark: theme === 'dark',
      isLight: theme === 'light',
    }),
    [setTheme, theme, toggleTheme]
  );
}


