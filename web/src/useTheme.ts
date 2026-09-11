import { useEffect, useState } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';
const STORAGE_KEY = 'pqcf.theme';

function readStored(): ThemePreference {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    if (value === 'light' || value === 'dark' || value === 'system') return value;
  } catch { /* private browsing / storage disabled */ }
  return 'system';
}

/**
 * Applies the theme preference to the document root as `data-theme`, which
 * index.css uses to override the system `prefers-color-scheme` in either
 * direction. `system` removes the attribute entirely so the media query
 * alone decides.
 */
export function useTheme() {
  const [theme, setThemeState] = useState<ThemePreference>(readStored);

  useEffect(() => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  function setTheme(next: ThemePreference) {
    setThemeState(next);
    try { localStorage.setItem(STORAGE_KEY, next); } catch { /* ignore */ }
  }

  return { theme, setTheme };
}
