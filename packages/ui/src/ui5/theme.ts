import { setTheme } from '@ui5/webcomponents-base/dist/config/Theme.js';
import { useCallback, useEffect, useState } from 'react';

export type ThemeMode = 'auto' | 'light' | 'dark';

export const THEME_MODES: { mode: ThemeMode; label: string; icon: string }[] = [
  { mode: 'auto', label: 'Same as system', icon: 'laptop' },
  { mode: 'light', label: 'Light', icon: 'light-mode' },
  { mode: 'dark', label: 'Dark', icon: 'dark-mode' },
];

const STORAGE_KEY = 'btp-lens.theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';

function readStoredMode(): ThemeMode {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored === 'light' || stored === 'dark' || stored === 'auto' ? stored : 'auto';
  } catch {
    return 'auto';
  }
}

function storeMode(mode: ThemeMode): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // Storage can be unavailable (private mode, file:// policies); not critical.
  }
}

function systemPrefersDark(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(DARK_QUERY).matches;
}

export function resolveTheme(mode: ThemeMode, prefersDark: boolean): string {
  const dark = mode === 'dark' || (mode === 'auto' && prefersDark);
  return dark ? 'sap_horizon_dark' : 'sap_horizon';
}

/** Horizon light/dark, following the OS by default, with a manual override. */
export function useThemeMode(): [ThemeMode, (mode: ThemeMode) => void] {
  const [mode, setMode] = useState<ThemeMode>(readStoredMode);
  const [prefersDark, setPrefersDark] = useState(systemPrefersDark);

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return undefined;
    const query = window.matchMedia(DARK_QUERY);
    const onChange = (event: MediaQueryListEvent) => setPrefersDark(event.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    const theme = resolveTheme(mode, prefersDark);
    void setTheme(theme);
    document.documentElement.style.colorScheme = theme === 'sap_horizon_dark' ? 'dark' : 'light';
  }, [mode, prefersDark]);

  const choose = useCallback((next: ThemeMode) => {
    storeMode(next);
    setMode(next);
  }, []);

  return [mode, choose];
}
