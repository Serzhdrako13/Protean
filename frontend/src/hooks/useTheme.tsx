import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { theme as antdTheme, type ThemeConfig } from 'antd';

// Same pattern as 3x-ui's useTheme.tsx: plain React Context + localStorage,
// dark/light applied to <html> BEFORE React mounts (module-level call below)
// so there's no flash of the wrong theme. Ultra-dark isn't offered — we only
// need the two states.
const STORAGE_DARK = 'protean-dark-mode';

function readBool(key: string, fallback: boolean): boolean {
  const raw = localStorage.getItem(key);
  if (raw === null) return fallback;
  return raw === 'true';
}

function applyDom(isDark: boolean) {
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
}

const prefersDark = typeof window !== 'undefined' && window.matchMedia
  ? window.matchMedia('(prefers-color-scheme: dark)').matches
  : true;
const initialDark = readBool(STORAGE_DARK, prefersDark);
applyDom(initialDark);

// Airy, 3x-ui-like spacing: generous corner radius + card padding + gutters
// instead of AntD's fairly tight defaults. Applied on top of either algorithm
// so light/dark share the same "roominess", only colors differ.
//
// Pastel pass: AntD's default seed colors (vivid blue/green/gold/red) read as
// harsh on a dark background — desaturated them, and lowered border/divider
// contrast so panel edges are barely-there rather than hard outlines. One
// seed set for both themes; AntD's algorithm derives the light/dark variants
// (backgrounds, hover, etc.) from each seed itself, so this stays consistent
// across the toggle.
const AIRY_TOKENS = {
  borderRadius: 10,
  borderRadiusLG: 14,
  padding: 16,
  paddingLG: 24,
  fontSize: 14,

  colorPrimary: '#7c8fc9', // muted slate-blue instead of AntD's vivid #1677ff
  colorSuccess: '#6fae7d',
  colorWarning: '#c9a35f',
  colorError: '#c17878',
  colorInfo: '#7c8fc9',

  colorBorder: 'rgba(130,135,160,0.28)',
  colorBorderSecondary: 'rgba(130,135,160,0.15)',
  colorSplit: 'rgba(130,135,160,0.16)',
};
const AIRY_COMPONENTS = {
  Card: { paddingLG: 24 },
  Table: { cellPaddingBlock: 14, cellPaddingInline: 16 },
  Statistic: { contentFontSize: 22 },
};

// The pastel seed colors above (colorSuccess/colorError/etc.) are muted by
// design for light mode, but AntD's dark algorithm derives status Tag/Badge
// backgrounds from them at a low fixed opacity -- combined with an already
// desaturated seed, that background nearly disappears against the dark
// page background. Explicit overrides, dark mode only, at a higher alpha
// so "up"/"down" status tags stay legible; light mode is untouched.
const DARK_STATUS_BG_TOKENS = {
  colorSuccessBg: 'rgba(111,174,125,0.32)',
  colorErrorBg: 'rgba(193,120,120,0.32)',
  colorWarningBg: 'rgba(201,163,95,0.32)',
  colorInfoBg: 'rgba(124,143,201,0.32)',
};

export function buildAntdThemeConfig(isDark: boolean): ThemeConfig {
  return {
    // cssVar: several pages reference var(--ant-color-*) directly (matching
    // 3x-ui's own Sparkline.tsx technique) — without this those variables are
    // never defined, so the declarations silently fall back to inherited
    // text color instead of the intended muted/tertiary tone.
    cssVar: {},
    hashed: false,
    algorithm: isDark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: isDark ? { ...AIRY_TOKENS, ...DARK_STATUS_BG_TOKENS } : AIRY_TOKENS,
    components: AIRY_COMPONENTS,
  };
}

interface ThemeContextValue {
  isDark: boolean;
  toggleTheme: () => void;
  antdThemeConfig: ThemeConfig;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [isDark, setIsDark] = useState<boolean>(initialDark);

  useEffect(() => {
    applyDom(isDark);
    localStorage.setItem(STORAGE_DARK, String(isDark));
  }, [isDark]);

  const toggleTheme = useCallback(() => setIsDark((v) => !v), []);
  const antdThemeConfig = useMemo(() => buildAntdThemeConfig(isDark), [isDark]);

  const value = useMemo<ThemeContextValue>(
    () => ({ isDark, toggleTheme, antdThemeConfig }),
    [isDark, toggleTheme, antdThemeConfig],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>');
  return ctx;
}
