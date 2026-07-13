import { useState } from 'react';

const KEY = 'protean-hide-down-providers';

// One shared preference across every provider list (dashboard, per-server
// providers table, ...) -- persisted like the other small per-browser UI
// prefs (theme, language, dashboard density).
export function useHideDownProviders() {
  const [hideDown, setHideDownState] = useState(() => localStorage.getItem(KEY) === 'true');
  function setHideDown(v: boolean) {
    setHideDownState(v);
    localStorage.setItem(KEY, String(v));
  }
  return [hideDown, setHideDown] as const;
}
