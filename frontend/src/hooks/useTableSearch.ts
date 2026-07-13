import { useMemo, useState } from 'react';

// Plain client-side substring filter -- every table this backs (users,
// peers, audit log, ...) is a single already-fetched array (see each
// page's useXQuery), not a paginated server endpoint, so filtering in the
// browser is simpler and fast enough at the scale a self-hosted panel
// actually sees (hundreds/low thousands of rows, not millions).
export function useTableSearch<T>(rows: T[] | null | undefined, extract: (row: T) => string) {
  const [query, setQuery] = useState('');
  const filtered = useMemo(() => {
    if (!rows) return rows;
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => extract(r).toLowerCase().includes(q));
  }, [rows, query, extract]);
  return { query, setQuery, filtered };
}
