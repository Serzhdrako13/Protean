import { Select } from 'antd';
import { useTranslation } from 'react-i18next';

// key looks up its display label in the "poll-interval" i18n namespace
// (see src/i18n/locales/*/poll-interval.json) -- there's no separate
// hardcoded label field, so every consumer (this Select and IndexPage's
// poll badge) always shows the current language, never a stale one.
export const POLL_INTERVALS = [
  { value: 10_000, key: '10s' },
  { value: 20_000, key: '20s' },
  { value: 30_000, key: '30s' },
  { value: 60_000, key: '60s' },
  { value: 300_000, key: '5m' },
];

// Controls how often a traffic chart re-fetches — not how often the backend
// actually samples (fixed, server-side, default 60s). Picking 10с just means
// "show me a freshly-landed sample within 10s of it existing", not "the
// panel now measures every 10s" — see queries/providers.ts useTrafficQuery.
export function PollIntervalSelect({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  const { t } = useTranslation('poll-interval');
  const options = POLL_INTERVALS.map((p) => ({ value: p.value, label: t(p.key) }));
  return (
    <Select
      size="small"
      value={value}
      onChange={onChange}
      options={options}
      style={{ width: 90 }}
    />
  );
}
