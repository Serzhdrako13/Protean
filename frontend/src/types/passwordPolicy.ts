// Shared with the portal entry (frontend/src/entries/portal.tsx), which has
// no QueryClientProvider -- this file must stay free of react-query so it's
// safe to import from both the admin app and the standalone portal bundle.
export interface PasswordPolicySettings {
  min_length: number;
  require_upper: boolean;
  require_lower: boolean;
  require_digit: boolean;
  require_symbol: boolean;
  // max_age_days: 0 = no forced expiry.
  max_age_days: number;
  session_ttl_hours: number;
}
